//! Kiểm tra sức khoẻ mật khẩu.
//!
//! - **Yếu**: zxcvbn < 3/4.
//! - **Trùng**: cùng một mật khẩu dùng cho nhiều mục.
//! - **Cũ**: chưa đổi quá `OLD_AFTER_DAYS` ngày.
//! - **Bị lộ**: có trong cơ sở dữ liệu Have I Been Pwned. Dùng k-anonymity: chỉ gửi
//!   **5 ký tự đầu** của SHA-1, so khớp phần còn lại trên máy; mật khẩu không bao giờ rời máy.
//!   Bật `Add-Padding` để kích thước phản hồi không tiết lộ gì.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use pwv_generator::estimate_strength;
use pwv_vault_core::model::{now_ms, IMPORTED_AT};
use pwv_vault_core::Entry;
use serde::Serialize;
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

pub const OLD_AFTER_DAYS: i64 = 365;
pub const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Issue {
    Empty,
    Weak { score: u8 },
    Reused { with: Vec<String> },
    Old { days: i64 },
    Breached { count: u64 },
}

impl Issue {
    pub fn describe(&self) -> String {
        match self {
            Issue::Empty => "chưa có mật khẩu".into(),
            Issue::Weak { score } => format!("mật khẩu yếu ({score}/4)"),
            Issue::Reused { with } => format!("dùng chung với {} mục khác", with.len()),
            Issue::Old { days } => format!("{days} ngày chưa đổi"),
            Issue::Breached { count } => {
                format!("ĐÃ BỊ LỘ trong {count} vụ rò rỉ dữ liệu — hãy đổi ngay")
            }
        }
    }

    /// 0 = nghiêm trọng nhất.
    pub fn severity(&self) -> u8 {
        match self {
            Issue::Breached { .. } => 0,
            Issue::Reused { .. } => 1,
            Issue::Weak { .. } => 2,
            Issue::Empty => 3,
            Issue::Old { .. } => 4,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Report {
    /// entry id → danh sách vấn đề (sắp theo mức độ).
    pub issues: BTreeMap<String, Vec<Issue>>,
    pub checked: usize,
    pub breach_check_done: bool,
}

impl Report {
    pub fn count(&self, pred: impl Fn(&Issue) -> bool) -> usize {
        self.issues.values().filter(|v| v.iter().any(&pred)).count()
    }
    /// Điểm tổng 0–100.
    pub fn score(&self) -> u8 {
        if self.checked == 0 {
            return 100;
        }
        let bad = self
            .issues
            .values()
            .filter(|v| v.iter().any(|i| i.severity() <= 2))
            .count();
        (100 - bad * 100 / self.checked) as u8
    }
    fn push(&mut self, id: &str, issue: Issue) {
        let v = self.issues.entry(id.to_string()).or_default();
        v.push(issue);
        v.sort_by_key(Issue::severity);
    }
}

/// Lần cuối mật khẩu được đặt (ms). Với mục nhập từ CSV chưa sửa mật khẩu (thời điểm là
/// [`IMPORTED_AT`] — một mốc cố định, không phải ngày thật), đây là thời điểm nhập (file CSV không
/// cho biết tuổi thật của mật khẩu).
fn password_set_at(e: &Entry) -> i64 {
    if e.field_times.password > IMPORTED_AT {
        e.field_times.password
    } else {
        e.created_at
    }
}

/// Kiểm tra không cần mạng: yếu, trùng, cũ.
pub fn offline_report(entries: &[Entry]) -> Report {
    let mut r = Report {
        checked: entries.len(),
        ..Default::default()
    };
    let mut by_pw: HashMap<&str, Vec<&Entry>> = HashMap::new();
    let now = now_ms();
    for e in entries {
        if e.password.is_empty() {
            if e.totp.is_none() && !e.username.is_empty() {
                r.push(&e.id, Issue::Empty);
            }
            continue;
        }
        by_pw.entry(e.password.as_str()).or_default().push(e);
        let s = estimate_strength(&e.password, &[&e.username, &e.title]);
        if s.score < 3 {
            r.push(&e.id, Issue::Weak { score: s.score });
        }
        let days = (now - password_set_at(e)) / 86_400_000;
        if days >= OLD_AFTER_DAYS {
            r.push(&e.id, Issue::Old { days });
        }
    }
    for group in by_pw.values().filter(|g| g.len() > 1) {
        for e in group {
            let with = group
                .iter()
                .filter(|o| o.id != e.id)
                .map(|o| o.title.clone())
                .collect();
            r.push(&e.id, Issue::Reused { with });
        }
    }
    r
}

/// SHA-1 viết hoa, tách thành (5 ký tự đầu, 35 ký tự còn lại).
pub fn sha1_prefix_suffix(password: &str) -> (String, String) {
    let hex: String = Sha1::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    (hex[..5].to_string(), hex[5..].to_string())
}

/// Tìm `suffix` trong phản hồi `SUFFIX:COUNT` của API range. Dòng đệm có COUNT = 0.
pub fn count_in_range_response(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, c)| c.trim().parse().ok())
        .unwrap_or(0)
}

/// Phản hồi có đúng là danh sách của API range không? (Mọi dòng dạng `35 ký tự hex:số`, và đủ
/// nhiều dòng — khi bật `Add-Padding` máy chủ luôn trả 800–1000 dòng.)
///
/// Nếu không kiểm tra, một trang HTML trả về với mã 200 (phần mềm diệt virus soi HTTPS, cổng đăng
/// nhập Wi-Fi, proxy công ty) sẽ bị hiểu là "không mật khẩu nào bị lộ".
pub fn looks_like_range_response(body: &str) -> bool {
    let mut lines = 0;
    for l in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some((suffix, count)) = l.split_once(':') else {
            return false;
        };
        if suffix.len() != 35
            || !suffix.bytes().all(|b| b.is_ascii_hexdigit())
            || count.is_empty()
            || !count.bytes().all(|b| b.is_ascii_digit())
        {
            return false;
        }
        lines += 1;
    }
    lines >= MIN_RANGE_LINES
}

/// Số dòng tối thiểu của một phản hồi thật (thực tế luôn ≥ 800 khi có `Add-Padding`).
pub const MIN_RANGE_LINES: usize = 100;
/// Thời gian tối đa cho MỘT yêu cầu mạng.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Thời gian tối đa cho cả lượt kiểm tra rò rỉ.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, thiserror::Error)]
pub enum BreachError {
    #[error("không kết nối được Have I Been Pwned: {0}")]
    Network(String),
    #[error("phản hồi nhận được không phải của Have I Been Pwned (có thể mạng đang bị chặn hoặc soi HTTPS)")]
    BadResponse,
    #[error("kiểm tra rò rỉ mất quá nhiều thời gian (mạng chậm) — chưa kiểm tra xong")]
    TooSlow,
}

/// Một câu hỏi gửi tới Have I Been Pwned cho một mục. KHÔNG chứa mật khẩu, chỉ chứa mã băm SHA-1
/// của nó (đã tách đôi); phần `suffix` không bao giờ rời máy và được xoá khỏi RAM khi dùng xong.
pub struct BreachQuery {
    pub id: String,
    prefix: String,
    suffix: Zeroizing<String>,
}

/// Chuẩn bị các câu hỏi cho mọi mục có mật khẩu. Tách riêng bước này để app chỉ cần giữ khoá phiên
/// trong lúc chuẩn bị, rồi nhả ra trước khi gọi mạng (mạng treo không còn làm treo cả app).
pub fn breach_queries(entries: &[Entry]) -> Vec<BreachQuery> {
    entries
        .iter()
        .filter(|e| !e.password.is_empty())
        .map(|e| {
            let (prefix, suffix) = sha1_prefix_suffix(&e.password);
            BreachQuery {
                id: e.id.clone(),
                prefix,
                suffix: Zeroizing::new(suffix),
            }
        })
        .collect()
}

/// Gửi các câu hỏi (mỗi tiền tố chỉ hỏi 1 lần). Trả về id → số lần bị lộ (chỉ gồm mục bị lộ).
/// Lỗi ở bất kỳ yêu cầu nào ⇒ cả lượt coi như CHƯA kiểm tra (không báo "an toàn" một cách sai).
pub fn run_breach_queries(
    queries: &[BreachQuery],
    mut fetch: impl FnMut(&str) -> Result<String, BreachError>,
) -> Result<HashMap<String, u64>, BreachError> {
    let started = Instant::now();
    let mut cache: HashMap<&str, String> = HashMap::new();
    let mut found = HashMap::new();
    for q in queries {
        if !cache.contains_key(q.prefix.as_str()) {
            if started.elapsed() > TOTAL_TIMEOUT {
                return Err(BreachError::TooSlow);
            }
            let body = fetch(&q.prefix)?;
            if !looks_like_range_response(&body) {
                return Err(BreachError::BadResponse);
            }
            cache.insert(q.prefix.as_str(), body);
        }
        let count = count_in_range_response(&cache[q.prefix.as_str()], &q.suffix);
        if count > 0 {
            found.insert(q.id.clone(), count);
        }
    }
    Ok(found)
}

/// Ghi kết quả kiểm tra rò rỉ vào báo cáo.
pub fn apply_breaches(report: &mut Report, found: &HashMap<String, u64>) {
    for (id, &count) in found {
        report.push(id, Issue::Breached { count });
    }
    report.breach_check_done = true;
}

/// Kiểm tra rò rỉ cho mọi mật khẩu (mỗi tiền tố chỉ hỏi 1 lần).
/// `fetch(prefix)` trả về nội dung phản hồi — tách ra để test không cần mạng.
pub fn check_breaches(
    entries: &[Entry],
    report: &mut Report,
    fetch: impl FnMut(&str) -> Result<String, BreachError>,
) -> Result<(), BreachError> {
    let found = run_breach_queries(&breach_queries(entries), fetch)?;
    apply_breaches(report, &found);
    Ok(())
}

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .user_agent("pwv-password-manager")
            .build()
            .new_agent()
    })
}

/// Gọi API thật của Have I Been Pwned (miễn phí, không cần khoá API). Có giới hạn thời gian, và
/// dùng lại kết nối giữa các lần gọi.
pub fn hibp_fetch(prefix: &str) -> Result<String, BreachError> {
    debug_assert_eq!(prefix.len(), 5);
    let mut resp = agent()
        .get(format!("{HIBP_RANGE_URL}{prefix}"))
        .header("Add-Padding", "true")
        .call()
        .map_err(|e| BreachError::Network(e.to_string()))?;
    resp.body_mut()
        .read_to_string()
        .map_err(|e| BreachError::Network(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(id: &str, title: &str, pw: &str) -> Entry {
        let mut x = Entry::new(title);
        x.id = id.into();
        x.username = "u".into();
        x.password = pw.into();
        x
    }

    #[test]
    fn sha1_split_matches_known_value() {
        // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(
            sha1_prefix_suffix("password"),
            ("5BAA6".into(), "1E4C9B93F3F0682250B6CF8331B7EE68FD8".into())
        );
    }

    #[test]
    fn offline_checks() {
        let mut old = e("c", "Cũ", "Q7#vLp2!mZ9@wX4$kR8");
        old.created_at = now_ms() - 400 * 86_400_000;
        old.field_times.password = old.created_at;
        let entries = vec![
            e("a", "A", "123456"),
            e("b", "B", "Tr0ub4dor&3-horse-staple-xyz"),
            e("b2", "B2", "Tr0ub4dor&3-horse-staple-xyz"),
            old,
        ];
        let r = offline_report(&entries);
        assert!(matches!(r.issues["a"][0], Issue::Weak { .. }));
        assert!(
            matches!(&r.issues["b"][0], Issue::Reused { with } if with == &vec!["B2".to_string()])
        );
        assert!(matches!(r.issues["c"][0], Issue::Old { days } if days >= 400));
        assert_eq!(r.count(|i| matches!(i, Issue::Reused { .. })), 2);
        assert_eq!(r.score(), 25);
    }

    /// Mục nhập từ CSV chưa sửa mật khẩu mang thời điểm cố định IMPORTED_AT (1970): tuổi mật khẩu
    /// tính từ lúc nhập, không phải "56 năm".
    #[test]
    fn imported_password_age_counts_from_the_import() {
        let mut d = pwv_vault_core::VaultData::default();
        let now = now_ms();
        d.add_imported_at(
            e("i", "Nhập", "Q7#vLp2!mZ9@wX4$kR8-imported"),
            now - 10 * 86_400_000,
        );
        let entry = d.entries[0].clone();
        assert_eq!(entry.field_times.password, IMPORTED_AT);
        let r = offline_report(&[entry]);
        assert!(r
            .issues
            .get("i")
            .is_none_or(|v| v.iter().all(|i| !matches!(i, Issue::Old { .. }))));
        let mut old = d.entries[0].clone();
        old.created_at = now - 400 * 86_400_000;
        let r = offline_report(&[old]);
        assert!(matches!(r.issues["i"][0], Issue::Old { days } if (399..=401).contains(&days)));
    }

    /// Phản hồi giả giống thật: nhiều dòng đệm (count 0) + các dòng cho sẵn.
    fn fake_range(extra: &[(&str, u64)]) -> String {
        let mut body = String::new();
        for i in 0..MIN_RANGE_LINES {
            body.push_str(&format!("{:035X}:0\r\n", i + 1));
        }
        for (suffix, count) in extra {
            body.push_str(&format!("{suffix}:{count}\r\n"));
        }
        body
    }

    #[test]
    fn breach_check_with_fake_api_and_cache() {
        let entries = vec![
            e("a", "A", "password"),
            e("b", "B", "password"),
            e("c", "C", "unique-🔐"),
        ];
        let mut r = offline_report(&entries);
        let mut calls = Vec::new();
        check_breaches(&entries, &mut r, |prefix| {
            calls.push(prefix.to_string());
            Ok(if prefix == "5BAA6" {
                fake_range(&[("1E4C9B93F3F0682250B6CF8331B7EE68FD8", 10434004)])
            } else {
                fake_range(&[])
            })
        })
        .unwrap();
        assert_eq!(calls.len(), 2, "mỗi tiền tố chỉ hỏi 1 lần: {calls:?}");
        assert!(calls.iter().all(|p| p.len() == 5), "chỉ được gửi 5 ký tự");
        assert_eq!(r.issues["a"][0], Issue::Breached { count: 10434004 });
        assert_eq!(r.issues["b"][0], Issue::Breached { count: 10434004 });
        assert!(r
            .issues
            .get("c")
            .is_none_or(|v| !v.iter().any(|i| matches!(i, Issue::Breached { .. }))));
        assert!(r.breach_check_done);
    }

    /// Lỗi 0.1.2: mọi phản hồi mã 200 đều được tin ⇒ một trang HTML chặn mạng được hiểu là
    /// "đã kiểm tra, không mật khẩu nào bị lộ" kèm dấu tích xanh.
    #[test]
    fn garbage_responses_are_not_reported_as_clean() {
        let entries = vec![e("a", "A", "password")];
        for body in [
            "<html>Captive portal</html>".to_string(),
            String::new(),
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n".to_string(), // quá ít dòng
            format!("{}\nkhông phải dòng hợp lệ\n", fake_range(&[])),
        ] {
            let mut r = offline_report(&entries);
            let res = check_breaches(&entries, &mut r, |_| Ok(body.clone()));
            assert!(matches!(res, Err(BreachError::BadResponse)), "{body:.40}");
            assert!(!r.breach_check_done);
        }
        assert!(looks_like_range_response(&fake_range(&[])));
        // Lỗi mạng giữa chừng: cũng không được đánh dấu là đã kiểm tra.
        let mut r = offline_report(&entries);
        assert!(
            check_breaches(&entries, &mut r, |_| Err(BreachError::Network("x".into()))).is_err()
        );
        assert!(!r.breach_check_done);
    }

    #[test]
    fn queries_never_contain_the_password() {
        let entries = vec![e("a", "A", "hunter2-rat-bi-mat"), e("b", "B", "")];
        let q = breach_queries(&entries);
        assert_eq!(q.len(), 1, "mục không có mật khẩu thì không hỏi");
        assert_eq!(q[0].prefix.len(), 5);
        assert_eq!(q[0].suffix.len(), 35);
        assert!(!q[0].suffix.contains("hunter2"));
    }
}
