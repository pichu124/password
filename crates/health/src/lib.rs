//! Kiểm tra sức khoẻ mật khẩu.
//!
//! - **Yếu**: zxcvbn < 3/4.
//! - **Trùng**: cùng một mật khẩu dùng cho nhiều mục.
//! - **Cũ**: chưa đổi quá `OLD_AFTER_DAYS` ngày.
//! - **Bị lộ**: có trong cơ sở dữ liệu Have I Been Pwned. Dùng k-anonymity: chỉ gửi
//!   **5 ký tự đầu** của SHA-1, so khớp phần còn lại trên máy; mật khẩu không bao giờ rời máy.
//!   Bật `Add-Padding` để kích thước phản hồi không tiết lộ gì.

use std::collections::{BTreeMap, HashMap};

use pwv_generator::estimate_strength;
use pwv_vault_core::model::now_ms;
use pwv_vault_core::Entry;
use serde::Serialize;
use sha1::{Digest, Sha1};

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

/// Lần cuối mật khẩu được đặt (ms).
fn password_set_at(e: &Entry) -> i64 {
    e.password_history
        .iter()
        .map(|h| h.replaced_at)
        .max()
        .unwrap_or(e.created_at)
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

#[derive(Debug, thiserror::Error)]
pub enum BreachError {
    #[error("không kết nối được Have I Been Pwned: {0}")]
    Network(String),
}

/// Kiểm tra rò rỉ cho mọi mật khẩu (mỗi tiền tố chỉ hỏi 1 lần).
/// `fetch(prefix)` trả về nội dung phản hồi — tách ra để test không cần mạng.
pub fn check_breaches(
    entries: &[Entry],
    report: &mut Report,
    mut fetch: impl FnMut(&str) -> Result<String, BreachError>,
) -> Result<(), BreachError> {
    let mut cache: HashMap<String, String> = HashMap::new();
    for e in entries.iter().filter(|e| !e.password.is_empty()) {
        let (prefix, suffix) = sha1_prefix_suffix(&e.password);
        if !cache.contains_key(&prefix) {
            let body = fetch(&prefix)?;
            cache.insert(prefix.clone(), body);
        }
        let count = count_in_range_response(&cache[&prefix], &suffix);
        if count > 0 {
            report.push(&e.id, Issue::Breached { count });
        }
    }
    report.breach_check_done = true;
    Ok(())
}

/// Gọi API thật của Have I Been Pwned (miễn phí, không cần khoá API).
pub fn hibp_fetch(prefix: &str) -> Result<String, BreachError> {
    debug_assert_eq!(prefix.len(), 5);
    let mut resp = ureq::get(format!("{HIBP_RANGE_URL}{prefix}"))
        .header("Add-Padding", "true")
        .header("User-Agent", "pwv-password-manager")
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
                // Có dòng đệm (count 0) giống phản hồi thật khi bật Add-Padding.
                "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\n".into()
            } else {
                "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n".into()
            })
        })
        .unwrap();
        assert_eq!(calls.len(), 2, "mỗi tiền tố chỉ hỏi 1 lần: {calls:?}");
        assert!(calls.iter().all(|p| p.len() == 5), "chỉ được gửi 5 ký tự");
        assert_eq!(r.issues["a"][0], Issue::Breached { count: 10434004 });
        assert!(r
            .issues
            .get("c")
            .is_none_or(|v| !v.iter().any(|i| matches!(i, Issue::Breached { .. }))));
        assert!(r.breach_check_done);
    }
}
