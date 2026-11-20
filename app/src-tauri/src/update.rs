//! Kiểm tra bản mới trên GitHub Releases.
//!
//! App chỉ **thông báo** và mở trang tải trong trình duyệt; không tự tải hay tự chạy file nào.
//! Chỉ gửi một yêu cầu tới api.github.com (GitHub biết địa chỉ IP, không có dữ liệu kho nào).

use serde::{Deserialize, Serialize};

pub const REPO: &str = "pichu124/password";
pub const RELEASES_PAGE_PREFIX: &str = "https://github.com/pichu124/password/releases/";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub available: bool,
    /// Trang release trên GitHub (người dùng tải bộ cài từ đây).
    pub page_url: String,
    pub notes: String,
    pub published_at: String,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// "v1.2.3" / "1.2.3" → (1, 2, 3). Bỏ qua hậu tố như "-beta".
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((
        it.next()??,
        it.next().unwrap_or(Some(0))?,
        it.next().unwrap_or(Some(0))?,
    ))
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Phân tích phản hồi JSON của `GET /repos/{repo}/releases/latest`.
pub fn from_release_json(json: &str, current: &str) -> Result<Option<UpdateInfo>, String> {
    let r: Release =
        serde_json::from_str(json).map_err(|e| format!("phản hồi lạ từ GitHub: {e}"))?;
    if r.draft || r.prerelease {
        return Ok(None);
    }
    let latest = r.tag_name.trim_start_matches(['v', 'V']).to_string();
    // Địa chỉ trang tải được DỰNG từ số phiên bản; không dùng bất kỳ địa chỉ nào trong phản hồi.
    let page_url = release_page_url(&latest).ok_or("tên phiên bản không hợp lệ")?;
    let notes: String = r.body.unwrap_or_default().chars().take(2000).collect();
    Ok(Some(UpdateInfo {
        available: is_newer(&latest, current),
        current: current.to_string(),
        latest,
        page_url,
        notes,
        published_at: r.published_at.unwrap_or_default(),
    }))
}

/// Trang tải của một phiên bản trên GitHub. Chỉ nhận số phiên bản dạng `1.2.3` (chữ số và dấu
/// chấm) nên không thể bị lái sang địa chỉ khác bằng `..`, `/`, `?`…
pub fn release_page_url(version: &str) -> Option<String> {
    let v = version.trim().trim_start_matches(['v', 'V']);
    let clean = !v.is_empty()
        && v.len() <= 32
        && v.split('.').count() <= 3
        && v.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    clean.then(|| format!("{RELEASES_PAGE_PREFIX}tag/v{v}"))
}

fn agent() -> &'static ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .http_status_as_error(false)
            .user_agent("pwv-app")
            .build()
            .new_agent()
    })
}

/// Hỏi GitHub. `Ok(None)` khi repo chưa có bản phát hành nào.
pub fn check() -> Result<Option<UpdateInfo>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let resp = agent()
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("không kết nối được GitHub: {e}"))?;
    let status = resp.status().as_u16();
    if status == 404 {
        return Ok(None);
    }
    if status != 200 {
        return Err(format!("GitHub trả về mã {status}"));
    }
    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("không đọc được phản hồi: {e}"))?;
    from_release_json(&body, CURRENT_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare() {
        assert_eq!(parse_version("v0.1.2"), Some((0, 1, 2)));
        assert_eq!(parse_version("1.10"), Some((1, 10, 0)));
        assert_eq!(parse_version("2.0.0-beta.1"), Some((2, 0, 0)));
        assert_eq!(parse_version("abc"), None);
        assert!(is_newer("v0.1.10", "0.1.9"));
        assert!(is_newer("0.2.0", "0.1.99"));
        assert!(!is_newer("v0.1.1", "0.1.1"));
        assert!(!is_newer("0.1.0", "0.1.1"));
        assert!(!is_newer("rác", "0.1.1"));
    }

    #[test]
    fn parses_github_release() {
        let json = r#"{"tag_name":"v0.2.0","html_url":"https://github.com/pichu124/password/releases/tag/v0.2.0",
            "body":"- Thêm tính năng","published_at":"2026-11-21T10:00:00Z","draft":false,"prerelease":false,"assets":[]}"#;
        let u = from_release_json(json, "0.1.1").unwrap().unwrap();
        assert!(u.available);
        assert_eq!(u.latest, "0.2.0");
        assert_eq!(u.notes, "- Thêm tính năng");
        let same = from_release_json(json, "0.2.0").unwrap().unwrap();
        assert!(!same.available);
    }

    #[test]
    fn page_url_is_built_from_the_version_never_taken_from_the_response() {
        // Phản hồi giả mạo trỏ sang nơi khác: bị bỏ qua, địa chỉ luôn là trang release của repo.
        let evil = r#"{"tag_name":"v9.9.9","html_url":"https://evil.example/download"}"#;
        let u = from_release_json(evil, "0.1.1").unwrap().unwrap();
        assert_eq!(
            u.page_url,
            "https://github.com/pichu124/password/releases/tag/v9.9.9"
        );
        // Tên phiên bản lạ (cố lái đường dẫn) bị từ chối.
        for bad in [
            r#"{"tag_name":"v1.0.0/../../../other/repo"}"#,
            r#"{"tag_name":"../../x"}"#,
            r#"{"tag_name":"1.0.0?x=1"}"#,
            r#"{"tag_name":""}"#,
        ] {
            assert!(from_release_json(bad, "0.1.1").is_err(), "{bad}");
        }
        let pre = r#"{"tag_name":"v9.9.9","prerelease":true}"#;
        assert_eq!(from_release_json(pre, "0.1.1").unwrap(), None);
    }

    #[test]
    fn release_page_url_accepts_only_plain_versions() {
        assert_eq!(
            release_page_url("0.2.0").as_deref(),
            Some("https://github.com/pichu124/password/releases/tag/v0.2.0")
        );
        assert_eq!(release_page_url("v1.10"), release_page_url("1.10"));
        for bad in [
            "",
            "1..2",
            "1.2.3.4",
            "1.2.3-beta",
            "../x",
            "1/2",
            "1.2.3 ",
            "a.b.c",
        ] {
            if bad == "1.2.3 " {
                assert!(
                    release_page_url(bad).is_some(),
                    "khoảng trắng đầu/cuối được cắt"
                );
            } else {
                assert!(release_page_url(bad).is_none(), "{bad}");
            }
        }
    }
}
