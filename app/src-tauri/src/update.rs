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
    html_url: String,
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
    // Chỉ chấp nhận link về đúng trang release của repo này.
    if !r.html_url.starts_with(RELEASES_PAGE_PREFIX) {
        return Err("link release không thuộc repo pwv".into());
    }
    let latest = r.tag_name.trim_start_matches(['v', 'V']).to_string();
    let notes: String = r.body.unwrap_or_default().chars().take(2000).collect();
    Ok(Some(UpdateInfo {
        available: is_newer(&latest, current),
        current: current.to_string(),
        latest,
        page_url: r.html_url,
        notes,
        published_at: r.published_at.unwrap_or_default(),
    }))
}

/// Hỏi GitHub. `Ok(None)` khi repo chưa có bản phát hành nào.
pub fn check() -> Result<Option<UpdateInfo>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let resp = ureq::get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "pwv-app")
        .config()
        .http_status_as_error(false)
        .build()
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
    fn rejects_foreign_links_and_prereleases() {
        let evil = r#"{"tag_name":"v9.9.9","html_url":"https://evil.example/download"}"#;
        assert!(from_release_json(evil, "0.1.1").is_err());
        let pre = r#"{"tag_name":"v9.9.9","html_url":"https://github.com/pichu124/password/releases/tag/v9.9.9","prerelease":true}"#;
        assert_eq!(from_release_json(pre, "0.1.1").unwrap(), None);
    }
}
