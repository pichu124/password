//! Cấu hình dùng chung giữa CLI và app: `%APPDATA%\pwv\config.json` trên Windows.
//! Không chứa bí mật nào.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Giới hạn cho thời gian tự khoá (phút).
pub const MAX_AUTO_LOCK_MINUTES: u32 = 240;
/// Giới hạn cho thời gian tự xoá clipboard (giây).
pub const CLIPBOARD_CLEAR_SECS_MIN: u32 = 5;
pub const CLIPBOARD_CLEAR_SECS_MAX: u32 = 300;
const MAX_SEEN_VAULTS: usize = 8;

/// Mốc mới nhất mà máy này từng thấy của một kho.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SeenMark {
    /// `modified_at` lớn nhất đã thấy.
    pub modified_at: i64,
    /// Lần đổi master password mới nhất đã thấy.
    pub key_changed_at: i64,
    /// Dấu nhận dạng của khoá kho mà máy này dùng gần đây nhất (`Vault::key_tag`; 0 = chưa ghi
    /// nhận). Không phải bí mật.
    pub key_tag: u64,
    /// Dấu khoá (`Vault::key_tag`) mà lần quét gần nhất của `Vault::backups_under_other_password`
    /// KHÔNG tìm thấy bản sao lưu nào mở được khoá hiện tại bằng một master password khác (0 = chưa
    /// quét / lần quét gần nhất có tìm thấy). Để app không quét lại (và tải lại file từ dịch vụ đồng
    /// bộ) ở mỗi lần mở khoá. Không phải bí mật.
    pub wrap_scan: u64,
}

/// File kho vừa mở CŨ HƠN bản mà máy này đã từng thấy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rollback {
    /// Máy này từng thấy nội dung mới hơn (ms).
    pub seen_modified_at: i64,
    pub file_modified_at: i64,
    /// File được mã hoá bằng master password cũ hơn lần đổi mật khẩu đã biết.
    pub older_password: bool,
    /// Khoá của kho vừa mở KHÔNG nối tiếp từ khoá mà máy này dùng lần trước: kho được mở bằng một
    /// mật khẩu chính cũ, hoặc file đã bị thay bằng file do người biết mật khẩu cũ làm ra. (Mốc thời
    /// gian trong file không phát hiện được trường hợp sau, vì người đó tự ghi được con số bất kỳ.)
    pub unknown_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    /// Đường dẫn file kho mặc định.
    pub vault: Option<PathBuf>,
    /// Tự khoá sau bao nhiêu phút không thao tác (0 = không tự khoá — không khuyến nghị).
    pub auto_lock_minutes: u32,
    /// Tự xoá clipboard sau bao nhiêu giây.
    pub clipboard_clear_secs: u32,
    /// App tự kiểm tra bản mới trên GitHub (mỗi ngày một lần).
    pub check_updates: bool,
    /// Mốc mới nhất đã thấy của từng kho (theo vault_id) — để cảnh báo khi file kho bị thay bằng
    /// một bản cũ hơn (dịch vụ đồng bộ khôi phục nhầm, hoặc ai đó chép đè file cũ).
    pub seen: BTreeMap<String, SeenMark>,
    /// `vault_id` của kho được mở khoá thành công gần nhất TẠI đường dẫn `vault` (để tìm bản sao
    /// riêng của máy này khi kho đang khoá mà file kho không còn). Bị xoá khi `vault` đổi sang file
    /// khác. Không phải bí mật.
    pub last_vault_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault: None,
            auto_lock_minutes: 5,
            clipboard_clear_secs: 20,
            check_updates: true,
            seen: BTreeMap::new(),
            last_vault_id: None,
        }
    }
}

static CONFIG_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Đường dẫn kho dạng URI (ví dụ `content://…` trên Android) — không phải đường dẫn file thường.
pub fn is_uri(p: &Path) -> bool {
    p.to_string_lossy().contains("://")
}

impl Config {
    /// Đặt thư mục chứa config.json (dùng trên điện thoại, nơi không có %APPDATA%).
    /// Chỉ có tác dụng ở lần gọi đầu tiên.
    pub fn set_dir(dir: PathBuf) {
        let _ = CONFIG_DIR.set(dir);
    }

    pub fn file() -> Option<PathBuf> {
        if let Some(d) = CONFIG_DIR.get() {
            return Some(d.join("config.json"));
        }
        dirs::config_dir().map(|d| d.join("pwv").join("config.json"))
    }

    pub fn load() -> Config {
        let mut c: Config = Self::file()
            .and_then(|f| std::fs::read(f).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        c.sanitize();
        c
    }

    /// File cấu hình không được bảo vệ: ai ngồi vào máy cũng sửa được. Vì vậy mọi giá trị đọc
    /// lên đều bị ép về khoảng hợp lệ (ví dụ không thể đặt "xoá clipboard sau 4 tỉ giây").
    pub fn sanitize(&mut self) {
        self.auto_lock_minutes = self.auto_lock_minutes.min(MAX_AUTO_LOCK_MINUTES);
        self.clipboard_clear_secs = self
            .clipboard_clear_secs
            .clamp(CLIPBOARD_CLEAR_SECS_MIN, CLIPBOARD_CLEAR_SECS_MAX);
        while self.seen.len() > MAX_SEEN_VAULTS {
            let oldest = self
                .seen
                .iter()
                .min_by_key(|(_, m)| m.modified_at)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => self.seen.remove(&k),
                None => break,
            };
        }
    }

    /// Dấu khoá đã ghi nhận của một kho (0 = chưa có).
    pub fn seen_key_tag(&self, vault_id: &str) -> u64 {
        self.seen.get(vault_id).map_or(0, |m| m.key_tag)
    }

    /// So file kho vừa mở với mốc đã thấy. Trả về `Some` nếu file cũ hơn, hoặc nếu khoá của nó
    /// không nối tiếp khoá đã ghi nhận (`key_known == false`, xem `Vault::rollback_against`).
    pub fn rollback_of(
        &self,
        vault_id: &str,
        modified_at: i64,
        key_changed_at: i64,
        key_known: bool,
    ) -> Option<Rollback> {
        let seen = self.seen.get(vault_id)?;
        let older_password = key_changed_at < seen.key_changed_at;
        let unknown_key = seen.key_tag != 0 && !key_known;
        (modified_at < seen.modified_at || older_password || unknown_key).then_some(Rollback {
            seen_modified_at: seen.modified_at,
            file_modified_at: modified_at,
            older_password,
            unknown_key,
        })
    }

    /// Người dùng đã biết và chấp nhận trạng thái hiện tại của kho (ví dụ vừa khôi phục từ bản
    /// sao lưu): đặt lại mốc để không cảnh báo "file cũ hơn" mãi.
    pub fn set_seen(
        &mut self,
        vault_id: &str,
        modified_at: i64,
        key_changed_at: i64,
        key_tag: u64,
    ) {
        let wrap_scan = self.seen.get(vault_id).map_or(0, |m| m.wrap_scan);
        self.seen.insert(
            vault_id.to_string(),
            SeenMark {
                modified_at,
                key_changed_at,
                key_tag,
                wrap_scan,
            },
        );
        self.sanitize();
    }

    /// Lần quét gần nhất (`Vault::backups_under_other_password`) cho đúng khoá `key_tag` này đã không
    /// tìm thấy gì ⇒ không cần quét lại.
    pub fn wrap_scan_clean(&self, vault_id: &str, key_tag: u64) -> bool {
        key_tag != 0
            && self
                .seen
                .get(vault_id)
                .is_some_and(|m| m.wrap_scan == key_tag)
    }

    /// Ghi nhận: quét cho khoá `key_tag` không tìm thấy gì (chưa lưu). Trả về true nếu có thay đổi.
    pub fn set_wrap_scan_clean(&mut self, vault_id: &str, key_tag: u64) -> bool {
        let m = self.seen.entry(vault_id.to_string()).or_default();
        let changed = m.wrap_scan != key_tag;
        m.wrap_scan = key_tag;
        self.sanitize();
        changed
    }

    /// Đặt `last_vault_id` (chỉ khi `path` đúng là đường dẫn kho đang cấu hình). Trả về true nếu có
    /// thay đổi.
    pub fn note_last_vault(&mut self, path: &Path, vault_id: &str) -> bool {
        let Some(configured) = self.vault.as_deref() else {
            return false;
        };
        if !same_path(configured, path) || self.last_vault_id.as_deref() == Some(vault_id) {
            return false;
        }
        self.last_vault_id = Some(vault_id.to_string());
        true
    }

    /// Ghi nhận mốc mới (các mốc thời gian chỉ tăng). `key_tag` khác 0 thì thay dấu khoá đã ghi
    /// nhận — người gọi chỉ truyền dấu khi khoá hiện tại nối tiếp khoá cũ (xem
    /// `Vault::note_seen_in`); truyền 0 để giữ nguyên. Trả về true nếu có thay đổi cần lưu.
    pub fn note_seen(
        &mut self,
        vault_id: &str,
        modified_at: i64,
        key_changed_at: i64,
        key_tag: u64,
    ) -> bool {
        let m = self.seen.entry(vault_id.to_string()).or_default();
        let new = SeenMark {
            modified_at: m.modified_at.max(modified_at),
            key_changed_at: m.key_changed_at.max(key_changed_at),
            key_tag: if key_tag != 0 { key_tag } else { m.key_tag },
            wrap_scan: m.wrap_scan,
        };
        let changed = *m != new;
        *m = new;
        self.sanitize();
        changed
    }

    pub fn save(&self) -> std::io::Result<()> {
        let f =
            Self::file().ok_or_else(|| std::io::Error::other("không tìm thấy thư mục cấu hình"))?;
        std::fs::create_dir_all(f.parent().unwrap())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        crate::fsutil::atomic_write(&f, &bytes).map_err(std::io::Error::other)
    }

    /// Đặt đường dẫn kho (chuyển sang đường dẫn tuyệt đối) — chưa lưu.
    /// Nếu đường dẫn đổi sang một file khác thì `last_vault_id` bị xoá.
    pub fn set_vault_path(&mut self, vault: &Path) {
        let new = if is_uri(vault) {
            vault.to_path_buf()
        } else {
            std::path::absolute(vault).unwrap_or_else(|_| vault.to_path_buf())
        };
        if !self
            .vault
            .as_deref()
            .is_some_and(|old| same_path(old, &new))
        {
            self.last_vault_id = None;
        }
        self.vault = Some(new);
    }

    /// Đặt đường dẫn kho và lưu.
    pub fn set_vault(&mut self, vault: &Path) -> std::io::Result<()> {
        self.set_vault_path(vault);
        self.save()
    }
}

/// Hai đường dẫn chỉ cùng một file (so dạng tuyệt đối; URI so nguyên văn).
fn same_path(a: &Path, b: &Path) -> bool {
    if is_uri(a) || is_uri(b) {
        return a == b;
    }
    let abs = |p: &Path| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    abs(a) == abs(b)
}

/// Gợi ý vị trí đặt kho, theo thứ tự: thư mục Google Drive for Desktop (bản tiếng Anh
/// "My Drive" hoặc tiếng Việt "Drive của tôi"), Dropbox, OneDrive, cuối cùng là Documents.
pub fn suggest_vault_location() -> PathBuf {
    sync_folder_candidates()
        .into_iter()
        .find(|d| d.is_dir())
        .map(|d| d.join("Passwords").join("vault.pwv"))
        .unwrap_or_else(|| {
            dirs::document_dir()
                .or_else(dirs::home_dir)
                .unwrap_or_else(|| PathBuf::from("."))
                .join("vault.pwv")
        })
}

fn sync_folder_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        for letter in b'D'..=b'Z' {
            for name in ["My Drive", "Drive của tôi"] {
                out.push(PathBuf::from(format!("{}:\\{name}", letter as char)));
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        out.push(home.join("Dropbox"));
    }
    // OneDrive đặt biến môi trường trỏ tới thư mục của nó.
    for var in ["OneDrive", "OneDriveConsumer"] {
        if let Some(p) = std::env::var_os(var) {
            out.push(PathBuf::from(p));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_config_without_new_fields_still_loads() {
        let c: Config = serde_json::from_str(r#"{"vault":"C:\\x\\vault.pwv"}"#).unwrap();
        assert_eq!(c.auto_lock_minutes, 5);
        assert_eq!(c.clipboard_clear_secs, 20);
        assert!(c.check_updates);
        assert!(c.vault.is_some());
        assert!(c.seen.is_empty());
    }

    #[test]
    fn hostile_values_are_clamped() {
        let mut c: Config = serde_json::from_str(
            r#"{"auto_lock_minutes":4000000000,"clipboard_clear_secs":4000000000}"#,
        )
        .unwrap();
        c.sanitize();
        assert_eq!(c.auto_lock_minutes, MAX_AUTO_LOCK_MINUTES);
        assert_eq!(c.clipboard_clear_secs, CLIPBOARD_CLEAR_SECS_MAX);
        let mut c: Config = serde_json::from_str(r#"{"clipboard_clear_secs":0}"#).unwrap();
        c.sanitize();
        assert_eq!(c.clipboard_clear_secs, CLIPBOARD_CLEAR_SECS_MIN);
    }

    #[test]
    fn rollback_detection() {
        let mut c = Config::default();
        assert!(
            c.rollback_of("v", 10, 1, true).is_none(),
            "kho chưa từng thấy"
        );
        assert!(c.note_seen("v", 100, 5, 0));
        assert!(!c.note_seen("v", 90, 5, 0), "mốc chỉ tăng");
        assert!(c.rollback_of("v", 100, 5, true).is_none());
        assert!(c.rollback_of("v", 150, 6, true).is_none());
        let r = c.rollback_of("v", 90, 5, true).unwrap();
        assert_eq!((r.seen_modified_at, r.file_modified_at), (100, 90));
        assert!(!r.older_password && !r.unknown_key);
        assert!(c.rollback_of("v", 200, 4, true).unwrap().older_password);
        assert!(c.rollback_of("other", 1, 1, true).is_none());
        // Người dùng chấp nhận bản cũ (vừa khôi phục từ sao lưu): hết cảnh báo.
        c.set_seen("v", 90, 5, 0);
        assert!(c.rollback_of("v", 90, 5, true).is_none());
        c.note_seen("v", 100, 5, 0);
        for i in 0..20 {
            c.note_seen(&format!("x{i}"), i, 0, 0);
        }
        assert!(c.seen.len() <= 8);
    }

    #[test]
    fn unknown_key_is_reported_until_accepted() {
        let mut c = Config::default();
        // Chưa ghi nhận dấu khoá nào (config của bản cũ): không cảnh báo.
        c.note_seen("v", 100, 5, 0);
        assert!(c.rollback_of("v", 100, 5, false).is_none());
        // Đã ghi nhận dấu khoá: kho mở bằng khoá không nối tiếp ⇒ cảnh báo, kể cả khi các mốc thời
        // gian trong file đều "mới" (người biết mật khẩu cũ tự ghi được con số bất kỳ).
        assert!(c.note_seen("v", 100, 5, 0xABC1));
        assert_eq!(c.seen_key_tag("v"), 0xABC1);
        let r = c.rollback_of("v", 9_999, 9_999, false).unwrap();
        assert!(r.unknown_key && !r.older_password);
        assert!(c.rollback_of("v", 9_999, 9_999, true).is_none());
        // Ghi nhận mốc với dấu 0 (khoá lạ, chưa được chấp nhận) không xoá dấu cũ ⇒ cảnh báo còn nguyên.
        c.note_seen("v", 9_999, 9_999, 0);
        assert_eq!(c.seen_key_tag("v"), 0xABC1);
        assert!(c.rollback_of("v", 9_999, 9_999, false).unwrap().unknown_key);
        // Chủ kho chấp nhận ⇒ dấu mới thay dấu cũ.
        c.set_seen("v", 9_999, 9_999, 0xDEF1);
        assert_eq!(c.seen_key_tag("v"), 0xDEF1);
        assert!(c.rollback_of("v", 9_999, 9_999, true).is_none());
    }

    #[test]
    fn old_seen_marks_without_key_tag_still_load() {
        let c: Config =
            serde_json::from_str(r#"{"seen":{"v":{"modified_at":7,"key_changed_at":3}}}"#).unwrap();
        assert_eq!(c.seen["v"].modified_at, 7);
        assert_eq!(c.seen_key_tag("v"), 0);
    }

    #[test]
    fn wrap_scan_memo_survives_seen_updates() {
        let mut c = Config::default();
        assert!(!c.wrap_scan_clean("v", 7));
        assert!(c.set_wrap_scan_clean("v", 7));
        assert!(!c.set_wrap_scan_clean("v", 7));
        assert!(c.wrap_scan_clean("v", 7));
        assert!(!c.wrap_scan_clean("v", 9), "khoá khác ⇒ quét lại");
        assert!(!c.wrap_scan_clean("v", 0));
        c.note_seen("v", 100, 5, 7);
        c.set_seen("v", 90, 5, 7);
        assert!(c.wrap_scan_clean("v", 7));
        assert_eq!(c.seen["v"].modified_at, 90);
        let back: Config = serde_json::from_slice(&serde_json::to_vec(&c).unwrap()).unwrap();
        assert!(back.wrap_scan_clean("v", 7));
    }

    #[test]
    fn last_vault_id_is_cleared_when_the_vault_path_changes() {
        let mut c: Config = serde_json::from_str(r#"{"vault":"/a/vault.pwv"}"#).unwrap();
        assert_eq!(c.last_vault_id, None);
        assert!(!c.note_last_vault(Path::new("/b/vault.pwv"), "id"));
        assert!(c.note_last_vault(Path::new("/a/vault.pwv"), "id"));
        assert!(!c.note_last_vault(Path::new("/a/vault.pwv"), "id"));
        c.set_vault_path(Path::new("/a/vault.pwv"));
        assert_eq!(c.last_vault_id.as_deref(), Some("id"));
        c.set_vault_path(Path::new("/b/vault.pwv"));
        assert_eq!(c.last_vault_id, None);
    }
}
