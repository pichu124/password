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
}

/// File kho vừa mở CŨ HƠN bản mà máy này đã từng thấy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rollback {
    /// Máy này từng thấy nội dung mới hơn (ms).
    pub seen_modified_at: i64,
    pub file_modified_at: i64,
    /// File được mã hoá bằng master password cũ hơn lần đổi mật khẩu đã biết.
    pub older_password: bool,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault: None,
            auto_lock_minutes: 5,
            clipboard_clear_secs: 20,
            check_updates: true,
            seen: BTreeMap::new(),
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

    /// So file kho vừa mở với mốc đã thấy. Trả về `Some` nếu file cũ hơn.
    pub fn rollback_of(
        &self,
        vault_id: &str,
        modified_at: i64,
        key_changed_at: i64,
    ) -> Option<Rollback> {
        let seen = self.seen.get(vault_id)?;
        let older_password = key_changed_at < seen.key_changed_at;
        (modified_at < seen.modified_at || older_password).then_some(Rollback {
            seen_modified_at: seen.modified_at,
            file_modified_at: modified_at,
            older_password,
        })
    }

    /// Người dùng đã biết và chấp nhận trạng thái hiện tại của kho (ví dụ vừa khôi phục từ bản
    /// sao lưu): đặt lại mốc để không cảnh báo "file cũ hơn" mãi.
    pub fn set_seen(&mut self, vault_id: &str, modified_at: i64, key_changed_at: i64) {
        self.seen.insert(
            vault_id.to_string(),
            SeenMark {
                modified_at,
                key_changed_at,
            },
        );
        self.sanitize();
    }

    /// Ghi nhận mốc mới (chỉ tăng). Trả về true nếu có thay đổi cần lưu.
    pub fn note_seen(&mut self, vault_id: &str, modified_at: i64, key_changed_at: i64) -> bool {
        let m = self.seen.entry(vault_id.to_string()).or_default();
        let new = SeenMark {
            modified_at: m.modified_at.max(modified_at),
            key_changed_at: m.key_changed_at.max(key_changed_at),
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
    pub fn set_vault_path(&mut self, vault: &Path) {
        self.vault = Some(if is_uri(vault) {
            vault.to_path_buf()
        } else {
            std::path::absolute(vault).unwrap_or_else(|_| vault.to_path_buf())
        });
    }

    /// Đặt đường dẫn kho và lưu.
    pub fn set_vault(&mut self, vault: &Path) -> std::io::Result<()> {
        self.set_vault_path(vault);
        self.save()
    }
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
        assert!(c.rollback_of("v", 10, 1).is_none(), "kho chưa từng thấy");
        assert!(c.note_seen("v", 100, 5));
        assert!(!c.note_seen("v", 90, 5), "mốc chỉ tăng");
        assert!(c.rollback_of("v", 100, 5).is_none());
        assert!(c.rollback_of("v", 150, 6).is_none());
        let r = c.rollback_of("v", 90, 5).unwrap();
        assert_eq!((r.seen_modified_at, r.file_modified_at), (100, 90));
        assert!(!r.older_password);
        assert!(c.rollback_of("v", 200, 4).unwrap().older_password);
        assert!(c.rollback_of("other", 1, 1).is_none());
        // Người dùng chấp nhận bản cũ (vừa khôi phục từ sao lưu): hết cảnh báo.
        c.set_seen("v", 90, 5);
        assert!(c.rollback_of("v", 90, 5).is_none());
        c.note_seen("v", 100, 5);
        for i in 0..20 {
            c.note_seen(&format!("x{i}"), i, 0);
        }
        assert!(c.seen.len() <= 8);
    }
}
