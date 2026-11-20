//! Cấu hình dùng chung giữa CLI và app: `%APPDATA%\pwv\config.json` trên Windows.
//! Không chứa bí mật nào.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault: None,
            auto_lock_minutes: 5,
            clipboard_clear_secs: 20,
            check_updates: true,
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
        Self::file()
            .and_then(|f| std::fs::read(f).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let f =
            Self::file().ok_or_else(|| std::io::Error::other("không tìm thấy thư mục cấu hình"))?;
        std::fs::create_dir_all(f.parent().unwrap())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        crate::fsutil::atomic_write(&f, &bytes, false).map_err(std::io::Error::other)
    }

    /// Đặt đường dẫn kho (chuyển sang đường dẫn tuyệt đối) và lưu.
    pub fn set_vault(&mut self, vault: &Path) -> std::io::Result<()> {
        self.vault = Some(if is_uri(vault) {
            vault.to_path_buf()
        } else {
            std::path::absolute(vault).unwrap_or_else(|_| vault.to_path_buf())
        });
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
    }
}
