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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault: None,
            auto_lock_minutes: 5,
            clipboard_clear_secs: 20,
        }
    }
}

impl Config {
    pub fn file() -> Option<PathBuf> {
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
        self.vault = Some(std::path::absolute(vault).unwrap_or_else(|_| vault.to_path_buf()));
        self.save()
    }
}

/// Gợi ý vị trí đặt kho: ưu tiên thư mục Google Drive for Desktop
/// (bản tiếng Anh "My Drive" hoặc tiếng Việt "Drive của tôi"), nếu không có thì Documents.
pub fn suggest_vault_location() -> PathBuf {
    if cfg!(windows) {
        for letter in b'D'..=b'Z' {
            for name in ["My Drive", "Drive của tôi"] {
                let dir = PathBuf::from(format!("{}:\\{name}", letter as char));
                if dir.is_dir() {
                    return dir.join("Passwords").join("vault.pwv");
                }
            }
        }
    }
    dirs::document_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vault.pwv")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_config_without_new_fields_still_loads() {
        let c: Config = serde_json::from_str(r#"{"vault":"C:\\x\\vault.pwv"}"#).unwrap();
        assert_eq!(c.auto_lock_minutes, 5);
        assert_eq!(c.clipboard_clear_secs, 20);
        assert!(c.vault.is_some());
    }
}
