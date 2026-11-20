//! Ghi file an toàn: nguyên tử, có sao lưu, chịu được việc Google Drive/antivirus
//! tạm khoá file trên Windows.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand::RngCore;

use crate::error::Result;

/// Số bản sao lưu giữ lại.
pub const BACKUPS_TO_KEEP: usize = 10;
const RETRIES: u32 = 8;

/// Thư mục sao lưu: `<file>.backups/` nằm cạnh file kho.
pub fn backup_dir(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".backups");
    path.with_file_name(name)
}

/// Ghi `bytes` vào `path` theo cách nguyên tử:
/// ghi ra file tạm cùng thư mục → fsync → (sao lưu file cũ) → rename đè.
pub fn atomic_write(path: &Path, bytes: &[u8], backup: bool) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut rnd = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let tmp_name = format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let tmp = dir.join(tmp_name);

    let result = (|| -> Result<()> {
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        if backup && path.exists() {
            make_backup(path)?;
        }
        retry(|| fs::rename(&tmp, path))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn make_backup(path: &Path) -> Result<()> {
    let dir = backup_dir(path);
    fs::create_dir_all(&dir)?;
    let stem = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    let ts = crate::model::now_ms();
    let target = dir.join(format!("{stem}-{ts}.{ext}"));
    retry(|| fs::copy(path, &target).map(|_| ()))?;

    // Xoá bớt bản cũ.
    let mut backups: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(&format!("{stem}-")))
        })
        .collect();
    backups.sort();
    while backups.len() > BACKUPS_TO_KEEP {
        let old = backups.remove(0);
        let _ = fs::remove_file(old);
    }
    Ok(())
}

/// Chuyển một thư mục (chỉ gồm file, không có thư mục con). Thử `rename` trước;
/// nếu khác ổ đĩa (ví dụ từ D:\ sang G:\) thì chép từng file rồi xoá bản cũ.
pub(crate) fn move_flat_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let p = entry?.path();
        if p.is_file() {
            fs::copy(&p, to.join(p.file_name().unwrap_or_default()))?;
        }
    }
    fs::remove_dir_all(from)
}

/// Thử lại khi gặp lỗi tạm thời (file đang bị process khác mở — thường gặp trên Windows).
pub(crate) fn retry<T>(mut op: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut delay = Duration::from_millis(50);
    for attempt in 0.. {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) if attempt < RETRIES && is_transient(&e) => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(1));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

fn is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    // ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33), ERROR_ACCESS_DENIED (5)
    matches!(e.kind(), PermissionDenied | Interrupted | WouldBlock)
        || matches!(e.raw_os_error(), Some(5) | Some(32) | Some(33))
}

/// Phần đuôi tên file (sau tên gốc) có phải kiểu bản xung đột của dịch vụ đồng bộ không:
/// - Google Drive: `vault (1).pwv`
/// - Dropbox (mọi ngôn ngữ): `vault (Binh's conflicted copy 2026-11-20).pwv`,
///   `vault (bản sao xung đột của Binh 2026-11-20).pwv`
/// - OneDrive: `vault-DESKTOP-AB12CD.pwv` (thêm tên máy viết hoa)
///
/// Nhận nhầm cũng vô hại: chỉ file có cùng `vault_id` (cùng kho) mới được gộp.
fn is_conflict_suffix(rest: &str) -> bool {
    let paren = rest.trim_start();
    if paren.len() >= 3 && paren.starts_with('(') && paren.ends_with(')') {
        return !paren[1..paren.len() - 1].trim().is_empty();
    }
    if let Some(machine) = rest.strip_prefix('-') {
        return machine.len() >= 2
            && machine.chars().any(|c| c.is_ascii_alphanumeric())
            && machine
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-');
    }
    false
}

/// Tìm các bản xung đột mà Google Drive / Dropbox / OneDrive tạo ra cạnh file kho.
pub fn conflict_copies(path: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(stem)) = (path.parent(), path.file_stem()) else {
        return Vec::new();
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let stem = stem.to_string_lossy().to_string();
    let ext = path.extension().map(|e| e.to_string_lossy().to_string());
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p != path)
        .filter(|p| {
            if p.extension().map(|e| e.to_string_lossy().to_string()) != ext {
                return false;
            }
            let s = p
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let Some(rest) = s.strip_prefix(&stem) else {
                return false;
            };
            is_conflict_suffix(rest)
        })
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_and_backups() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        for i in 0..15u8 {
            atomic_write(&p, &[i], true).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(fs::read(&p).unwrap(), vec![14]);
        let n = fs::read_dir(backup_dir(&p)).unwrap().count();
        assert_eq!(n, BACKUPS_TO_KEEP);
        // Không còn file tạm.
        let tmp = fs::read_dir(d.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(tmp, 0);
    }

    #[test]
    fn finds_conflict_copies_of_drive_dropbox_onedrive() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        for n in [
            "vault.pwv",
            // Google Drive
            "vault (1).pwv",
            "vault(2).pwv",
            // Dropbox, tiếng Anh và tiếng Việt
            "vault (Binh's conflicted copy 2026-11-20).pwv",
            "vault (bản sao xung đột của Binh 2026-11-20).pwv",
            // OneDrive
            "vault-DESKTOP-AB12CD.pwv",
            // Không phải bản xung đột
            "vault ().pwv",
            "vault-backup.pwv",
            "vault2.pwv",
            "vault (1).txt",
            "other (1).pwv",
        ] {
            fs::write(d.path().join(n), b"x").unwrap();
        }
        let mut names: Vec<String> = conflict_copies(&p)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        names.sort();
        let mut expected = vec![
            "vault (1).pwv",
            "vault (Binh's conflicted copy 2026-11-20).pwv",
            "vault (bản sao xung đột của Binh 2026-11-20).pwv",
            "vault(2).pwv",
            "vault-DESKTOP-AB12CD.pwv",
        ];
        expected.sort();
        assert_eq!(names, expected);
    }
}
