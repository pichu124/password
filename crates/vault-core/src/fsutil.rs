//! Ghi file an toàn: nguyên tử, có sao lưu, chịu được việc Google Drive/antivirus
//! tạm khoá file trên Windows.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use rand::RngCore;

use crate::error::{Error, Result};

/// Luôn giữ ngần này bản sao lưu mới nhất…
pub const KEEP_RECENT: usize = 10;
/// …cộng bản cuối cùng của mỗi NGÀY (UTC) trong ngần này ngày gần nhất CÓ bản sao lưu…
pub const KEEP_DAILY_DAYS: usize = 30;
/// …cộng bản cuối cùng của mỗi kỳ 30 ngày trong ngần này kỳ gần nhất CÓ bản sao lưu.
pub const KEEP_MONTHLY: usize = 12;
/// Số bản xung đột đã gộp / file hỏng đã cất / bản ghi bằng khoá cũ giữ lại (mỗi loại) trong thư
/// mục sao lưu.
pub const KEEP_ARCHIVED: usize = 20;
/// File lớn hơn mức này không được coi là file kho (chống file rác làm đầy RAM).
pub const MAX_VAULT_FILE: u64 = 64 * 1024 * 1024;
const MAX_SIBLINGS: usize = 32;
const DAY_MS: i64 = 86_400_000;

/// Thư mục sao lưu: `<file>.backups/` nằm cạnh file kho.
pub fn backup_dir(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".backups");
    path.with_file_name(name)
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn temp_path(path: &Path) -> PathBuf {
    let mut rnd = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    parent_of(path).join(format!(
        ".{}.{}.tmp",
        file_name_of(path),
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// Đọc cả file, thử lại nếu file đang bị tiến trình khác (dịch vụ đồng bộ, antivirus) giữ.
pub fn read_retry(path: &Path) -> std::io::Result<Vec<u8>> {
    retry(|| fs::read(path))
}

/// Đọc tối đa `max` byte đầu của file.
pub fn read_prefix(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    fs::File::open(path)?
        .take(max as u64)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// Ghi `bytes` vào `path` theo cách nguyên tử: ghi ra file tạm cùng thư mục → fsync → rename đè.
/// Mất điện giữa chừng thì file cũ vẫn nguyên vẹn.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_path(path);
    let result = (|| -> Result<()> {
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        retry(|| fs::rename(&tmp, path))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = retry(|| fs::remove_file(&tmp));
    }
    result
}

/// Như [`atomic_write`], rồi đọc lại để chắc chắn đúng những byte đó đã nằm trên đĩa.
pub fn atomic_write_verified(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write(path, bytes)?;
    match read_retry(path) {
        Ok(back) if back == bytes => Ok(()),
        _ => Err(Error::WriteVerifyFailed),
    }
}

/// Tạo file MỚI (báo lỗi nếu đã có file trùng tên — kể cả khi nó vừa xuất hiện do đồng bộ).
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::AlreadyExists(path.display().to_string()))
        }
        Err(e) => return Err(e.into()),
    };
    let result = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = result {
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    Ok(())
}

// ----------------------------------------------------------------------------- sao lưu

/// Loại file nằm trong thư mục sao lưu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKind {
    /// Bản sao tự động của file kho trước mỗi lần ghi: `vault-<ms>.pwv`.
    Auto,
    /// Bản xung đột của dịch vụ đồng bộ đã được gộp xong: `merged-<ms>-<tên gốc>`.
    Merged,
    /// File kho bị hỏng đã được thay bằng bản tốt: `damaged-<ms>-<tên gốc>`.
    Damaged,
    /// Một bản (file kho chính hoặc bản xung đột) chỉ mở được bằng khoá của mật khẩu chính CŨ, nên
    /// KHÔNG được tự gộp: `oldkey-<ms>-<tên gốc>`. Nội dung đã được mã hoá lại bằng khoá hiện tại
    /// (mật khẩu cũ không mở được nó nữa); chủ kho xem lại và lấy từng mục ra nếu muốn.
    OldKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFile {
    pub path: PathBuf,
    pub kind: BackupKind,
    /// Thời điểm ghi trong tên file (ms).
    pub timestamp: i64,
}

fn stem_and_ext(path: &Path) -> (String, String) {
    (
        path.file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        path.extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default(),
    )
}

fn leading_timestamp(s: &str) -> Option<(i64, &str)> {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits > 15 {
        return None;
    }
    Some((s[..digits].parse().ok()?, &s[digits..]))
}

fn classify(vault_path: &Path, name: &str) -> Option<(BackupKind, i64)> {
    for (prefix, kind) in [
        ("merged-", BackupKind::Merged),
        ("damaged-", BackupKind::Damaged),
        ("oldkey-", BackupKind::OldKey),
    ] {
        if let Some(rest) = name.strip_prefix(prefix) {
            let (ts, rest) = leading_timestamp(rest)?;
            return rest.starts_with('-').then_some((kind, ts));
        }
    }
    let (stem, ext) = stem_and_ext(vault_path);
    let rest = name.strip_prefix(&stem)?.strip_prefix('-')?;
    let (ts, rest) = leading_timestamp(rest)?;
    let expected = if ext.is_empty() {
        String::new()
    } else {
        format!(".{ext}")
    };
    (rest == expected).then_some((BackupKind::Auto, ts))
}

/// Liệt kê các file trong thư mục sao lưu của kho, mới nhất trước.
pub fn list_backups(vault_path: &Path) -> Vec<BackupFile> {
    let Ok(rd) = fs::read_dir(backup_dir(vault_path)) else {
        return Vec::new();
    };
    let mut out: Vec<BackupFile> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .filter_map(|p| {
            let (kind, timestamp) = classify(vault_path, &file_name_of(&p))?;
            Some(BackupFile {
                path: p,
                kind,
                timestamp,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

/// Chọn tên cho một bản sao lưu mới (tạo thư mục nếu chưa có; không trùng với bản đã có).
fn next_backup_path(path: &Path, now: i64) -> std::io::Result<PathBuf> {
    let dir = backup_dir(path);
    fs::create_dir_all(&dir)?;
    let (stem, ext) = stem_and_ext(path);
    let mut ts = now;
    loop {
        let name = if ext.is_empty() {
            format!("{stem}-{ts}")
        } else {
            format!("{stem}-{ts}.{ext}")
        };
        let t = dir.join(name);
        if !t.exists() {
            return Ok(t);
        }
        ts += 1; // hai lần lưu trong cùng một mili-giây: không đè lên bản trước
    }
}

/// Chép file kho hiện tại vào thư mục sao lưu (gọi ngay trước khi ghi đè nó).
/// Trả về `None` nếu chưa có file nào để sao lưu.
pub fn backup_current(path: &Path, now: i64) -> std::io::Result<Option<PathBuf>> {
    if !path.is_file() {
        return Ok(None);
    }
    let target = next_backup_path(path, now)?;
    retry(|| fs::copy(path, &target).map(|_| ()))?;
    Ok(Some(target))
}

/// Ghi `bytes` (nội dung file kho vừa được ghi) thành một bản sao lưu mới.
pub fn backup_bytes(path: &Path, now: i64, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let target = next_backup_path(path, now)?;
    atomic_write(&target, bytes).map_err(std::io::Error::other)?;
    Ok(target)
}

/// Chọn những bản sao lưu tự động cần XOÁ (theo thời điểm trong tên file).
///
/// Chỉ phụ thuộc vào chính các thời điểm đó — KHÔNG dùng đồng hồ của máy đang dọn. Thư mục sao lưu
/// nằm trong thư mục đồng bộ, nên một máy chạy sai giờ (hết pin CMOS, giờ nhảy tới tương lai) mà dọn
/// theo đồng hồ của nó thì sẽ xoá phần lớn lịch sử sao lưu trên MỌI máy.
///
/// Giữ lại (sau khi bỏ trùng, xếp mới → cũ):
/// - [`KEEP_RECENT`] bản mới nhất;
/// - bản mới nhất của mỗi ngày UTC, trong [`KEEP_DAILY_DAYS`] ngày gần nhất CÓ bản sao lưu;
/// - bản mới nhất của mỗi kỳ 30 ngày (tính từ 1970), trong [`KEEP_MONTHLY`] kỳ gần nhất CÓ bản
///   sao lưu.
///
/// Nhờ vậy vài chục lần lưu lặt vặt trong một buổi tối không đẩy được các trạng thái cũ ra ngoài, kho
/// ít dùng vẫn giữ lịch sử dài, và số bản giữ lại luôn ≤ 10 + 30 + 12. Bản mang thời điểm "ở tương
/// lai" (máy kia sai giờ) chỉ chiếm chỗ của đúng số ngày/kỳ mà chúng mang, không hơn.
pub fn backups_to_prune(stamps: &[i64]) -> Vec<i64> {
    let mut sorted: Vec<i64> = stamps.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.dedup();

    let mut keep: HashSet<i64> = sorted.iter().take(KEEP_RECENT).copied().collect();
    let (mut days, mut periods): (Vec<i64>, Vec<i64>) = (Vec::new(), Vec::new());
    for &t in &sorted {
        // `sorted` xếp mới → cũ, nên bản gặp đầu tiên của mỗi ô là bản mới nhất của ngày/kỳ đó.
        let day = t.div_euclid(DAY_MS);
        if days.len() < KEEP_DAILY_DAYS && days.last() != Some(&day) {
            days.push(day);
            keep.insert(t);
        }
        let period = day.div_euclid(30);
        if periods.len() < KEEP_MONTHLY && periods.last() != Some(&period) {
            periods.push(period);
            keep.insert(t);
        }
    }
    sorted.into_iter().filter(|t| !keep.contains(t)).collect()
}

/// Dọn thư mục sao lưu theo [`backups_to_prune`]. Chỉ xoá file mà `is_ours` xác nhận thuộc về
/// đúng kho này — file lạ (kho khác trùng tên, file người dùng tự chép vào) không bao giờ bị đụng tới.
/// Các bản đã cất (`merged-…`, `damaged-…`, `oldkey-…`): giữ [`KEEP_ARCHIVED`] bản mới nhất mỗi loại.
pub fn prune_backups(vault_path: &Path, is_ours: impl Fn(&Path) -> bool) {
    let all = list_backups(vault_path);
    let autos: Vec<i64> = all
        .iter()
        .filter(|b| b.kind == BackupKind::Auto)
        .map(|b| b.timestamp)
        .collect();
    let doomed: HashSet<i64> = backups_to_prune(&autos).into_iter().collect();
    for b in all
        .iter()
        .filter(|b| b.kind == BackupKind::Auto && doomed.contains(&b.timestamp))
    {
        if is_ours(&b.path) {
            let _ = fs::remove_file(&b.path);
        }
    }
    for kind in [BackupKind::Merged, BackupKind::Damaged, BackupKind::OldKey] {
        // `all` đã xếp mới nhất trước.
        for b in all.iter().filter(|b| b.kind == kind).skip(KEEP_ARCHIVED) {
            if is_ours(&b.path) {
                let _ = fs::remove_file(&b.path);
            }
        }
    }
}

/// Đường dẫn để cất một file (bản xung đột đã gộp, file hỏng) vào thư mục sao lưu.
pub fn archive_path(vault_path: &Path, kind: BackupKind, now: i64, original: &Path) -> PathBuf {
    let prefix = match kind {
        BackupKind::Merged => "merged",
        BackupKind::Damaged => "damaged",
        BackupKind::OldKey => "oldkey",
        BackupKind::Auto => "copy",
    };
    let dir = backup_dir(vault_path);
    let mut ts = now;
    loop {
        let p = dir.join(format!("{prefix}-{ts}-{}", file_name_of(original)));
        if !p.exists() {
            return p;
        }
        ts += 1;
    }
}

/// Chuyển `file` vào thư mục sao lưu dưới tên `<loại>-<ms>-<tên gốc>`.
pub fn archive_file(
    vault_path: &Path,
    kind: BackupKind,
    now: i64,
    file: &Path,
) -> std::io::Result<PathBuf> {
    fs::create_dir_all(backup_dir(vault_path))?;
    let target = archive_path(vault_path, kind, now, file);
    retry(|| fs::rename(file, &target))?;
    Ok(target)
}

/// Ghi `bytes` thành một file mới trong thư mục sao lưu dưới tên `<loại>-<ms>-<tên gốc>` (nguyên
/// tử). Dùng khi thứ được cất không phải chính file gốc (ví dụ bản đã được mã hoá lại).
pub fn write_archive(
    vault_path: &Path,
    kind: BackupKind,
    now: i64,
    original: &Path,
    bytes: &[u8],
) -> std::io::Result<PathBuf> {
    fs::create_dir_all(backup_dir(vault_path))?;
    let target = archive_path(vault_path, kind, now, original);
    atomic_write(&target, bytes).map_err(|e| match e {
        Error::Io(io) => io,
        e => std::io::Error::other(e.to_string()),
    })?;
    Ok(target)
}

// ----------------------------------------------------------------------------- thư mục

/// Chuyển một thư mục phẳng (chỉ gồm file). Thử `rename` trước; nếu khác ổ đĩa (ví dụ từ D:\ sang
/// G:\) thì chép từng file rồi xoá ĐÚNG file vừa chép. Không bao giờ xoá đệ quy, không ghi đè file
/// đã có ở đích. Trả về true nếu thư mục nguồn đã trống và được gỡ bỏ.
pub(crate) fn move_flat_dir(from: &Path, to: &Path) -> std::io::Result<bool> {
    if !to.exists() && fs::rename(from, to).is_ok() {
        return Ok(true);
    }
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let src = entry?.path();
        if !src.is_file() {
            continue;
        }
        let dst = to.join(src.file_name().unwrap_or_default());
        if dst.exists() {
            continue;
        }
        fs::copy(&src, &dst)?;
        if fs::metadata(&dst)?.len() == fs::metadata(&src)?.len() {
            let _ = fs::remove_file(&src);
        }
    }
    Ok(fs::remove_dir(from).is_ok())
}

/// Dạng chuẩn của một đường dẫn có thể chưa tồn tại: chuẩn hoá phần thư mục đã có (theo hệ điều
/// hành: phân giải symlink, hoa/thường trên Windows) rồi nối phần còn lại.
pub(crate) fn canonical_lossy(path: &Path) -> PathBuf {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = abs.as_path();
    loop {
        if let Ok(c) = fs::canonicalize(cur) {
            let mut out = c;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                cur = parent;
            }
            _ => return abs,
        }
    }
}

/// `path` có nằm trong (hoặc chính là) thư mục `dir` không?
pub(crate) fn is_within(path: &Path, dir: &Path) -> bool {
    let (p, d) = (canonical_lossy(path), canonical_lossy(dir));
    let norm = |x: &Path| -> Vec<String> {
        x.components()
            .filter(|c| !matches!(c, Component::CurDir))
            .map(|c| {
                let s = c.as_os_str().to_string_lossy().to_string();
                if cfg!(windows) {
                    s.to_lowercase()
                } else {
                    s
                }
            })
            .collect()
    };
    let (p, d) = (norm(&p), norm(&d));
    p.len() >= d.len() && p[..d.len()] == d[..]
}

/// Thử lại khi gặp lỗi tạm thời (file đang bị process khác mở — thường gặp trên Windows).
///
/// "File đang bị dùng" (lỗi 32/33) được thử lại lâu (~4,5 giây). "Không có quyền" (lỗi 5) trên
/// Windows đôi khi cũng chỉ là tạm thời (antivirus đang quét) nhưng thường là vĩnh viễn (thư mục
/// chỉ đọc), nên chỉ thử lại vài lần (~0,35 giây) để không làm treo app.
pub(crate) fn retry<T>(mut op: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    const SHARING_RETRIES: u32 = 8;
    const DENIED_RETRIES: u32 = 3;
    let mut delay = Duration::from_millis(50);
    for attempt in 0.. {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let budget = match transient_kind(&e) {
                    Some(Transient::Sharing) => SHARING_RETRIES,
                    Some(Transient::Denied) => DENIED_RETRIES,
                    None => 0,
                };
                if attempt >= budget {
                    return Err(e);
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        }
    }
    unreachable!()
}

enum Transient {
    Sharing,
    Denied,
}

fn transient_kind(e: &std::io::Error) -> Option<Transient> {
    use std::io::ErrorKind::*;
    // Windows: ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33), ERROR_ACCESS_DENIED (5).
    if cfg!(windows) && matches!(e.raw_os_error(), Some(32) | Some(33)) {
        return Some(Transient::Sharing);
    }
    match e.kind() {
        Interrupted | WouldBlock => Some(Transient::Sharing),
        PermissionDenied => Some(Transient::Denied),
        _ => None,
    }
}

// ----------------------------------------------------------------------------- file cạnh kho

/// Các file khác nằm cùng thư mục, cùng phần mở rộng với file kho — ứng viên là bản xung đột do
/// Google Drive / Dropbox / OneDrive tạo (`vault (1).pwv`, `vault (… conflicted copy …).pwv`,
/// `vault-TÊN-MÁY.pwv`…). Không đoán theo tên: người gọi sẽ đọc header và chỉ nhận file có cùng
/// `vault_id`. Bỏ qua file ẩn/tạm (tên bắt đầu bằng dấu chấm) và file quá lớn.
pub fn sibling_candidates(path: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(parent_of(path)) else {
        return Vec::new();
    };
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    let own = file_name_of(path);
    let mut out: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            let name = file_name_of(p);
            let same_file = if cfg!(windows) {
                name.to_lowercase() == own.to_lowercase()
            } else {
                name == own
            };
            !same_file
                && !name.starts_with('.')
                && p.extension().map(|e| e.to_string_lossy().to_lowercase()) == ext
                && fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() <= MAX_VAULT_FILE)
        })
        .collect();
    out.sort();
    out.truncate(MAX_SIBLINGS);
    out
}

/// Xoá các file tạm `.vault.pwv.<12 hex>.tmp` bị bỏ lại (app bị tắt đột ngột giữa lúc ghi).
/// Chỉ xoá file cũ hơn 10 phút — file mới hơn có thể đang được một tiến trình khác ghi.
pub fn clean_stale_temps(path: &Path) {
    let Ok(rd) = fs::read_dir(parent_of(path)) else {
        return;
    };
    let prefix = format!(".{}.", file_name_of(path));
    for p in rd.filter_map(|e| e.ok().map(|e| e.path())) {
        let name = file_name_of(&p);
        let Some(mid) = name
            .strip_prefix(&prefix)
            .and_then(|r| r.strip_suffix(".tmp"))
        else {
            continue;
        };
        if mid.len() != 12 || !mid.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let old_enough = fs::metadata(&p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > Duration::from_secs(600));
        if old_enough {
            let _ = fs::remove_file(&p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        for i in 0..5u8 {
            atomic_write_verified(&p, &[i; 100]).unwrap();
        }
        assert_eq!(fs::read(&p).unwrap(), vec![4; 100]);
        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1,
            "không còn file tạm"
        );
    }

    #[test]
    fn write_new_refuses_existing_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        write_new(&p, b"one").unwrap();
        assert!(matches!(
            write_new(&p, b"two"),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&p).unwrap(), b"one");
    }

    #[test]
    fn backups_are_listed_and_classified() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        fs::write(&p, b"v1").unwrap();
        let b1 = backup_current(&p, 1_700_000_000_000).unwrap().unwrap();
        let b2 = backup_current(&p, 1_700_000_000_000).unwrap().unwrap();
        assert_ne!(b1, b2, "cùng mili-giây không đè lên nhau");
        let conflict = d.path().join("vault (1).pwv");
        fs::write(&conflict, b"c").unwrap();
        let merged = archive_file(&p, BackupKind::Merged, 1_700_000_000_500, &conflict).unwrap();
        assert!(!conflict.exists() && merged.exists());
        for junk in [
            "vault-abc.pwv",
            "other-1700000000000.pwv",
            "notes.txt",
            "vault-17.txt",
        ] {
            fs::write(backup_dir(&p).join(junk), b"x").unwrap();
        }
        let list = list_backups(&p);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].kind, BackupKind::Merged);
        assert_eq!(list[0].timestamp, 1_700_000_000_500);
        assert_eq!(list[1].timestamp, 1_700_000_000_001);
        assert!(list[1..].iter().all(|b| b.kind == BackupKind::Auto));
        assert!(backup_current(&d.path().join("missing.pwv"), 1)
            .unwrap()
            .is_none());
    }

    fn kept(stamps: &[i64]) -> Vec<i64> {
        let prune: HashSet<i64> = backups_to_prune(stamps).into_iter().collect();
        let mut k: Vec<i64> = stamps
            .iter()
            .copied()
            .filter(|t| !prune.contains(t))
            .collect();
        k.sort_unstable_by(|a, b| b.cmp(a));
        k.dedup();
        k
    }

    #[test]
    fn retention_keeps_recent_daily_and_monthly_backups() {
        // Giữa ngày UTC, và là ngày cuối của một kỳ 30 ngày ⇒ ranh giới ngày/kỳ rõ ràng.
        let day0 = 30 * 700 + 29;
        let now: i64 = day0 * DAY_MS + DAY_MS / 2;
        let min = 60_000;
        // 40 lần lưu lặt vặt trong 40 phút gần đây + mỗi ngày một bản trong 100 ngày trước đó.
        let mut stamps: Vec<i64> = (0..40).map(|i| now - i * min).collect();
        stamps.extend((1..=100).map(|d| now - d * DAY_MS));
        let kept = kept(&stamps);
        // 10 bản gần nhất còn nguyên.
        assert!((0..10).all(|i| kept.contains(&(now - i * min))));
        // Mỗi ngày trong 29 ngày trước đó đều còn một bản (lỗi 0.1.2: chỉ còn đúng 10 bản mới nhất).
        assert!((1..30).all(|d| kept.contains(&(now - d * DAY_MS))));
        // Xa hơn: bản mới nhất của mỗi kỳ 30 ngày (12 kỳ có bản: kỳ hiện tại + 3 kỳ trước đó).
        let older: Vec<i64> = kept
            .iter()
            .copied()
            .filter(|&t| t < now - 29 * DAY_MS)
            .collect();
        assert_eq!(
            older,
            [30, 60, 90].map(|d| now - d * DAY_MS),
            "bản mới nhất của mỗi kỳ cũ hơn"
        );
        assert_eq!(kept.len(), 10 + 29 + 3);
        // Chạy lại trên kết quả: không xoá thêm gì (ổn định).
        assert!(backups_to_prune(&kept).is_empty());
    }

    /// Rà soát "prune-clock": 180 bản sao lưu thật trong 60 ngày. Trước đây máy dọn có đồng hồ lùi
    /// 25 năm chỉ giữ 10 bản, đồng hồ nhanh 90 ngày giữ 12. Giờ không còn đồng hồ: luôn giữ đúng
    /// một tập, tính được trước.
    #[test]
    fn retention_does_not_depend_on_the_pruning_devices_clock() {
        let day0 = 30 * 600 + 29;
        let real_now: i64 = day0 * DAY_MS + DAY_MS / 2;
        let at = |d: i64, k: i64| real_now - d * DAY_MS - k * 60_000;
        let mut stamps: Vec<i64> = Vec::new();
        for d in 0..60 {
            for k in 0..3 {
                stamps.push(at(d, k));
            }
        }
        let mut expected: Vec<i64> = Vec::new();
        expected.extend(
            [
                (0, 0),
                (0, 1),
                (0, 2),
                (1, 0),
                (1, 1),
                (1, 2),
                (2, 0),
                (2, 1),
                (2, 2),
            ]
            .map(|(d, k)| at(d, k)),
        );
        expected.extend((3..30).map(|d| at(d, 0))); // bản mới nhất của 30 ngày gần nhất
        expected.push(at(30, 0)); // kỳ 30 ngày trước đó
        expected.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(kept(&stamps), expected);
        assert_eq!(expected.len(), 37);
    }

    #[test]
    fn retention_is_not_fooled_by_future_dated_backups() {
        let day0 = 30 * 700 + 29;
        let now: i64 = day0 * DAY_MS + DAY_MS / 2;
        // 40 ngày lịch sử thật (mỗi ngày một bản), 400 ngày trước đó mỗi kỳ một bản…
        let mut real: Vec<i64> = (0..40).map(|d| now - d * DAY_MS).collect();
        real.extend((2..15).map(|m| now - m * 30 * DAY_MS));
        // …cộng 3 bản do một máy sai đồng hồ ghi "ở tương lai" (năm 2100).
        let future: Vec<i64> = (0..3).map(|i| 4_102_444_800_000 + i * DAY_MS).collect();
        let all: Vec<i64> = future.iter().chain(real.iter()).copied().collect();
        let kept = kept(&all);
        // Chúng chỉ chiếm đúng 3 ngày và 1 kỳ: 27 ngày thật gần nhất và 11 kỳ thật vẫn còn.
        assert!((0..27).all(|d| kept.contains(&(now - d * DAY_MS))));
        let real_periods: Vec<i64> = {
            let mut v: Vec<i64> = real.iter().map(|t| t.div_euclid(DAY_MS) / 30).collect();
            v.dedup();
            v
        };
        for p in real_periods.iter().take(KEEP_MONTHLY - 1) {
            let newest = real
                .iter()
                .find(|t| t.div_euclid(DAY_MS) / 30 == *p)
                .unwrap();
            assert!(kept.contains(newest), "kỳ {p}");
        }
        assert!(kept.len() <= KEEP_RECENT + KEEP_DAILY_DAYS + KEEP_MONTHLY);
    }

    #[test]
    fn rarely_used_vault_keeps_bounded_long_history() {
        // Mỗi tháng (~30,4 ngày) một bản, trong 3 năm.
        let start: i64 = 1_700_000_000_000;
        let stamps: Vec<i64> = (0..36).map(|m| start + m * 2_629_746_000).collect();
        let kept = kept(&stamps);
        // Mỗi bản rơi vào một ngày riêng ⇒ 30 bản mới nhất còn (≈ 2,5 năm); có giới hạn.
        assert_eq!(kept.len(), 30);
        let mut newest: Vec<i64> = stamps.clone();
        newest.reverse();
        assert_eq!(kept, newest[..30]);
    }

    #[test]
    fn same_day_bursts_keep_the_days_last_backup() {
        let day = 20_000i64;
        let mut stamps: Vec<i64> = Vec::new();
        // 3 ngày, mỗi ngày 25 lần lưu (từ 08:00, cách nhau 1 phút), ngày mới nhất trước.
        for d in 0..3 {
            for i in 0..25 {
                stamps.push((day - d) * DAY_MS + 8 * 3_600_000 + i * 60_000);
            }
        }
        let kept = kept(&stamps);
        for d in 0..3 {
            let last = (day - d) * DAY_MS + 8 * 3_600_000 + 24 * 60_000;
            assert!(kept.contains(&last), "ngày {d}");
        }
        // 10 bản mới nhất (đều của ngày mới nhất) + bản cuối của 2 ngày trước.
        assert_eq!(kept.len(), 12);
        // Trùng thời điểm (hai máy lưu cùng mili-giây) không làm lệch kết quả.
        let mut dup = stamps.clone();
        dup.extend_from_slice(&stamps[..5]);
        assert_eq!(super::tests::kept(&dup), kept);
    }

    #[test]
    fn prune_only_deletes_files_confirmed_as_ours() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        fs::write(&p, b"x").unwrap();
        let now: i64 = 1_800_000_000_000;
        for i in 0..15 {
            backup_current(&p, now - i * 1000).unwrap();
        }
        prune_backups(&p, |_| false);
        assert_eq!(list_backups(&p).len(), 15, "file lạ không bị xoá");
        prune_backups(&p, |_| true);
        assert_eq!(list_backups(&p).len(), KEEP_RECENT);
    }

    #[test]
    fn move_flat_dir_never_deletes_what_it_did_not_copy() {
        let d = tempfile::tempdir().unwrap();
        let from = d.path().join("a.backups");
        fs::create_dir_all(&from).unwrap();
        fs::write(from.join("one"), b"1").unwrap();
        // Đích nằm TRONG nguồn (rename thất bại): không được xoá sạch nguồn như bản 0.1.2.
        let to = from.join("sub").join("b.backups");
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::write(from.join("sub").join("precious"), b"keep").unwrap();
        let emptied = move_flat_dir(&from, &to).unwrap();
        assert!(!emptied);
        assert_eq!(fs::read(to.join("one")).unwrap(), b"1");
        assert_eq!(
            fs::read(from.join("sub").join("precious")).unwrap(),
            b"keep"
        );
        // Trường hợp thường: chuyển trọn thư mục.
        let from2 = d.path().join("c.backups");
        fs::create_dir_all(&from2).unwrap();
        fs::write(from2.join("x"), b"x").unwrap();
        let to2 = d.path().join("moved").join("c.backups");
        fs::create_dir_all(to2.parent().unwrap()).unwrap();
        assert!(move_flat_dir(&from2, &to2).unwrap());
        assert!(!from2.exists() && to2.join("x").exists());
    }

    #[test]
    fn is_within_detects_nesting() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("vault.pwv.backups");
        fs::create_dir_all(&dir).unwrap();
        assert!(is_within(&dir.join("x.pwv"), &dir));
        assert!(is_within(&dir.join("a").join("b").join("x.pwv"), &dir));
        assert!(is_within(
            &dir.join("..").join("vault.pwv.backups").join("y"),
            &dir
        ));
        assert!(!is_within(&d.path().join("x.pwv"), &dir));
        assert!(!is_within(
            &d.path().join("vault.pwv.backups2").join("x"),
            &dir
        ));
    }

    #[test]
    fn siblings_and_stale_temps() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        for n in [
            "vault.pwv",
            "vault (1).pwv",
            "vault-Binh-Laptop.PWV",
            "kho khac.pwv",
            ".vault.pwv.0123456789ab.tmp",
            "vault.txt",
        ] {
            fs::write(d.path().join(n), b"x").unwrap();
        }
        fs::create_dir(d.path().join("thu muc.pwv")).unwrap();
        let names: Vec<String> = sibling_candidates(&p)
            .iter()
            .map(|p| file_name_of(p))
            .collect();
        assert_eq!(
            names,
            ["kho khac.pwv", "vault (1).pwv", "vault-Binh-Laptop.PWV"]
        );
        // File tạm còn mới: giữ nguyên (có thể tiến trình khác đang ghi).
        clean_stale_temps(&p);
        assert!(d.path().join(".vault.pwv.0123456789ab.tmp").exists());
    }
}
