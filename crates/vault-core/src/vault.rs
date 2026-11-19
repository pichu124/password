//! API chính: tạo / mở / sửa / lưu kho, có hỗ trợ đồng bộ qua Google Drive.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::crypto::{self, KdfParams};
use crate::error::{Error, Result};
use crate::format::{self, Header};
use crate::fsutil;
use crate::memlock::LockedKey;
use crate::model::{now_ms, Entry, HistoryItem, MergeStats, Tombstone, VaultData, MAX_HISTORY};

#[derive(Debug, Clone, Copy)]
pub struct CreateOptions {
    pub kdf: KdfParams,
    /// Cho phép tham số Argon2 dưới mức tối thiểu. CHỈ dùng cho test.
    pub allow_weak_kdf: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            kdf: KdfParams::DEFAULT,
            allow_weak_kdf: false,
        }
    }
}

/// Kết quả của một lần lưu.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SaveReport {
    /// File trên đĩa đã bị thay đổi bởi thiết bị khác và đã được gộp vào trước khi lưu.
    pub merged_remote: Option<MergeStats>,
    /// Master password đã được đổi ở thiết bị khác (header mới hơn được giữ lại).
    pub adopted_remote_password: bool,
}

/// Kho đang mở khoá. Khi `Vault` bị drop, khoá và dữ liệu được xoá khỏi RAM (zeroize).
pub struct Vault {
    path: PathBuf,
    header: Header,
    /// Khoá giải mã, nằm trong vùng RAM được khoá (không bị ghi xuống pagefile).
    vault_key: LockedKey,
    data: VaultData,
    /// SHA-256 của file trên đĩa ở lần đọc/ghi gần nhất — để phát hiện thay đổi từ máy khác.
    disk_fingerprint: Option<[u8; 32]>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("entries", &self.data.entries.len())
            .finish_non_exhaustive()
    }
}

fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl Vault {
    /// Tạo kho mới và ghi ra `path`. Báo lỗi nếu file đã tồn tại.
    pub fn create(path: impl AsRef<Path>, password: &[u8], opts: CreateOptions) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(Error::AlreadyExists(path.display().to_string()));
        }
        opts.kdf.validate(opts.allow_weak_kdf)?;
        let vault_key = crypto::random_key();
        let now = now_ms();
        let header = Header::new_wrapped(
            uuid::Uuid::new_v4().to_string(),
            password,
            opts.kdf,
            &vault_key,
            now,
        )?;
        let mut v = Vault {
            path,
            header,
            vault_key: LockedKey::new(vault_key),
            data: VaultData {
                modified_at: now,
                ..Default::default()
            },
            disk_fingerprint: None,
        };
        v.write_to_disk(false)?;
        Ok(v)
    }

    /// Mở kho bằng master password.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        let bytes = fs::read(&path)?;
        let raw = format::parse(&bytes)?;
        let vault_key = raw.header.unwrap_key(password)?;
        let data = raw.decrypt_body(&vault_key)?;
        Ok(Vault {
            header: raw.header.clone(),
            path,
            vault_key: LockedKey::new(vault_key),
            data,
            disk_fingerprint: Some(fingerprint(&bytes)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id(&self) -> &str {
        &self.header.vault_id
    }

    /// Khoá giải mã có được khoá trong RAM (không bị ghi xuống pagefile) hay không.
    pub fn memory_locked(&self) -> bool {
        self.vault_key.is_locked()
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf
    }

    /// Kiểm tra lại master password (ví dụ trước khi hiện mật khẩu / xuất dữ liệu).
    pub fn verify_password(&self, password: &[u8]) -> bool {
        self.header
            .unwrap_key(password)
            .map(|k| *k == **self.vault_key)
            .unwrap_or(false)
    }

    // ------------------------------------------------------------------ đọc

    pub fn entries(&self) -> &[Entry] {
        &self.data.entries
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.data.entries.iter().find(|e| e.id == id)
    }

    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self
            .data
            .entries
            .iter()
            .filter(|e| e.matches(query))
            .collect();
        v.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        v
    }

    // ------------------------------------------------------------------ ghi (trong RAM)

    /// Thêm mục mới, trả về id. Gọi [`Vault::save`] để ghi ra đĩa.
    pub fn add(&mut self, mut entry: Entry) -> String {
        let now = now_ms();
        if entry.id.is_empty() || self.get(&entry.id).is_some() {
            entry.id = uuid::Uuid::new_v4().to_string();
        }
        entry.created_at = now;
        entry.updated_at = now;
        let id = entry.id.clone();
        self.data.entries.push(entry);
        self.data.modified_at = now;
        id
    }

    /// Sửa một mục. Nếu mật khẩu thay đổi, mật khẩu cũ được đưa vào lịch sử.
    pub fn update(&mut self, id: &str, edit: impl FnOnce(&mut Entry)) -> Result<()> {
        let now = now_ms();
        let e = self
            .data
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        let before = e.clone();
        edit(e);
        // Không cho đổi các trường quản lý.
        e.id = before.id.clone();
        e.created_at = before.created_at;
        if *e == before {
            return Ok(());
        }
        if e.password != before.password && !before.password.is_empty() {
            e.password_history.insert(
                0,
                HistoryItem {
                    password: before.password.clone(),
                    replaced_at: now,
                },
            );
            e.password_history.truncate(MAX_HISTORY);
        }
        e.updated_at = now.max(before.updated_at + 1);
        self.data.modified_at = now;
        Ok(())
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        let idx = self
            .data
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        let removed = self.data.entries.remove(idx);
        let now = now_ms().max(removed.updated_at + 1);
        self.data.tombstones.retain(|t| t.id != id);
        self.data.tombstones.push(Tombstone {
            id: id.to_string(),
            deleted_at: now,
        });
        self.data.modified_at = now;
        Ok(())
    }

    /// Đổi master password (và có thể tăng tham số Argon2). Dữ liệu không cần mã hoá lại:
    /// chỉ vault_key được gói lại bằng KEK mới. Gọi [`Vault::save`] sau đó.
    pub fn change_password(&mut self, new_password: &[u8], kdf: KdfParams) -> Result<()> {
        kdf.validate(false)?;
        self.change_password_inner(new_password, kdf)
    }

    #[doc(hidden)]
    pub fn change_password_insecure_for_tests(
        &mut self,
        new_password: &[u8],
        kdf: KdfParams,
    ) -> Result<()> {
        self.change_password_inner(new_password, kdf)
    }

    fn change_password_inner(&mut self, new_password: &[u8], kdf: KdfParams) -> Result<()> {
        let changed = now_ms().max(self.header.key_changed_at + 1);
        self.header = Header::new_wrapped(
            self.header.vault_id.clone(),
            new_password,
            kdf,
            &self.vault_key,
            changed,
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------ đồng bộ

    /// Gộp một file khác của **cùng kho** (ví dụ bản xung đột `vault (1).pwv` do
    /// Google Drive tạo) vào kho hiện tại. Không cần mật khẩu vì cùng vault_key.
    pub fn merge_file(&mut self, other: impl AsRef<Path>) -> Result<MergeStats> {
        let bytes = fs::read(other.as_ref())?;
        let (stats, _) = self.merge_bytes(&bytes)?;
        Ok(stats)
    }

    fn merge_bytes(&mut self, bytes: &[u8]) -> Result<(MergeStats, bool)> {
        let raw = format::parse(bytes)?;
        if raw.header.vault_id != self.header.vault_id {
            return Err(Error::DifferentVault);
        }
        let remote = raw.decrypt_body(&self.vault_key)?;
        let stats = self.data.merge_from(&remote);
        let adopt = raw.header.key_changed_at > self.header.key_changed_at;
        if adopt {
            self.header = raw.header.clone();
        }
        Ok((stats, adopt))
    }

    /// Các bản xung đột do Google Drive tạo cạnh file kho.
    pub fn conflict_copies(&self) -> Vec<PathBuf> {
        fsutil::conflict_copies(&self.path)
    }

    /// Gộp mọi bản xung đột của Google Drive vào kho rồi chuyển chúng vào thư mục sao lưu.
    /// Bản không mở được (kho khác, hỏng) được giữ nguyên và báo lỗi trong kết quả.
    /// Gọi [`Vault::save`] sau đó nếu có gì được gộp.
    pub fn merge_conflict_copies(&mut self) -> Vec<(PathBuf, Result<MergeStats>)> {
        let mut out = Vec::new();
        for c in self.conflict_copies() {
            let r = self.merge_file(&c).and_then(|stats| {
                let dir = fsutil::backup_dir(&self.path);
                fs::create_dir_all(&dir)?;
                let name = format!(
                    "merged-{}-{}",
                    now_ms(),
                    c.file_name().unwrap_or_default().to_string_lossy()
                );
                fs::rename(&c, dir.join(name))?;
                Ok(stats)
            });
            out.push((c, r));
        }
        out
    }

    /// File trên đĩa có bị thay đổi (bởi máy khác) kể từ lần đọc/ghi gần nhất không?
    pub fn changed_on_disk(&self) -> Result<bool> {
        match fs::read(&self.path) {
            Ok(b) => Ok(Some(fingerprint(&b)) != self.disk_fingerprint),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Nạp lại thay đổi từ đĩa (nếu có) mà không ghi gì.
    pub fn reload(&mut self) -> Result<Option<MergeStats>> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let fp = fingerprint(&bytes);
        if Some(fp) == self.disk_fingerprint {
            return Ok(None);
        }
        let (stats, _) = self.merge_bytes(&bytes)?;
        self.disk_fingerprint = Some(fp);
        Ok(Some(stats))
    }

    /// Lưu ra đĩa. Nếu file đã bị máy khác sửa (qua Google Drive), tự gộp trước rồi mới ghi,
    /// nên không bao giờ ghi đè mất dữ liệu của máy kia.
    pub fn save(&mut self) -> Result<SaveReport> {
        let mut report = SaveReport::default();
        match fs::read(&self.path) {
            Ok(bytes) => {
                if Some(fingerprint(&bytes)) != self.disk_fingerprint {
                    let (stats, adopted) = self.merge_bytes(&bytes)?;
                    report.merged_remote = Some(stats);
                    report.adopted_remote_password = adopted;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.write_to_disk(true)?;
        Ok(report)
    }

    fn write_to_disk(&mut self, backup: bool) -> Result<()> {
        let bytes = format::serialize(&self.header, &self.data, &self.vault_key)?;
        fsutil::atomic_write(&self.path, &bytes, backup)?;
        self.disk_fingerprint = Some(fingerprint(&bytes));
        Ok(())
    }
}
