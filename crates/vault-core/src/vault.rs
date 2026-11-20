//! API chính: tạo / mở / sửa / lưu kho, đồng bộ qua thư mục Google Drive / Dropbox / OneDrive.
//!
//! # Nguyên tắc an toàn dữ liệu
//!
//! - **Đọc–gộp–ghi**: trước mỗi lần ghi, file trên đĩa được đọc lại và gộp vào bản trong RAM, nên
//!   không bao giờ ghi đè mất thay đổi của máy khác.
//! - **Giao dịch**: [`Vault::transact`] gộp file trên đĩa TRƯỚC khi sửa, và nếu ghi thất bại thì
//!   hoàn tác thay đổi trong RAM — thứ đang hiển thị luôn là thứ đã nằm trên đĩa.
//! - **Không tự ghi đè file lạ**: file trên đĩa hỏng, thuộc kho khác, do bản app mới hơn ghi, hoặc
//!   biến mất ⇒ báo lỗi riêng cho từng trường hợp và chờ người dùng quyết định.
//! - **Đổi master password = đổi luôn khoá kho**: bản sao cũ + mật khẩu cũ không mở được dữ liệu mới.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, Key};
use crate::error::{Error, Result};
use crate::format::{self, Header, RawFile};
use crate::fsutil::{self, BackupFile, BackupKind};
use crate::memlock::LockedKey;
use crate::model::{now_ms, Entry, MergeStats, VaultData};

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

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    /// Cho phép mở kho có tham số Argon2 dưới mức tối thiểu. CHỈ dùng cho test.
    pub allow_weak_kdf: bool,
}

/// Kết quả của việc chuyển kho sang thư mục khác.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveReport {
    /// Thư mục sao lưu đã được chuyển theo.
    pub backups_moved: bool,
    /// File ở vị trí cũ đã được xoá (false nếu không xoá được — kho mới vẫn dùng bình thường).
    pub old_removed: bool,
    /// Số bản xung đột đã gộp trước khi chuyển.
    pub conflicts_merged: usize,
    /// File ở vị trí cũ không đọc được (hỏng / biến mất / của kho khác): chỉ ghi bản đang mở sang
    /// vị trí mới, mọi thứ ở vị trí cũ được giữ nguyên.
    pub rescued: bool,
}

/// Kết quả của một lần lưu.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SaveReport {
    /// File trên đĩa đã bị thay đổi bởi thiết bị khác và đã được gộp vào trước khi lưu.
    pub merged_remote: Option<MergeStats>,
    /// Master password đã được đổi ở thiết bị khác chạy bản app cũ (header mới hơn được giữ lại).
    pub adopted_remote_password: bool,
    /// Không tạo được bản sao lưu trước khi ghi (file kho vẫn được ghi an toàn).
    pub backup_failed: bool,
}

/// Một file cạnh kho được coi là bản xung đột của dịch vụ đồng bộ.
#[derive(Debug)]
pub struct ConflictOutcome {
    pub path: PathBuf,
    pub result: Result<MergeStats>,
    /// Đã chuyển vào thư mục sao lưu (chỉ sau khi kho đã được ghi thành công).
    pub archived: bool,
}

/// Kết quả của một lần đồng bộ.
#[derive(Debug, Default)]
pub struct SyncReport {
    pub merged_remote: Option<MergeStats>,
    pub conflicts: Vec<ConflictOutcome>,
    /// Đã ghi lại file kho (vì bản trong RAM có thứ mà file trên đĩa không có).
    pub wrote: bool,
    pub adopted_remote_password: bool,
    pub backup_failed: bool,
}

/// Kết quả của việc đổi master password.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PasswordChangeReport {
    /// Số bản sao lưu đã được mã hoá lại bằng khoá mới.
    pub backups_reencrypted: usize,
    /// Số bản sao lưu không mã hoá lại được (có thể vẫn mở được bằng mật khẩu cũ).
    pub backups_skipped: usize,
    /// Kết quả của lần ghi (có gộp thay đổi của máy khác không, có tạo được bản sao lưu không).
    pub save: SaveReport,
}

/// Kho đang mở khoá. Khi `Vault` bị drop, khoá và dữ liệu được xoá khỏi RAM (zeroize).
pub struct Vault {
    path: PathBuf,
    header: Header,
    /// Khoá giải mã. Bản sao này nằm trong vùng RAM được khoá (hệ điều hành không ghi nó xuống
    /// pagefile); các dữ liệu đã giải mã khác thì KHÔNG được bảo vệ như vậy.
    vault_key: LockedKey,
    data: VaultData,
    /// SHA-256 của file trên đĩa ở lần đọc/ghi gần nhất — để phát hiện thay đổi từ máy khác.
    disk_fingerprint: Option<[u8; 32]>,
    /// Bản trong RAM có thứ mà file trên đĩa (theo lần đọc gần nhất) chưa có.
    dirty: bool,
    /// SHA-256 của nội dung file kho mà ta biết chắc đã có một bản trong thư mục sao lưu.
    backed_up: Option<[u8; 32]>,
    /// Mở từ dữ liệu thô (ví dụ trên điện thoại): không bao giờ ghi ra đĩa.
    read_only: bool,
    allow_weak_kdf: bool,
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

/// Đọc header (chưa xác thực) của một file — chỉ để biết nó thuộc kho nào.
fn header_of(path: &Path) -> Option<Header> {
    const QUICK: usize = 4096;
    let prefix = fsutil::read_prefix(path, QUICK).ok()?;
    match format::peek_header(&prefix) {
        Ok(h) => Some(h),
        Err(_) if prefix.len() == QUICK => {
            let more = fsutil::read_prefix(path, format::HEADER_PEEK_LEN).ok()?;
            format::peek_header(&more).ok()
        }
        Err(_) => None,
    }
}

struct Unlocked {
    header: Header,
    key: Key,
    data: VaultData,
}

/// Mở một file kho bằng master password.
fn unlock_bytes(bytes: &[u8], password: &[u8], allow_weak_kdf: bool) -> Result<Unlocked> {
    let raw = format::parse(bytes)?;
    let key = raw.header.unwrap_key(password, allow_weak_kdf)?;
    // Mật khẩu đã đúng (gói khoá mở được) mà phần thân không giải mã được ⇒ file hỏng, không phải sai mật khẩu.
    let data = raw.decrypt_body(&key).map_err(|e| match e {
        Error::Decrypt => Error::VaultFileDamaged,
        e => e,
    })?;
    Ok(Unlocked {
        header: raw.header.clone(),
        key,
        data,
    })
}

/// Giải mã phần thân bằng `current`, nếu không được thì thử các khoá cũ. Trả về dữ liệu và việc
/// có dùng đúng khoá hiện tại hay không.
fn decrypt_with_keys(raw: &RawFile, current: &Key, old: &VaultData) -> Result<(VaultData, bool)> {
    match raw.decrypt_body(current) {
        Ok(d) => return Ok((d, true)),
        Err(Error::Decrypt) => {}
        Err(e) => return Err(e),
    }
    for k in &old.old_keys {
        let key: Key = Zeroizing::new(k.key);
        match raw.decrypt_body(&key) {
            Ok(d) => return Ok((d, false)),
            Err(Error::Decrypt) => {}
            Err(e) => return Err(e),
        }
    }
    Err(Error::Decrypt)
}

struct Snapshot {
    header: Header,
    key: Key,
    data: VaultData,
    disk_fingerprint: Option<[u8; 32]>,
    dirty: bool,
}

#[derive(Default)]
struct Refreshed {
    stats: Option<MergeStats>,
    adopted: bool,
}

impl Vault {
    // ------------------------------------------------------------------ tạo / mở

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
        let data = VaultData {
            modified_at: now,
            ..Default::default()
        };
        let bytes = format::serialize(&header, &data, &vault_key)?;
        // create_new: nếu dịch vụ đồng bộ vừa tải về một file trùng tên thì KHÔNG ghi đè nó.
        fsutil::write_new(&path, &bytes)?;
        Ok(Vault {
            path,
            header,
            vault_key: LockedKey::new(vault_key),
            data,
            disk_fingerprint: Some(fingerprint(&bytes)),
            dirty: false,
            backed_up: None,
            read_only: false,
            allow_weak_kdf: opts.allow_weak_kdf,
        })
    }

    /// Mở kho bằng master password.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Vault> {
        Self::open_with(path, password, OpenOptions::default())
    }

    pub fn open_with(path: impl AsRef<Path>, password: &[u8], opts: OpenOptions) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        let bytes = fsutil::read_retry(&path)?;
        let v = match unlock_bytes(&bytes, password, opts.allow_weak_kdf) {
            Ok(u) => Vault {
                path,
                header: u.header,
                vault_key: LockedKey::new(u.key),
                data: u.data,
                disk_fingerprint: Some(fingerprint(&bytes)),
                dirty: false,
                backed_up: None,
                read_only: false,
                allow_weak_kdf: opts.allow_weak_kdf,
            },
            Err(Error::Decrypt) => {
                Self::open_via_newer_copy(&path, &bytes, password, opts).ok_or(Error::Decrypt)?
            }
            Err(e) => return Err(e),
        };
        fsutil::clean_stale_temps(&v.path);
        Ok(v)
    }

    /// Mật khẩu không mở được file chính. Nếu cạnh đó có bản xung đột của CÙNG kho với lần đổi
    /// master password MỚI HƠN (máy kia đổi mật khẩu đúng lúc máy này đang ghi, nên dịch vụ đồng bộ
    /// giữ cả hai file), thử mở bằng bản đó rồi gộp file chính vào. Lần đồng bộ kế tiếp sẽ ghi
    /// kết quả ra file chính và cất bản xung đột đi.
    fn open_via_newer_copy(
        path: &Path,
        main_bytes: &[u8],
        password: &[u8],
        opts: OpenOptions,
    ) -> Option<Vault> {
        let main = format::parse(main_bytes).ok()?;
        let mut candidates: Vec<(i64, PathBuf)> = fsutil::sibling_candidates(path)
            .into_iter()
            .filter_map(|p| {
                let h = header_of(&p)?;
                (h.vault_id == main.header.vault_id
                    && h.key_changed_at > main.header.key_changed_at)
                    .then_some((h.key_changed_at, p))
            })
            .collect();
        candidates.sort_by(|a, b| b.cmp(a));
        // Mỗi lần thử tốn một lượt Argon2 (~1 giây) ⇒ chỉ thử vài bản mới nhất.
        for (_, p) in candidates.into_iter().take(2) {
            let Ok(bytes) = fsutil::read_retry(&p) else {
                continue;
            };
            let Ok(u) = unlock_bytes(&bytes, password, opts.allow_weak_kdf) else {
                continue;
            };
            let Ok((main_data, _)) = decrypt_with_keys(&main, &u.key, &u.data) else {
                continue;
            };
            let mut data = u.data;
            data.merge_from(&main_data);
            return Some(Vault {
                path: path.to_path_buf(),
                header: u.header,
                vault_key: LockedKey::new(u.key),
                data,
                disk_fingerprint: Some(fingerprint(main_bytes)),
                dirty: true,
                backed_up: None,
                read_only: false,
                allow_weak_kdf: opts.allow_weak_kdf,
            });
        }
        None
    }

    /// File kho chính không mở được (hỏng, đồng bộ dở, bị xoá): dựng lại kho từ thư mục sao lưu.
    ///
    /// Lấy bản sao lưu mới nhất mở được bằng `password`, rồi gộp thêm các bản khác (kể cả các bản
    /// xung đột đã cất) để vớt được nhiều dữ liệu nhất. Kết quả mới chỉ nằm trong RAM: gọi
    /// [`Vault::force_write`] để ghi ra — file hỏng (nếu còn) sẽ được cất vào thư mục sao lưu,
    /// không bị xoá. Trả về kho, số file đã dùng và thời điểm của bản mới nhất trong số đó.
    pub fn recover_from_backups(
        path: impl AsRef<Path>,
        password: &[u8],
        opts: OpenOptions,
    ) -> Result<(Vault, usize, i64)> {
        const MAX_PASSWORD_ATTEMPTS: usize = 5; // mỗi lần thử tốn một lượt Argon2
        const MAX_FILES_MERGED: usize = 40;
        let path = path.as_ref().to_path_buf();
        let candidates: Vec<BackupFile> = fsutil::list_backups(&path)
            .into_iter()
            .filter(|b| b.kind != BackupKind::Damaged)
            .collect();
        let mut last_err = Error::VaultFileMissing(path.display().to_string());
        let mut found: Option<(Vault, i64)> = None;
        for b in candidates.iter().take(MAX_PASSWORD_ATTEMPTS) {
            let unlocked = fsutil::read_retry(&b.path)
                .map_err(Error::from)
                .and_then(|bytes| unlock_bytes(&bytes, password, opts.allow_weak_kdf));
            match unlocked {
                Ok(u) => {
                    let v = Vault {
                        path: path.clone(),
                        header: u.header,
                        vault_key: LockedKey::new(u.key),
                        data: u.data,
                        disk_fingerprint: None,
                        dirty: true,
                        backed_up: None,
                        read_only: false,
                        allow_weak_kdf: opts.allow_weak_kdf,
                    };
                    found = Some((v, b.timestamp));
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        let Some((mut v, newest)) = found else {
            return Err(last_err);
        };
        // (Bản vừa mở cũng nằm trong danh sách và được tính ở đây.)
        let used = candidates
            .iter()
            .take(MAX_FILES_MERGED)
            .filter(|b| v.merge_file(&b.path).is_ok())
            .count()
            .max(1);
        Ok((v, used, newest))
    }

    /// Mở kho **chỉ đọc** từ dữ liệu thô (ví dụ file đọc qua Drive/Dropbox trên Android).
    /// `label` chỉ để hiển thị. Các thao tác ghi ra đĩa sẽ trả về `Error::ReadOnly`.
    pub fn open_bytes(label: impl Into<PathBuf>, bytes: &[u8], password: &[u8]) -> Result<Vault> {
        Self::open_bytes_with(label, bytes, password, OpenOptions::default())
    }

    pub fn open_bytes_with(
        label: impl Into<PathBuf>,
        bytes: &[u8],
        password: &[u8],
        opts: OpenOptions,
    ) -> Result<Vault> {
        let u = unlock_bytes(bytes, password, opts.allow_weak_kdf)?;
        Ok(Vault {
            path: label.into(),
            header: u.header,
            vault_key: LockedKey::new(u.key),
            data: u.data,
            disk_fingerprint: Some(fingerprint(bytes)),
            dirty: false,
            backed_up: None,
            read_only: true,
            allow_weak_kdf: opts.allow_weak_kdf,
        })
    }

    /// Nạp phiên bản khác của **cùng kho** vào kho chỉ đọc (điện thoại bấm "tải lại"). Dữ liệu được
    /// GỘP chứ không thay thế, nên nếu dịch vụ đồng bộ trả về một bản cũ hơn thì các thay đổi mới
    /// đã thấy trước đó không bị mất. Trả về true nếu nội dung thay đổi.
    ///
    /// Nếu máy khác đã đổi master password: trả về [`Error::PasswordChangedElsewhere`] — phải mở
    /// khoá lại bằng mật khẩu mới.
    pub fn replace_from_bytes(&mut self, bytes: &[u8]) -> Result<bool> {
        let fp = fingerprint(bytes);
        if Some(fp) == self.disk_fingerprint {
            return Ok(false);
        }
        let (remote, adopt) = self.decrypt_same_vault(bytes)?;
        let before = self.data.clone();
        self.data.merge_from(&remote);
        if let Some(h) = adopt {
            self.header = h;
        }
        self.disk_fingerprint = Some(fp);
        Ok(self.data != before)
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id(&self) -> &str {
        &self.header.vault_id
    }

    /// Lần sửa nội dung gần nhất (ms) — chỉ tăng, kể cả sau khi gộp.
    pub fn modified_at(&self) -> i64 {
        self.data.modified_at
    }

    /// Lần đổi master password gần nhất (ms).
    pub fn key_changed_at(&self) -> i64 {
        self.header.key_changed_at
    }

    /// Bản sao khoá giải mã có được khoá trong RAM (không bị ghi xuống pagefile) hay không.
    pub fn memory_locked(&self) -> bool {
        self.vault_key.is_locked()
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf
    }

    /// Bản trong RAM có thay đổi chưa nằm trên đĩa (ví dụ lần ghi gần nhất thất bại).
    pub fn has_unsaved_changes(&self) -> bool {
        self.dirty
    }

    /// Kiểm tra lại master password (ví dụ trước khi đổi mật khẩu).
    pub fn verify_password(&self, password: &[u8]) -> bool {
        self.header
            .unwrap_key(password, self.allow_weak_kdf)
            .map(|k| *k == **self.vault_key)
            .unwrap_or(false)
    }

    // ------------------------------------------------------------------ đọc

    /// Các mục đang dùng (không gồm thùng rác).
    pub fn entries(&self) -> &[Entry] {
        &self.data.entries
    }

    /// Các mục trong thùng rác.
    pub fn trash(&self) -> &[Entry] {
        &self.data.trash
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.data.get(id)
    }

    pub fn get_trashed(&self, id: &str) -> Option<&Entry> {
        self.data.get_trashed(id)
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

    // ------------------------------------------------------------------ sửa (trong RAM)
    //
    // Các hàm dưới đây chỉ sửa trong RAM. App giao diện gọi chúng BÊN TRONG `transact` để được
    // gộp-trước-khi-sửa và hoàn tác khi ghi lỗi; CLI có thể gọi rồi `save()`.

    /// Thêm mục mới, trả về id.
    pub fn add(&mut self, entry: Entry) -> String {
        self.dirty = true;
        self.data.add_at(entry, now_ms())
    }

    /// Sửa một mục. Chỉ các trường thực sự thay đổi mới được ghi nhận; nếu mật khẩu thay đổi,
    /// mật khẩu cũ được đưa vào lịch sử.
    pub fn update(&mut self, id: &str, edit: impl FnOnce(&mut Entry)) -> Result<()> {
        if self.data.update_at(id, now_ms(), edit)? {
            self.dirty = true;
        }
        Ok(())
    }

    /// Xoá một mục = chuyển vào thùng rác (khôi phục được bằng [`Vault::restore`]).
    pub fn delete(&mut self, id: &str) -> Result<()> {
        self.data.trash_at(id, now_ms())?;
        self.dirty = true;
        Ok(())
    }

    /// Lấy một mục ra khỏi thùng rác.
    pub fn restore(&mut self, id: &str) -> Result<()> {
        self.data.restore_at(id, now_ms())?;
        self.dirty = true;
        Ok(())
    }

    /// Xoá vĩnh viễn một mục trên mọi thiết bị (không khôi phục được, trừ từ bản sao lưu).
    pub fn purge(&mut self, id: &str) -> Result<()> {
        self.data.purge_at(id, now_ms())?;
        self.dirty = true;
        Ok(())
    }

    /// Xoá vĩnh viễn mọi mục trong thùng rác. Trả về số mục đã xoá.
    pub fn empty_trash(&mut self) -> usize {
        let ids: Vec<String> = self.data.trash.iter().map(|e| e.id.clone()).collect();
        let now = now_ms();
        for id in &ids {
            let _ = self.data.purge_at(id, now);
        }
        if !ids.is_empty() {
            self.dirty = true;
        }
        ids.len()
    }

    /// Đưa phiên bản `old` của một mục (lấy từ bản sao lưu) trở lại làm phiên bản hiện hành.
    /// Trả về true nếu có thay đổi.
    pub fn reinstate(&mut self, old: &Entry) -> bool {
        let changed = self.data.reinstate_at(old, now_ms());
        self.dirty |= changed;
        changed
    }

    // ------------------------------------------------------------------ đọc file trên đĩa

    /// Giải mã một file của CÙNG kho bằng khoá đang có (khoá hiện tại hoặc khoá cũ).
    /// Trả về dữ liệu (dạng chuẩn) và header cần nhận về, nếu có.
    fn decrypt_same_vault(&self, bytes: &[u8]) -> Result<(VaultData, Option<Header>)> {
        let raw = format::parse(bytes).map_err(|e| match e {
            Error::BadFormat => Error::VaultFileDamaged,
            e => e,
        })?;
        if raw.header.vault_id != self.header.vault_id {
            return Err(Error::DifferentVault);
        }
        let newer_epoch = raw.header.key_changed_at > self.header.key_changed_at;
        match decrypt_with_keys(&raw, &self.vault_key, &self.data) {
            // Cùng khoá nhưng header mới hơn: bản app cũ (≤ 0.1.2) ở máy khác đã đổi master password
            // mà không đổi khoá kho ⇒ nhận header đó để hai máy dùng chung một mật khẩu.
            Ok((data, true)) => Ok((data, newer_epoch.then(|| raw.header.clone()))),
            // File được ghi bằng khoá cũ (máy kia chưa biết lần đổi mật khẩu): chỉ lấy dữ liệu.
            Ok((data, false)) => Ok((data, None)),
            Err(Error::Decrypt) if newer_epoch => Err(Error::PasswordChangedElsewhere),
            Err(Error::Decrypt) | Err(Error::BadFormat) | Err(Error::Json) => {
                Err(Error::VaultFileDamaged)
            }
            Err(e) => Err(e),
        }
    }

    /// Đọc file kho trên đĩa. `None` = không đổi so với lần đọc/ghi gần nhất.
    fn read_changed_file(&self) -> Result<Option<(Vec<u8>, [u8; 32])>> {
        // Dịch vụ đồng bộ có thể gỡ file trong tích tắc khi thay bằng bản mới ⇒ thử lại vài lần
        // trước khi kết luận file đã biến mất.
        let mut attempts = 0;
        let bytes = loop {
            match fsutil::read_retry(&self.path) {
                Ok(b) => break b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    attempts += 1;
                    if attempts >= 3 {
                        return Err(Error::VaultFileMissing(self.path.display().to_string()));
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
                Err(e) => return Err(e.into()),
            }
        };
        let fp = fingerprint(&bytes);
        Ok((Some(fp) != self.disk_fingerprint).then_some((bytes, fp)))
    }

    /// Gộp file trên đĩa (nếu đã bị máy khác thay đổi) vào bản trong RAM. Không ghi gì.
    fn refresh(&mut self) -> Result<Refreshed> {
        let Some((bytes, fp)) = self.read_changed_file()? else {
            return Ok(Refreshed::default());
        };
        let (remote, adopt) = self.decrypt_same_vault(&bytes)?;
        let disk_header = format::peek_header(&bytes)?;
        let stats = self.data.merge_from(&remote);
        let adopted = adopt.is_some();
        if let Some(h) = adopt {
            self.header = h;
        }
        self.disk_fingerprint = Some(fp);
        // Phải ghi lại nếu RAM có thứ file không có, hoặc file đang dùng khoá/mật khẩu cũ.
        self.dirty = self.data != remote || disk_header != self.header;
        Ok(Refreshed {
            stats: Some(stats),
            adopted,
        })
    }

    /// Nạp thay đổi từ đĩa (nếu có) mà không ghi gì. Dùng [`Vault::sync`] để vừa nạp vừa ghi lại.
    pub fn reload(&mut self) -> Result<Option<MergeStats>> {
        if self.read_only {
            return Ok(None);
        }
        Ok(self.refresh()?.stats)
    }

    /// File trên đĩa có bị thay đổi (bởi máy khác) kể từ lần đọc/ghi gần nhất không?
    pub fn changed_on_disk(&self) -> Result<bool> {
        if self.read_only {
            return Ok(false);
        }
        Ok(self.read_changed_file()?.is_some())
    }

    // ------------------------------------------------------------------ ghi

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            header: self.header.clone(),
            key: Zeroizing::new(**self.vault_key),
            data: self.data.clone(),
            disk_fingerprint: self.disk_fingerprint,
            dirty: self.dirty,
        }
    }

    fn rollback(&mut self, s: Snapshot) {
        if *s.key != **self.vault_key {
            self.vault_key = LockedKey::new(s.key);
        }
        self.header = s.header;
        self.data = s.data;
        self.disk_fingerprint = s.disk_fingerprint;
        self.dirty = s.dirty;
    }

    /// Ghi bản trong RAM ra đĩa (nguyên tử, có đọc lại kiểm tra) và giữ sao lưu:
    ///
    /// - TRƯỚC khi ghi (`keep_previous`): nếu nội dung đang nằm trên đĩa chưa chắc đã có trong thư
    ///   mục sao lưu (do máy khác / bản app cũ ghi, hoặc là lần ghi đầu của phiên) thì chép nó lại.
    /// - SAU khi ghi: chép luôn bản vừa ghi. Nhờ vậy bản sao lưu mới nhất luôn giống hệt file kho,
    ///   và nếu file kho hỏng thì khôi phục không mất lần sửa cuối cùng.
    ///
    /// Trả về true nếu có bản sao lưu KHÔNG tạo được (file kho vẫn được ghi an toàn).
    fn write_to_disk(&mut self, keep_previous: bool) -> Result<bool> {
        let bytes = format::serialize(&self.header, &self.data, &self.vault_key)?;
        let fp = fingerprint(&bytes);
        let mut backup_failed = false;
        if keep_previous
            && self.disk_fingerprint.is_some()
            && self.disk_fingerprint != self.backed_up
        {
            match fsutil::backup_current(&self.path, now_ms()) {
                Ok(_) => self.backed_up = self.disk_fingerprint,
                Err(_) => backup_failed = true,
            }
        }
        fsutil::atomic_write_verified(&self.path, &bytes)?;
        self.disk_fingerprint = Some(fp);
        self.dirty = false;
        match fsutil::backup_bytes(&self.path, now_ms(), &bytes) {
            Ok(_) => self.backed_up = Some(fp),
            Err(_) => backup_failed = true,
        }
        Ok(backup_failed)
    }

    fn prune_backups(&self) {
        fsutil::prune_backups(&self.path, now_ms(), |p| self.is_same_vault_file(p));
    }

    /// Thực hiện một thay đổi theo kiểu giao dịch:
    ///
    /// 1. Gộp file trên đĩa vào RAM (lỗi ⇒ dừng, chưa sửa gì).
    /// 2. Chạy `f` (sửa trong RAM).
    /// 3. Ghi ra đĩa. Nếu `f` hoặc việc ghi thất bại ⇒ HOÀN TÁC về trạng thái sau bước 1.
    pub fn transact<T>(
        &mut self,
        f: impl FnOnce(&mut Vault) -> Result<T>,
    ) -> Result<(T, SaveReport)> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let refreshed = self.refresh()?;
        let snap = self.snapshot();
        let result = f(self).and_then(|t| {
            let backup_failed = if self.dirty {
                self.write_to_disk(true)?
            } else {
                false
            };
            Ok((t, backup_failed))
        });
        match result {
            Ok((t, backup_failed)) => {
                self.prune_backups();
                Ok((
                    t,
                    SaveReport {
                        merged_remote: refreshed.stats,
                        adopted_remote_password: refreshed.adopted,
                        backup_failed,
                    },
                ))
            }
            Err(e) => {
                self.rollback(snap);
                Err(e)
            }
        }
    }

    /// Lưu ra đĩa những thay đổi đang có trong RAM (gộp file trên đĩa trước).
    pub fn save(&mut self) -> Result<SaveReport> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let refreshed = self.refresh()?;
        let backup_failed = if self.dirty {
            self.write_to_disk(true)?
        } else {
            false
        };
        self.prune_backups();
        Ok(SaveReport {
            merged_remote: refreshed.stats,
            adopted_remote_password: refreshed.adopted,
            backup_failed,
        })
    }

    /// Ghi bản đang mở ra đĩa khi file kho trên đĩa đang HỎNG hoặc đã BIẾN MẤT.
    /// Chỉ gọi khi người dùng đã xác nhận. File hỏng được cất vào thư mục sao lưu
    /// (`damaged-…`) chứ không bị xoá; trả về đường dẫn của nó.
    ///
    /// Không bao giờ ghi đè file của kho khác, file do bản app mới hơn ghi, hay file đã đổi mật khẩu.
    pub fn force_write(&mut self) -> Result<Option<PathBuf>> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        match self.refresh() {
            // Hoá ra file đọc được (đồng bộ vừa xong): lưu như bình thường.
            Ok(_) => {
                if self.dirty {
                    self.write_to_disk(true)?;
                }
                Ok(None)
            }
            Err(Error::VaultFileMissing(_)) => {
                let bytes = format::serialize(&self.header, &self.data, &self.vault_key)?;
                fsutil::write_new(&self.path, &bytes)?;
                self.disk_fingerprint = Some(fingerprint(&bytes));
                self.dirty = false;
                Ok(None)
            }
            Err(Error::VaultFileDamaged) => {
                let archived =
                    fsutil::archive_file(&self.path, BackupKind::Damaged, now_ms(), &self.path)?;
                self.write_to_disk(false)?;
                Ok(Some(archived))
            }
            Err(e) => Err(e),
        }
    }

    /// Toàn bộ kho (đã mã hoá) dưới dạng bytes — để ghi một bản cứu hộ ở nơi khác.
    pub fn export_bytes(&self) -> Result<Vec<u8>> {
        format::serialize(&self.header, &self.data, &self.vault_key)
    }

    // ------------------------------------------------------------------ master password

    /// Đổi master password (và có thể tăng tham số Argon2), rồi ghi ra đĩa.
    ///
    /// Một **khoá kho mới** được sinh ra và toàn bộ dữ liệu được mã hoá lại, nên người biết mật
    /// khẩu cũ và giữ một bản sao cũ của file không đọc được dữ liệu từ nay về sau. Khoá cũ được
    /// giữ bên trong phần đã mã hoá để vẫn gộp được các bản xung đột cũ. Các file trong thư mục
    /// sao lưu được mã hoá lại bằng khoá mới.
    ///
    /// Lưu ý: bản cũ trong lịch sử phiên bản của Drive/Dropbox và trên các thiết bị chưa đồng bộ
    /// vẫn mở được bằng mật khẩu cũ — phần mềm không thể với tới chúng.
    pub fn change_password(
        &mut self,
        new_password: &[u8],
        kdf: KdfParams,
    ) -> Result<PasswordChangeReport> {
        kdf.validate(self.allow_weak_kdf)?;
        let ((), save) = self.transact(|v| {
            let new_key = crypto::random_key();
            let changed = now_ms().max(v.header.key_changed_at + 1);
            let header = Header::new_wrapped(
                v.header.vault_id.clone(),
                new_password,
                kdf,
                &new_key,
                changed,
            )?;
            let old: Key = Zeroizing::new(**v.vault_key);
            v.data.push_old_key(&old, changed);
            v.header = header;
            v.vault_key = LockedKey::new(new_key);
            v.dirty = true;
            Ok(())
        })?;
        let mut report = self.reencrypt_backups();
        report.save = save;
        Ok(report)
    }

    /// Mã hoá lại các file trong thư mục sao lưu bằng khoá + mật khẩu hiện tại.
    fn reencrypt_backups(&self) -> PasswordChangeReport {
        let mut report = PasswordChangeReport::default();
        for b in fsutil::list_backups(&self.path) {
            // File hỏng đã cất (`damaged-…`) vốn không giải mã được bằng bất kỳ mật khẩu nào: bỏ qua,
            // không tính vào số "chưa mã hoá lại được".
            let unreadable = usize::from(b.kind != BackupKind::Damaged);
            let Ok(bytes) = fsutil::read_retry(&b.path) else {
                report.backups_skipped += unreadable;
                continue;
            };
            let Ok(raw) = format::parse(&bytes) else {
                report.backups_skipped += unreadable;
                continue;
            };
            if raw.header.vault_id != self.header.vault_id || raw.header == self.header {
                continue; // file của kho khác, hoặc đã dùng khoá hiện tại
            }
            let done = decrypt_with_keys(&raw, &self.vault_key, &self.data)
                .and_then(|(data, _)| format::serialize(&self.header, &data, &self.vault_key))
                .and_then(|out| fsutil::atomic_write(&b.path, &out));
            match done {
                Ok(()) => report.backups_reencrypted += 1,
                Err(_) => report.backups_skipped += unreadable,
            }
        }
        report
    }

    // ------------------------------------------------------------------ đồng bộ

    fn is_same_vault_file(&self, p: &Path) -> bool {
        header_of(p).is_some_and(|h| h.vault_id == self.header.vault_id)
    }

    /// Các bản xung đột do Google Drive / Dropbox / OneDrive tạo cạnh file kho: mọi file khác
    /// trong cùng thư mục có cùng `vault_id` (không đoán theo tên file).
    pub fn conflict_copies(&self) -> Vec<PathBuf> {
        if self.read_only {
            return Vec::new();
        }
        fsutil::sibling_candidates(&self.path)
            .into_iter()
            .filter(|p| self.is_same_vault_file(p))
            .collect()
    }

    /// Gộp một file khác của **cùng kho** vào kho hiện tại (chỉ trong RAM).
    pub fn merge_file(&mut self, other: impl AsRef<Path>) -> Result<MergeStats> {
        let bytes = fsutil::read_retry(other.as_ref())?;
        self.merge_copy(&bytes).map(|(stats, _)| stats)
    }

    fn merge_copy(&mut self, bytes: &[u8]) -> Result<(MergeStats, bool)> {
        let (remote, adopt) = self.decrypt_same_vault(bytes)?;
        let before = self.data.clone();
        let stats = self.data.merge_from(&remote);
        let adopted = adopt.is_some();
        if let Some(h) = adopt {
            self.header = h;
        }
        if adopted || self.data != before {
            self.dirty = true;
        }
        Ok((stats, adopted))
    }

    /// Đồng bộ với thư mục: nạp thay đổi của máy khác, gộp các bản xung đột, **ghi lại file kho nếu
    /// bản trong RAM có thứ mà file trên đĩa không có**, rồi mới cất các bản xung đột đã gộp vào
    /// thư mục sao lưu (không bao giờ cất trước khi kho đã được ghi thành công).
    pub fn sync(&mut self) -> Result<SyncReport> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let refreshed = self.refresh()?;
        let mut report = SyncReport {
            merged_remote: refreshed.stats,
            adopted_remote_password: refreshed.adopted,
            ..Default::default()
        };
        for path in self.conflict_copies() {
            let result = fsutil::read_retry(&path)
                .map_err(Error::from)
                .and_then(|bytes| self.merge_copy(&bytes));
            match result {
                Ok((stats, adopted)) => {
                    report.adopted_remote_password |= adopted;
                    report.conflicts.push(ConflictOutcome {
                        path,
                        result: Ok(stats),
                        archived: false,
                    });
                }
                // Bản xung đột dùng mật khẩu mới hơn: không thể gộp khi chưa nhập mật khẩu đó.
                Err(Error::PasswordChangedElsewhere) => {
                    return Err(Error::PasswordChangedElsewhere)
                }
                Err(e) => report.conflicts.push(ConflictOutcome {
                    path,
                    result: Err(e),
                    archived: false,
                }),
            }
        }
        if self.dirty {
            report.backup_failed = self.write_to_disk(true)?;
            report.wrote = true;
        }
        let now = now_ms();
        for c in report.conflicts.iter_mut().filter(|c| c.result.is_ok()) {
            c.archived = fsutil::archive_file(&self.path, BackupKind::Merged, now, &c.path).is_ok();
        }
        if report.wrote || report.conflicts.iter().any(|c| c.archived) {
            self.prune_backups();
        }
        Ok(report)
    }

    // ------------------------------------------------------------------ sao lưu

    /// Các file trong thư mục sao lưu thuộc về kho này, mới nhất trước.
    pub fn backups(&self) -> Vec<BackupFile> {
        fsutil::list_backups(&self.path)
            .into_iter()
            .filter(|b| self.is_same_vault_file(&b.path))
            .collect()
    }

    /// Đọc nội dung một bản sao lưu (phải nằm trong thư mục sao lưu của kho này).
    pub fn read_backup(&self, path: &Path) -> Result<VaultData> {
        if !fsutil::is_within(path, &fsutil::backup_dir(&self.path)) {
            return Err(Error::BadFormat);
        }
        let bytes = fsutil::read_retry(path)?;
        let raw = format::parse(&bytes)?;
        if raw.header.vault_id != self.header.vault_id {
            return Err(Error::DifferentVault);
        }
        decrypt_with_keys(&raw, &self.vault_key, &self.data).map(|(d, _)| d)
    }

    // ------------------------------------------------------------------ chuyển kho

    fn file_matches_memory(&self, path: &Path) -> bool {
        fsutil::read_retry(path).ok().is_some_and(|b| {
            format::parse(&b)
                .and_then(|raw| raw.decrypt_body(&self.vault_key))
                .is_ok_and(|d| d == self.data)
        })
    }

    /// Chuyển kho sang vị trí mới (ví dụ từ Documents sang thư mục Dropbox).
    ///
    /// Trình tự an toàn: gộp bản xung đột + lưu ở chỗ cũ → ghi bản sao ở chỗ mới →
    /// **đọc lại và giải mã thử** bản mới → chỉ khi đúng mới chuyển thư mục sao lưu và xoá file cũ.
    /// Lỗi ở bất kỳ bước nào trước khi xác minh xong thì kho cũ giữ nguyên.
    ///
    /// Nếu file ở chỗ cũ không còn đọc được (hỏng, biến mất, bị thay bằng kho khác) thì đây là
    /// cách "lưu bản đang mở ra chỗ khác": chỉ ghi bản mới, không đụng tới bất cứ thứ gì ở chỗ cũ.
    pub fn move_to(&mut self, new_path: impl AsRef<Path>) -> Result<MoveReport> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let new_path = std::path::absolute(new_path.as_ref())?;
        let old_path = std::path::absolute(&self.path)?;
        if new_path == old_path {
            return Err(Error::SamePath);
        }
        if new_path.exists() {
            return Err(Error::AlreadyExists(new_path.display().to_string()));
        }
        let old_backups = fsutil::backup_dir(&old_path);
        let new_backups = fsutil::backup_dir(&new_path);
        // Đích nằm trong thư mục sao lưu của chính kho (hoặc ngược lại) ⇒ bước chuyển thư mục sao
        // lưu sẽ tự nuốt chính nó. Bản 0.1.2 đã xoá sạch cả kho lẫn sao lưu trong trường hợp này.
        if fsutil::is_within(&new_path, &old_backups) || fsutil::is_within(&old_path, &new_backups)
        {
            return Err(Error::MoveIntoBackups);
        }
        if let Some(dir) = new_path.parent() {
            fs::create_dir_all(dir)?;
        }

        // 1. Đưa chỗ cũ về trạng thái mới nhất.
        let mut report = MoveReport::default();
        match self.sync() {
            Ok(s) => {
                report.conflicts_merged = s.conflicts.iter().filter(|c| c.result.is_ok()).count();
            }
            // Máy khác đã đổi mật khẩu: bản trong RAM đã cũ, không được nhân nó ra chỗ khác.
            Err(e @ Error::PasswordChangedElsewhere) => return Err(e),
            Err(_) => report.rescued = true,
        }

        // 2. Ghi ở chỗ mới rồi xác minh.
        let bytes = format::serialize(&self.header, &self.data, &self.vault_key)?;
        fsutil::write_new(&new_path, &bytes)?;
        if !self.file_matches_memory(&new_path) {
            let _ = fs::remove_file(&new_path);
            return Err(Error::MoveVerifyFailed);
        }

        // 3. Từ đây kho mới đã dùng được; các bước còn lại là dọn dẹp, lỗi không làm hỏng gì.
        self.path = new_path.clone();
        self.disk_fingerprint = Some(fingerprint(&bytes));
        self.dirty = false;
        if report.rescued {
            return Ok(report);
        }
        if old_backups.is_dir() {
            report.backups_moved = fsutil::move_flat_dir(&old_backups, &new_backups).is_ok();
        }
        // Kiểm tra bản mới thêm một lần nữa ngay trước khi xoá bản cũ.
        if self.file_matches_memory(&new_path) {
            report.old_removed = fsutil::retry(|| fs::remove_file(&old_path)).is_ok();
        }
        Ok(report)
    }
}
