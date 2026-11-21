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
//! - **Đổi master password = đổi luôn khoá kho**: bản sao cũ + mật khẩu cũ không mở được dữ liệu
//!   ghi SAU lần đổi (trong file kho và thư mục sao lưu do app này quản lý).
//! - **Khoá cũ chỉ còn quyền đọc**: một file trong thư mục đồng bộ chỉ mở được bằng khoá của mật
//!   khẩu chính cũ (ai biết mật khẩu cũ và giữ bản sao cũ cũng làm ra được file như vậy) KHÔNG BAO
//!   GIỜ được tự gộp vào kho. Nó được mã hoá lại bằng khoá hiện tại và cất vào thư mục sao lưu
//!   (`oldkey-…`) để chủ kho tự xem lại.

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
    /// File kho trên đĩa chỉ mở được bằng khoá của mật khẩu chính CŨ (máy chưa biết lần đổi mật
    /// khẩu đã ghi đè nó, hoặc ai đó biết mật khẩu cũ đã thay nó). Nó KHÔNG được gộp mà được cất vào
    /// thư mục sao lưu (`oldkey-…`, đã mã hoá lại bằng khoá hiện tại), rồi file kho được ghi lại.
    pub old_key_archived: bool,
    /// Đã ghi file kho nhưng đọc lại không xác minh được là đúng những byte đó (ví dụ phần mềm
    /// diệt virus / dịch vụ đồng bộ giữ file lúc đọc lại). Thay đổi KHÔNG bị hoàn tác: bản trong RAM
    /// được giữ, lần đồng bộ sau đọc lại file và ghi lại nếu cần.
    pub unverified: bool,
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
    /// Số bản (file kho chính + bản xung đột) chỉ mở được bằng khoá CŨ đã được cất vào thư mục sao
    /// lưu (`oldkey-…`) thay vì gộp.
    pub old_key_archived: usize,
    /// Đã ghi file kho nhưng đọc lại không xác minh được (xem [`SaveReport::unverified`]).
    pub unverified: bool,
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
    /// File kho chính đã đọc được mà chỉ mở được bằng khoá cũ: KHÔNG được gộp, phải được cất (đã mã
    /// hoá lại) vào thư mục sao lưu TRƯỚC khi file kho bị ghi đè — có thể đó là bản duy nhất chứa
    /// các thay đổi của một máy chưa biết lần đổi mật khẩu.
    pending_old_keys: Vec<PendingOldKey>,
    /// SHA-256 của các bản trong `pending_old_keys` đã được cất xong. Không nằm trong `Snapshot`:
    /// hoàn tác một giao dịch không được làm bản cất bị ghi thêm lần nữa.
    archived_old_keys: Vec<[u8; 32]>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("entries", &self.data.entries.len())
            .finish_non_exhaustive()
    }
}

// Chỗ nối cho test: chạy một đoạn mã đúng vào khoảnh khắc giữa hai bước (ví dụ "máy khác ghi file
// đúng lúc này"). Ngoài test thì không làm gì.
#[cfg(test)]
type TestHook = Option<(&'static str, Box<dyn FnMut()>)>;

#[cfg(test)]
thread_local! {
    static TEST_HOOK: std::cell::RefCell<TestHook> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_hook(point: &str) {
    TEST_HOOK.with(|h| {
        if let Some((p, f)) = h.borrow_mut().as_mut() {
            if *p == point {
                f();
            }
        }
    });
}

#[cfg(not(test))]
#[inline(always)]
fn test_hook(_: &str) {}

// Test: các lần "đọc lại sau khi ghi" kế tiếp trả về những kết quả này thay vì đọc đĩa thật.
#[cfg(test)]
thread_local! {
    static READBACK_FAULTS: std::cell::RefCell<std::collections::VecDeque<std::io::Result<Vec<u8>>>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
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

/// Khoá đã giải mã được một file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyUsed {
    /// Khoá kho hiện tại.
    Current,
    /// Một khoá cũ trong `old_keys` (khoá của một mật khẩu chính đã đổi).
    Retired,
}

/// Giải mã phần thân bằng `current`, nếu không được thì thử các khoá cũ. Trả về dữ liệu và khoá
/// nào đã mở được nó.
fn decrypt_with_keys(
    raw: &RawFile,
    current: &Key,
    old: &VaultData,
) -> Result<(VaultData, KeyUsed)> {
    match raw.decrypt_body(current) {
        Ok(d) => return Ok((d, KeyUsed::Current)),
        Err(Error::Decrypt) => {}
        Err(e) => return Err(e),
    }
    for k in &old.old_keys {
        let key: Key = Zeroizing::new(k.key);
        match raw.decrypt_body(&key) {
            Ok(d) => return Ok((d, KeyUsed::Retired)),
            Err(Error::Decrypt) => {}
            Err(e) => return Err(e),
        }
    }
    Err(Error::Decrypt)
}

/// Kết quả giải mã một file của CÙNG kho bằng các khoá đang có.
enum Decrypted {
    /// Mở được bằng khoá hiện tại: chỉ người có khoá hiện tại mới ghi ra được file này ⇒ được gộp.
    /// `adopt_header`: header mới hơn cần nhận về (bản app ≤ 0.1.2 đổi mật khẩu mà không đổi khoá).
    Current {
        data: VaultData,
        adopt_header: Option<Header>,
    },
    /// Chỉ mở được bằng một khoá cũ. Một máy chưa biết lần đổi mật khẩu ghi ra được file như vậy,
    /// nhưng ai biết mật khẩu CŨ và giữ một bản sao cũ cũng làm được ⇒ KHÔNG BAO GIỜ tự gộp.
    Retired { data: VaultData },
}

/// Tham số Argon2 của `a` không tốn kém hơn `b` ở bất kỳ chiều nào (bộ nhớ, số vòng, số luồng).
/// Dùng để chặn file cài cắm bắt máy chạy Argon2 nặng mỗi lần mở khoá.
fn kdf_not_costlier(a: &KdfParams, b: &KdfParams) -> bool {
    a.m_kib <= b.m_kib && a.t <= b.t && a.p <= b.p
}

fn kdf_max(a: &KdfParams, b: &KdfParams) -> KdfParams {
    KdfParams {
        m_kib: a.m_kib.max(b.m_kib),
        t: a.t.max(b.t),
        p: a.p.max(b.p),
    }
}

/// Bản chỉ mở được bằng khoá cũ, đang chờ được cất (đã mã hoá lại) vào thư mục sao lưu.
#[derive(Clone)]
struct PendingOldKey {
    /// SHA-256 của file đã đọc.
    fp: [u8; 32],
    /// Đường dẫn file gốc (để đặt tên bản cất: `oldkey-<ms>-<tên gốc>`).
    origin: PathBuf,
    data: VaultData,
}

struct Snapshot {
    header: Header,
    key: Key,
    data: VaultData,
    disk_fingerprint: Option<[u8; 32]>,
    dirty: bool,
    pending_old_keys: Vec<PendingOldKey>,
}

#[derive(Default)]
struct Refreshed {
    stats: Option<MergeStats>,
    adopted: bool,
}

/// Kết quả của một lần ghi file kho.
#[derive(Default)]
struct WriteOutcome {
    backup_failed: bool,
    /// Số bản ghi bằng khoá cũ vừa được cất vào thư mục sao lưu.
    old_key_archived: usize,
    /// Đã ghi (rename xong) nhưng không xác minh được.
    unverified: bool,
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
        Ok(Vault::assemble(
            path,
            header,
            vault_key,
            data,
            Some(fingerprint(&bytes)),
            false,
            opts.allow_weak_kdf,
        ))
    }

    /// Dựng một `Vault` (ghi được) từ các phần đã có.
    fn assemble(
        path: PathBuf,
        header: Header,
        key: Key,
        data: VaultData,
        disk_fingerprint: Option<[u8; 32]>,
        dirty: bool,
        allow_weak_kdf: bool,
    ) -> Vault {
        Vault {
            path,
            header,
            vault_key: LockedKey::new(key),
            data,
            disk_fingerprint,
            dirty,
            backed_up: None,
            read_only: false,
            allow_weak_kdf,
            pending_old_keys: Vec::new(),
            archived_old_keys: Vec::new(),
        }
    }

    /// Mở kho bằng master password.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Vault> {
        Self::open_with(path, password, OpenOptions::default())
    }

    /// Mở kho bằng master password.
    ///
    /// Ngoài file kho chính, mật khẩu vừa nhập còn được thử trên tối đa 2 bản cạnh kho của CÙNG kho
    /// có lần đổi mật khẩu chính MỚI HƠN (xem [`Vault::absorb_forked_copies`] và
    /// `open_via_newer_copy`): đó là cách hai lần đổi mật khẩu trên hai máy chưa kịp đồng bộ được
    /// nối lại, và là cách mở kho khi máy khác vừa đổi mật khẩu.
    pub fn open_with(path: impl AsRef<Path>, password: &[u8], opts: OpenOptions) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        let bytes = fsutil::read_retry(&path)?;
        let v = match unlock_bytes(&bytes, password, opts.allow_weak_kdf) {
            Ok(u) => {
                let mut v = Vault::assemble(
                    path,
                    u.header,
                    u.key,
                    u.data,
                    Some(fingerprint(&bytes)),
                    false,
                    opts.allow_weak_kdf,
                );
                v.absorb_forked_copies(password);
                v
            }
            Err(Error::Decrypt) => {
                Self::open_via_newer_copy(&path, &bytes, password, opts).ok_or(Error::Decrypt)?
            }
            Err(e) => return Err(e),
        };
        fsutil::clean_stale_temps(&v.path);
        Ok(v)
    }

    /// Các bản cạnh kho của CÙNG kho có header khác `header` và lần đổi mật khẩu chính MỚI HƠN, mà
    /// tham số Argon2 không vượt `kdf_cap` ở chiều nào — mới nhất trước, tối đa 2 bản. Mỗi lần thử
    /// tốn một lượt Argon2 với tham số do FILE quy định, nên giới hạn này chặn việc ai đó có quyền
    /// ghi vào thư mục đồng bộ cài file bắt máy chạy Argon2 hàng phút mỗi lần mở khoá.
    fn newer_epoch_siblings(path: &Path, header: &Header, kdf_cap: &KdfParams) -> Vec<PathBuf> {
        let mut candidates: Vec<(i64, PathBuf)> = fsutil::sibling_candidates(path)
            .into_iter()
            .filter_map(|p| {
                let h = header_of(&p)?;
                (h.vault_id == header.vault_id
                    && h != *header
                    && h.key_changed_at > header.key_changed_at
                    && kdf_not_costlier(&h.kdf, kdf_cap))
                .then_some((h.key_changed_at, p))
            })
            .collect();
        candidates.sort_by(|a, b| b.cmp(a));
        candidates.into_iter().take(2).map(|(_, p)| p).collect()
    }

    /// Mật khẩu vừa nhập ĐÃ mở được file chính. Nếu cạnh đó có bản của cùng kho với lần đổi mật
    /// khẩu chính mới hơn mà CŨNG mở được bằng mật khẩu này, thì đó là lần đổi mật khẩu trên một máy
    /// khác (chưa kịp đồng bộ — có thể hai máy cùng đổi, sang cùng một mật khẩu mới). Cả hai khoá
    /// đều được chính mật khẩu chủ kho vừa gõ xác thực ⇒ gộp hai bên, nhận header + khoá của bản mới
    /// hơn làm khoá hiện tại, khoá của file chính vào `old_keys`. Lần đồng bộ kế tiếp ghi lại file
    /// chính và cất bản kia đi như một bản xung đột đã gộp. (Không làm vậy thì mỗi máy mãi mãi thấy
    /// file của máy kia là "hỏng" hoặc "mật khẩu đã đổi".)
    fn absorb_forked_copies(&mut self, password: &[u8]) {
        let cap = self.header.kdf;
        for p in Self::newer_epoch_siblings(&self.path, &self.header, &cap) {
            let Ok(bytes) = fsutil::read_retry(&p) else {
                continue;
            };
            let Ok(u) = unlock_bytes(&bytes, password, self.allow_weak_kdf) else {
                continue;
            };
            // Bản đầu tiên mở được đã đưa khoá lên mốc mới hơn; bản tiếp theo phải mới hơn nữa.
            if u.header.key_changed_at <= self.header.key_changed_at {
                continue;
            }
            self.data.merge_from(&u.data);
            if *u.key != **self.vault_key {
                let old: Key = Zeroizing::new(**self.vault_key);
                self.data.push_old_key(&old, u.header.key_changed_at);
                self.vault_key = LockedKey::new(u.key);
            }
            self.header = u.header;
            self.dirty = true;
        }
    }

    /// Mật khẩu không mở được file chính. Nếu cạnh đó có bản của CÙNG kho với lần đổi master
    /// password MỚI HƠN (máy kia đổi mật khẩu đúng lúc máy này đang ghi, nên dịch vụ đồng bộ giữ cả
    /// hai file), thử mở bằng bản đó. Sau đó xét file chính bằng khoá của bản vừa mở:
    ///
    /// - cùng khoá hiện tại ⇒ gộp vào;
    /// - chỉ mở được bằng khoá cũ ⇒ KHÔNG gộp; nó sẽ được cất (mã hoá lại) vào thư mục sao lưu
    ///   trước lần ghi kế tiếp;
    /// - không giải mã được ⇒ vẫn mở kho từ bản kia (mật khẩu đúng thì không được báo "sai mật
    ///   khẩu"), nhưng lần đồng bộ kế tiếp sẽ báo đúng tình trạng file chính để chủ kho quyết định.
    ///
    /// Lần đồng bộ kế tiếp ghi kết quả ra file chính và cất bản xung đột đi.
    fn open_via_newer_copy(
        path: &Path,
        main_bytes: &[u8],
        password: &[u8],
        opts: OpenOptions,
    ) -> Option<Vault> {
        let main = format::parse(main_bytes).ok()?;
        // Mật khẩu chưa mở được gì nên chưa biết tham số "thật"; cho phép tới mức mặc định.
        let cap = kdf_max(&main.header.kdf, &KdfParams::DEFAULT);
        for p in Self::newer_epoch_siblings(path, &main.header, &cap) {
            let Ok(bytes) = fsutil::read_retry(&p) else {
                continue;
            };
            let Ok(u) = unlock_bytes(&bytes, password, opts.allow_weak_kdf) else {
                continue;
            };
            let main_fp = fingerprint(main_bytes);
            let mut v = Vault::assemble(
                path.to_path_buf(),
                u.header,
                u.key,
                u.data,
                Some(main_fp),
                true,
                opts.allow_weak_kdf,
            );
            match decrypt_with_keys(&main, &v.vault_key, &v.data) {
                Ok((main_data, KeyUsed::Current)) => {
                    v.data.merge_from(&main_data);
                }
                Ok((main_data, KeyUsed::Retired)) => v.queue_old_key_archive(main_fp, main_data),
                Err(_) => v.disk_fingerprint = None,
            }
            return Some(v);
        }
        None
    }

    /// File kho chính không mở được (hỏng, đồng bộ dở, bị xoá): dựng lại kho từ thư mục sao lưu.
    /// Như [`Vault::recover_from_backups_opts`] với `allow_older = false`.
    pub fn recover_from_backups(
        path: impl AsRef<Path>,
        password: &[u8],
        opts: OpenOptions,
    ) -> Result<(Vault, usize, i64)> {
        Self::recover_from_backups_opts(path, password, opts, false)
    }

    /// File kho chính không mở được (hỏng, đồng bộ dở, bị xoá): dựng lại kho từ thư mục sao lưu.
    ///
    /// Các bản sao lưu (trừ file hỏng `damaged-…` và bản ghi bằng khoá cũ `oldkey-…`, vốn không bao
    /// giờ được tự gộp) được nhóm theo header; mỗi nhóm tốn một lượt Argon2, thử nhóm có lần đổi mật
    /// khẩu chính mới nhất trước, tối đa 5 nhóm. Nhóm đầu tiên mở được bằng `password` là gốc; rồi
    /// gộp thêm MỌI bản sao lưu giải mã được bằng đúng khoá đó (kể cả bản xung đột đã cất) để vớt
    /// được nhiều dữ liệu nhất. Bản chỉ mở được bằng khoá khác (khoá cũ) bị bỏ qua.
    ///
    /// Nếu gốc cũ hơn lần đổi mật khẩu mới nhất mà thư mục sao lưu ghi nhận (`password` là mật khẩu
    /// CŨ) thì trả về [`Error::OlderPasswordBackups`] — dựng lại từ đó sẽ đưa kho về mật khẩu cũ và
    /// làm mất các thay đổi sau lần đổi. Chỉ khi chủ kho chọn rõ ràng (`allow_older`) mới làm vậy.
    ///
    /// Kết quả mới chỉ nằm trong RAM: gọi [`Vault::force_write`] để ghi ra — file hỏng (nếu còn) sẽ
    /// được cất vào thư mục sao lưu, không bị xoá. Trả về kho, số file đã dùng và thời điểm của bản
    /// mới nhất trong số đó.
    pub fn recover_from_backups_opts(
        path: impl AsRef<Path>,
        password: &[u8],
        opts: OpenOptions,
        allow_older: bool,
    ) -> Result<(Vault, usize, i64)> {
        const MAX_PASSWORD_ATTEMPTS: usize = 5; // mỗi nhóm tốn một lượt Argon2
        const MAX_FILES_MERGED: usize = 40;
        let path = path.as_ref().to_path_buf();
        let candidates: Vec<(BackupFile, Header)> = fsutil::list_backups(&path)
            .into_iter()
            .filter(|b| !matches!(b.kind, BackupKind::Damaged | BackupKind::OldKey))
            .filter_map(|b| header_of(&b.path).map(|h| (b, h)))
            .collect();
        // `candidates` xếp mới nhất trước ⇒ trong mỗi nhóm cũng vậy.
        let mut groups: Vec<&Header> = Vec::new();
        for (_, h) in &candidates {
            if !groups.contains(&h) {
                groups.push(h);
            }
        }
        groups.sort_by_key(|h| std::cmp::Reverse(h.key_changed_at));
        let mut last_err = Error::VaultFileMissing(path.display().to_string());
        let mut base: Option<(Header, Key)> = None;
        for h in groups.into_iter().take(MAX_PASSWORD_ATTEMPTS) {
            match h.unwrap_key(password, opts.allow_weak_kdf) {
                Ok(k) => {
                    base = Some((h.clone(), k));
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        let Some((header, key)) = base else {
            return Err(last_err);
        };
        let newest_claimed = candidates
            .iter()
            .filter(|(_, h)| h.vault_id == header.vault_id)
            .map(|(_, h)| h.key_changed_at)
            .max()
            .unwrap_or(header.key_changed_at);
        if header.key_changed_at < newest_claimed && !allow_older {
            return Err(Error::OlderPasswordBackups);
        }
        let mut data: Option<VaultData> = None;
        let (mut used, mut newest) = (0usize, 0i64);
        for (b, _) in candidates
            .iter()
            .filter(|(_, h)| h.vault_id == header.vault_id)
            .take(MAX_FILES_MERGED)
        {
            // Chỉ nhận đúng khoá gốc: bản ghi bằng khoá cũ / khoá lạ trong thư mục đồng bộ không
            // được tự gộp (xem quy tắc ở đầu file).
            let Ok(bytes) = fsutil::read_retry(&b.path) else {
                continue;
            };
            let Ok(d) = format::parse(&bytes).and_then(|raw| raw.decrypt_body(&key)) else {
                continue;
            };
            match data.as_mut() {
                None => data = Some(d),
                Some(x) => {
                    x.merge_from(&d);
                }
            }
            used += 1;
            newest = newest.max(b.timestamp);
        }
        let Some(data) = data else {
            return Err(Error::VaultFileDamaged);
        };
        let v = Vault::assemble(path, header, key, data, None, true, opts.allow_weak_kdf);
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
        let mut v = Vault::assemble(
            label.into(),
            u.header,
            u.key,
            u.data,
            Some(fingerprint(bytes)),
            false,
            opts.allow_weak_kdf,
        );
        v.read_only = true;
        Ok(v)
    }

    /// Nạp phiên bản khác của **cùng kho** vào kho chỉ đọc (điện thoại bấm "tải lại"). Dữ liệu được
    /// GỘP chứ không thay thế, nên nếu dịch vụ đồng bộ trả về một bản cũ hơn thì các thay đổi mới
    /// đã thấy trước đó không bị mất. Trả về true nếu nội dung thay đổi.
    ///
    /// Bản chỉ mở được bằng khoá của mật khẩu chính CŨ bị bỏ qua (`Ok(false)`), không gộp.
    /// Nếu máy khác đã đổi master password: trả về [`Error::PasswordChangedElsewhere`] — phải mở
    /// khoá lại bằng mật khẩu mới.
    pub fn replace_from_bytes(&mut self, bytes: &[u8]) -> Result<bool> {
        let fp = fingerprint(bytes);
        if Some(fp) == self.disk_fingerprint {
            return Ok(false);
        }
        let (remote, adopt) = match self.decrypt_same_vault(bytes)? {
            Decrypted::Current { data, adopt_header } => (data, adopt_header),
            Decrypted::Retired { .. } => {
                self.disk_fingerprint = Some(fp);
                return Ok(false);
            }
        };
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
    ///
    /// Lỗi: [`Error::DifferentVault`], [`Error::UnsupportedVersion`], [`Error::VaultFileDamaged`],
    /// và [`Error::PasswordChangedElsewhere`] khi file ghi lần đổi mật khẩu MỚI HƠN mà không khoá
    /// nào mở được (người gọi đổi lỗi này thành [`Error::CopyUsesOtherPassword`] nếu đó không phải
    /// file kho chính — header chưa được xác thực, ai cũng ghi ra được một con số lớn).
    fn decrypt_same_vault(&self, bytes: &[u8]) -> Result<Decrypted> {
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
            // mà không đổi khoá kho ⇒ nhận header đó để hai máy dùng chung một mật khẩu. (Header này
            // đã được xác thực: nó nằm trong AAD của phần thân vừa giải mã bằng khoá hiện tại.)
            Ok((data, KeyUsed::Current)) => Ok(Decrypted::Current {
                data,
                adopt_header: newer_epoch.then(|| raw.header.clone()),
            }),
            Ok((data, KeyUsed::Retired)) => Ok(Decrypted::Retired { data }),
            Err(Error::Decrypt) if newer_epoch => Err(Error::PasswordChangedElsewhere),
            Err(Error::Decrypt) | Err(Error::BadFormat) | Err(Error::Json) => {
                Err(Error::VaultFileDamaged)
            }
            Err(e) => Err(e),
        }
    }

    /// Ghi nhớ một bản chỉ mở được bằng khoá cũ để cất nó (đã mã hoá lại) trước lần ghi kế tiếp.
    fn queue_old_key_archive(&mut self, fp: [u8; 32], data: VaultData) {
        if self.pending_old_keys.iter().all(|p| p.fp != fp) {
            self.pending_old_keys.push(PendingOldKey {
                fp,
                origin: self.path.clone(),
                data,
            });
        }
        self.dirty = true;
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
    ///
    /// File chỉ mở được bằng khoá CŨ thì không được gộp: nó được xếp hàng để cất (đã mã hoá lại)
    /// vào thư mục sao lưu, và kho bị đánh dấu cần ghi lại. Dấu vân tay của nó được nhớ nên lần đọc
    /// sau không xét lại đúng những byte đó.
    fn refresh(&mut self) -> Result<Refreshed> {
        let Some((bytes, fp)) = self.read_changed_file()? else {
            return Ok(Refreshed::default());
        };
        let (remote, adopt) = match self.decrypt_same_vault(&bytes)? {
            Decrypted::Current { data, adopt_header } => (data, adopt_header),
            Decrypted::Retired { data } => {
                self.queue_old_key_archive(fp, data);
                self.disk_fingerprint = Some(fp);
                return Ok(Refreshed::default());
            }
        };
        let disk_header = format::peek_header(&bytes)?;
        let stats = self.data.merge_from(&remote);
        let adopted = adopt.is_some();
        if let Some(h) = adopt {
            self.header = h;
        }
        self.disk_fingerprint = Some(fp);
        // Phải ghi lại nếu RAM có thứ file không có, hoặc file đang dùng khoá/mật khẩu cũ, hoặc còn
        // một bản ghi bằng khoá cũ chưa được cất.
        self.dirty =
            self.data != remote || disk_header != self.header || !self.pending_old_keys.is_empty();
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
            pending_old_keys: self.pending_old_keys.clone(),
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
        self.pending_old_keys = s.pending_old_keys;
    }

    /// Cất (đã mã hoá lại bằng header + khoá HIỆN TẠI) các bản chỉ mở được bằng khoá cũ đang chờ.
    /// Lỗi ⇒ trả lỗi: không được ghi đè file kho khi bản có thể là duy nhất chứa thay đổi chưa gộp
    /// của một máy khác còn chưa được cất an toàn.
    fn archive_pending_old_keys(&mut self) -> Result<usize> {
        let mut n = 0;
        for i in 0..self.pending_old_keys.len() {
            let p = &self.pending_old_keys[i];
            if self.archived_old_keys.contains(&p.fp) {
                continue;
            }
            let out = format::serialize(&self.header, &p.data, &self.vault_key)?;
            fsutil::write_archive(&self.path, BackupKind::OldKey, now_ms(), &p.origin, &out)?;
            let fp = p.fp;
            self.archived_old_keys.push(fp);
            n += 1;
        }
        Ok(n)
    }

    /// Ghi bản trong RAM ra đĩa (nguyên tử, có đọc lại kiểm tra) và giữ sao lưu:
    ///
    /// - TRƯỚC khi ghi: bản ghi bằng khoá cũ đang chờ (xem `refresh`) được cất, đã mã hoá lại.
    /// - TRƯỚC khi ghi (`keep_previous`): nếu nội dung đang nằm trên đĩa chưa chắc đã có trong thư
    ///   mục sao lưu (do máy khác / bản app cũ ghi, hoặc là lần ghi đầu của phiên) thì chép nó lại —
    ///   trừ khi đó là bản ghi bằng khoá cũ (đã được cất ở bước trên dưới dạng mã hoá lại; chép
    ///   nguyên văn thì mật khẩu cũ lại mở được nó).
    /// - SAU khi ghi: chép luôn bản vừa ghi. Nhờ vậy sau mỗi lần ghi bình thường, bản sao lưu mới
    ///   nhất giống hệt file kho, và nếu file kho hỏng thì khôi phục không mất lần sửa cuối cùng.
    ///
    /// Lỗi TRƯỚC khi file kho bị thay (không cất được bản khoá cũ, không ghi được file tạm, không
    /// rename được) ⇒ trả lỗi, người gọi hoàn tác. Đã thay xong mà đọc lại không xác minh được ⇒
    /// KHÔNG trả lỗi (xem `verify_written`): thay đổi đã nằm trên đĩa (rất có thể), nên hoàn tác RAM
    /// mới là thứ làm RAM và đĩa lệch nhau — với đổi mật khẩu thì RAM giữ khoá cũ còn đĩa dùng khoá
    /// mới, và chủ kho bị báo "thất bại" rồi không mở được kho. Khi đó trạng thái mới được giữ, dấu
    /// vân tay của đĩa bị quên (lần đọc sau đọc lại thật) và kho được đánh dấu cần ghi lại.
    fn write_to_disk(&mut self, keep_previous: bool) -> Result<WriteOutcome> {
        let bytes = format::serialize(&self.header, &self.data, &self.vault_key)?;
        let fp = fingerprint(&bytes);
        let mut out = WriteOutcome {
            old_key_archived: self.archive_pending_old_keys()?,
            ..Default::default()
        };
        let disk_is_old_key = self
            .pending_old_keys
            .iter()
            .any(|p| Some(p.fp) == self.disk_fingerprint);
        if keep_previous
            && !disk_is_old_key
            && self.disk_fingerprint.is_some()
            && self.disk_fingerprint != self.backed_up
        {
            match fsutil::backup_current(&self.path, now_ms()) {
                Ok(_) => self.backed_up = self.disk_fingerprint,
                Err(_) => out.backup_failed = true,
            }
        }
        fsutil::atomic_write(&self.path, &bytes)?;
        let verified = self.verify_written(&bytes);
        self.pending_old_keys.clear();
        self.archived_old_keys.clear();
        if verified {
            self.disk_fingerprint = Some(fp);
            self.dirty = false;
        } else {
            self.disk_fingerprint = None;
            self.dirty = true;
            out.unverified = true;
        }
        // Bản sao lưu luôn lấy từ `bytes` (bản tốt trong RAM), kể cả khi chưa xác minh được đĩa.
        match fsutil::backup_bytes(&self.path, now_ms(), &bytes) {
            Ok(_) => self.backed_up = Some(fp),
            Err(_) => out.backup_failed = true,
        }
        Ok(out)
    }

    /// Đọc lại file kho vừa ghi (test có thể giả lập lần đọc lại lỗi / sai).
    fn read_back(&self) -> std::io::Result<Vec<u8>> {
        #[cfg(test)]
        if let Some(f) = READBACK_FAULTS.with(|q| q.borrow_mut().pop_front()) {
            return f;
        }
        fsutil::read_retry(&self.path)
    }

    /// File vừa ghi có đúng là `bytes` không. Đọc lại; sai/lỗi ⇒ chờ một chút rồi đọc lại lần nữa
    /// (dịch vụ đồng bộ / diệt virus thường chỉ giữ file trong chốc lát); vẫn sai ⇒ ghi lại một lần
    /// nữa rồi kiểm tra. Không ghi lại nếu thứ đọc được là một file hợp lệ của kho này mà máy khác vừa
    /// ghi (đè lên là làm mất nó khỏi file kho) — lần đọc sau sẽ gộp nó như bình thường.
    fn verify_written(&self, bytes: &[u8]) -> bool {
        if self.read_back().is_ok_and(|b| b == bytes) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
        match self.read_back() {
            Ok(b) if b == bytes => return true,
            Ok(b) if self.written_by_someone_else(&b) => return false,
            _ => {}
        }
        fsutil::atomic_write(&self.path, bytes).is_ok()
            && self.read_back().is_ok_and(|b| b == bytes)
    }

    /// `b` là một file hợp lệ của kho này (mở được bằng một khoá đang có, hoặc ghi lần đổi mật khẩu
    /// mới hơn) — tức là của một máy khác, không phải bản ghi hỏng của chính ta.
    fn written_by_someone_else(&self, b: &[u8]) -> bool {
        matches!(
            self.decrypt_same_vault(b),
            Ok(_) | Err(Error::PasswordChangedElsewhere)
        )
    }

    fn prune_backups(&self) {
        fsutil::prune_backups(&self.path, now_ms(), |p| self.is_same_vault_file(p));
    }

    fn save_report(refreshed: Refreshed, w: WriteOutcome) -> SaveReport {
        SaveReport {
            merged_remote: refreshed.stats,
            adopted_remote_password: refreshed.adopted,
            backup_failed: w.backup_failed,
            old_key_archived: w.old_key_archived > 0,
            unverified: w.unverified,
        }
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
            let w = if self.dirty {
                self.write_to_disk(true)?
            } else {
                WriteOutcome::default()
            };
            Ok((t, w))
        });
        match result {
            Ok((t, w)) => {
                self.prune_backups();
                Ok((t, Self::save_report(refreshed, w)))
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
        let w = if self.dirty {
            self.write_to_disk(true)?
        } else {
            WriteOutcome::default()
        };
        self.prune_backups();
        Ok(Self::save_report(refreshed, w))
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
                self.archive_pending_old_keys()?;
                let bytes = format::serialize(&self.header, &self.data, &self.vault_key)?;
                fsutil::write_new(&self.path, &bytes)?;
                self.pending_old_keys.clear();
                self.archived_old_keys.clear();
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
    /// Trước hết chạy một lần [`Vault::sync`] đầy đủ (lỗi ⇒ huỷ đổi mật khẩu): các bản xung đột
    /// đang chờ, ghi bằng khoá hiện tại, phải được gộp TRƯỚC khi khoá đó thành khoá cũ — sau đó
    /// chúng chỉ còn là "bản ghi bằng khoá cũ" và không bao giờ được tự gộp nữa.
    ///
    /// Một **khoá kho mới** được sinh ra và toàn bộ dữ liệu được mã hoá lại, nên người biết mật
    /// khẩu cũ và giữ một bản sao cũ của file không đọc được dữ liệu ghi từ nay về sau, và file họ
    /// làm ra bằng khoá cũ không bao giờ được tự gộp vào kho. Khoá cũ được giữ bên trong phần đã mã
    /// hoá để chủ kho vẫn đọc được các bản sao lưu cũ. Các file trong thư mục sao lưu được mã hoá
    /// lại bằng khoá mới.
    ///
    /// Lưu ý: bản cũ trong lịch sử phiên bản của Drive/Dropbox và trên các thiết bị chưa đồng bộ
    /// vẫn mở được bằng mật khẩu cũ — phần mềm không thể với tới chúng.
    pub fn change_password(
        &mut self,
        new_password: &[u8],
        kdf: KdfParams,
    ) -> Result<PasswordChangeReport> {
        kdf.validate(self.allow_weak_kdf)?;
        self.sync()?;
        let ((), save) = self.transact(|v| {
            let new_key = crypto::random_key();
            let changed = now_ms().max(v.header.key_changed_at.saturating_add(1));
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

    /// Mã hoá lại bằng khoá + mật khẩu hiện tại những bản sao lưu còn dùng header cũ (ví dụ lần
    /// đổi mật khẩu trước bị ngắt giữa chừng, trước khi kịp mã hoá lại thư mục sao lưu). Trả về số
    /// file đã mã hoá lại. Đọc mọi file trong thư mục sao lưu ⇒ chỉ nên gọi một lần mỗi khi mở khoá,
    /// không gọi trong đồng bộ nền.
    pub fn reencrypt_stale_backups(&self) -> usize {
        if self.read_only {
            return 0;
        }
        self.reencrypt_backups().backups_reencrypted
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
    ///
    /// CHỈ dùng cho bản sao ĐÁNG TIN nằm ngoài thư mục đồng bộ (ví dụ bản cứu hộ trong thư mục dữ
    /// liệu riêng của app, nơi người chỉ có quyền ghi vào thư mục đồng bộ không với tới): khác với
    /// [`Vault::sync`], hàm này gộp cả nội dung chỉ mở được bằng khoá CŨ.
    pub fn merge_file(&mut self, other: impl AsRef<Path>) -> Result<MergeStats> {
        let bytes = fsutil::read_retry(other.as_ref())?;
        let (remote, adopt) = match self.decrypt_same_vault(&bytes) {
            Ok(Decrypted::Current { data, adopt_header }) => (data, adopt_header),
            Ok(Decrypted::Retired { data }) => (data, None),
            Err(Error::PasswordChangedElsewhere) => return Err(Error::CopyUsesOtherPassword),
            Err(e) => return Err(e),
        };
        Ok(self.merge_remote(&remote, adopt).0)
    }

    /// Gộp dữ liệu đã giải mã (và nhận header, nếu có) vào RAM.
    fn merge_remote(&mut self, remote: &VaultData, adopt: Option<Header>) -> (MergeStats, bool) {
        let before = self.data.clone();
        let stats = self.data.merge_from(remote);
        let adopted = adopt.is_some();
        if let Some(h) = adopt {
            self.header = h;
        }
        if adopted || self.data != before {
            self.dirty = true;
        }
        (stats, adopted)
    }

    /// Chuyển `path` vào thư mục sao lưu (loại `kind`) chỉ khi nội dung của nó vẫn đúng là thứ đã
    /// đọc (SHA-256 `fp`). Nếu dịch vụ đồng bộ vừa thay file bằng bản khác thì để nguyên — lần đồng
    /// bộ sau sẽ xét lại.
    fn archive_if_unchanged(&self, path: &Path, fp: [u8; 32], kind: BackupKind) -> bool {
        let unchanged = fsutil::read_retry(path).is_ok_and(|b| fingerprint(&b) == fp);
        unchanged && fsutil::archive_file(&self.path, kind, now_ms(), path).is_ok()
    }

    /// Bản cạnh kho chỉ mở được bằng khoá cũ: cất nó (đã mã hoá lại bằng khoá hiện tại) vào thư
    /// mục sao lưu rồi xoá file gốc — chỉ khi file gốc vẫn đúng là thứ đã đọc. Không xoá được thì
    /// xoá bản vừa cất, để các lần đồng bộ sau không chất thêm bản trùng.
    fn archive_retired_copy(&self, path: &Path, fp: [u8; 32], data: &VaultData) -> bool {
        let Ok(out) = format::serialize(&self.header, data, &self.vault_key) else {
            return false;
        };
        let Ok(archived) =
            fsutil::write_archive(&self.path, BackupKind::OldKey, now_ms(), path, &out)
        else {
            return false;
        };
        let unchanged = fsutil::read_retry(path).is_ok_and(|b| fingerprint(&b) == fp);
        if unchanged && fsutil::retry(|| fs::remove_file(path)).is_ok() {
            return true;
        }
        let _ = fs::remove_file(&archived);
        false
    }

    /// Đồng bộ với thư mục: nạp thay đổi của máy khác, gộp các bản xung đột, **ghi lại file kho nếu
    /// bản trong RAM có thứ mà file trên đĩa không có**, rồi mới cất các bản xung đột đã gộp vào
    /// thư mục sao lưu (không bao giờ cất trước khi kho đã được ghi thành công, và chỉ cất nếu file
    /// vẫn đúng là bản đã gộp).
    ///
    /// Với từng bản cạnh kho:
    /// - mở được bằng khoá hiện tại ⇒ gộp, rồi cất (`merged-…`);
    /// - chỉ mở được bằng khoá cũ ⇒ KHÔNG gộp; cất bản đã mã hoá lại (`oldkey-…`) rồi xoá nó, báo
    ///   [`Error::RetiredKeyCopy`];
    /// - ghi lần đổi mật khẩu mới hơn mà không mở được ⇒ để nguyên, báo
    ///   [`Error::CopyUsesOtherPassword`] và vẫn đồng bộ tiếp. [`Error::PasswordChangedElsewhere`]
    ///   chỉ được trả về khi đó là FILE KHO CHÍNH.
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
        // (vị trí trong report.conflicts, SHA-256 của bản đã gộp)
        let mut merged: Vec<(usize, [u8; 32])> = Vec::new();
        let mut retired: Vec<(PathBuf, [u8; 32], VaultData)> = Vec::new();
        for path in self.conflict_copies() {
            let bytes = match fsutil::read_retry(&path) {
                Ok(b) => b,
                Err(e) => {
                    report.conflicts.push(ConflictOutcome {
                        path,
                        result: Err(e.into()),
                        archived: false,
                    });
                    continue;
                }
            };
            let fp = fingerprint(&bytes);
            let result = match self.decrypt_same_vault(&bytes) {
                Ok(Decrypted::Current { data, adopt_header }) => {
                    let (stats, adopted) = self.merge_remote(&data, adopt_header);
                    report.adopted_remote_password |= adopted;
                    merged.push((report.conflicts.len(), fp));
                    Ok(stats)
                }
                Ok(Decrypted::Retired { data }) => {
                    retired.push((path, fp, data));
                    continue;
                }
                // Header chưa xác thực của một bản cạnh kho thì ai cũng ghi được ⇒ không bao giờ
                // được làm dừng đồng bộ hay khoá app.
                Err(Error::PasswordChangedElsewhere) => Err(Error::CopyUsesOtherPassword),
                Err(e) => Err(e),
            };
            report.conflicts.push(ConflictOutcome {
                path,
                result,
                archived: false,
            });
        }
        if self.dirty {
            let w = self.write_to_disk(true)?;
            report.backup_failed = w.backup_failed;
            report.old_key_archived += w.old_key_archived;
            report.unverified = w.unverified;
            report.wrote = true;
        }
        test_hook("sync:before-archive");
        for (i, fp) in merged {
            let c = &mut report.conflicts[i];
            c.archived = self.archive_if_unchanged(&c.path, fp, BackupKind::Merged);
        }
        for (path, fp, data) in retired {
            let archived = self.archive_retired_copy(&path, fp, &data);
            report.old_key_archived += usize::from(archived);
            report.conflicts.push(ConflictOutcome {
                path,
                result: Err(Error::RetiredKeyCopy),
                archived,
            });
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

    /// Đọc nội dung một bản sao lưu (phải nằm trong thư mục sao lưu của kho này). Nhận cả bản chỉ
    /// mở được bằng khoá cũ: đây là việc chủ kho tự chọn xem / khôi phục từng mục.
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
        // (Bản ghi bằng khoá cũ còn chờ chỉ có thể nằm ở chỗ cũ khi "cứu" — chỗ cũ giữ nguyên.)
        self.pending_old_keys.clear();
        self.archived_old_keys.clear();
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

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &[u8] = b"mat khau test";

    fn opts() -> CreateOptions {
        CreateOptions {
            kdf: KdfParams::INSECURE_TEST,
            allow_weak_kdf: true,
        }
    }

    fn open(p: &Path) -> Vault {
        Vault::open_with(
            p,
            PW,
            OpenOptions {
                allow_weak_kdf: true,
            },
        )
        .unwrap()
    }

    fn titles(v: &Vault) -> Vec<String> {
        let mut t: Vec<String> = v.entries().iter().map(|e| e.title.clone()).collect();
        t.sort();
        t
    }

    fn set_hook(point: &'static str, f: impl FnMut() + 'static) {
        TEST_HOOK.with(|h| *h.borrow_mut() = Some((point, Box::new(f))));
    }

    fn clear_hook() {
        TEST_HOOK.with(|h| *h.borrow_mut() = None);
    }

    /// Rà soát "archive race": bản xung đột được gộp lúc đọc, nhưng chỉ được cất SAU khi ghi kho.
    /// Nếu dịch vụ đồng bộ thay nó bằng bản khác trong lúc đó thì bản mới chưa hề được gộp ⇒ không
    /// được cất đi (trước đây: bị chuyển vào `merged-…` và không bao giờ được gộp).
    #[test]
    fn conflict_copy_replaced_between_merge_and_archive_is_left_for_the_next_sync() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        let mut v = Vault::create(&p, PW, opts()).unwrap();
        v.add(Entry::new("Base"));
        v.save().unwrap();
        let conflict = d.path().join("vault (1).pwv");
        fs::copy(&p, &conflict).unwrap();
        let mut other = open(&conflict);
        other.add(Entry::new("Bản 1"));
        other.save().unwrap();
        let _ = fs::remove_dir_all(fsutil::backup_dir(&conflict));

        let c2 = conflict.clone();
        set_hook("sync:before-archive", move || {
            // Dịch vụ đồng bộ tải về phiên bản mới hơn của bản xung đột đúng lúc này.
            let mut o = open(&c2);
            o.add(Entry::new("Bản 2"));
            o.save().unwrap();
            let _ = fs::remove_dir_all(fsutil::backup_dir(&c2));
        });
        let r = v.sync();
        clear_hook();
        let r = r.unwrap();
        assert!(r.wrote);
        assert!(r.conflicts[0].result.is_ok() && !r.conflicts[0].archived);
        assert!(conflict.exists());
        assert_eq!(titles(&v), ["Base", "Bản 1"]);
        // Lần đồng bộ sau gộp bản mới rồi mới cất.
        let r = v.sync().unwrap();
        assert!(r.conflicts[0].archived && !conflict.exists());
        assert_eq!(titles(&open(&p)), ["Base", "Bản 1", "Bản 2"]);
    }
}
