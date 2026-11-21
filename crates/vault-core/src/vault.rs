//! API chính: tạo / mở / sửa / lưu kho, đồng bộ qua thư mục Google Drive / Dropbox / OneDrive.
//!
//! # Nguyên tắc an toàn dữ liệu
//!
//! - **Đọc–gộp–ghi**: trước mỗi lần ghi, file trên đĩa được đọc lại và gộp vào bản trong RAM, nên
//!   không bao giờ ghi đè mất thay đổi của máy khác.
//! - **Giao dịch**: [`Vault::transact`] gộp file trên đĩa TRƯỚC khi sửa, và nếu ghi thất bại
//!   (trước khi file kho bị thay) thì hoàn tác thay đổi trong RAM — thứ đang hiển thị là thứ đã nằm
//!   trên đĩa. Ngoại lệ duy nhất: file ĐÃ được thay nhưng đọc lại không xác minh được
//!   ([`SaveReport::unverified`]) — khi đó KHÔNG hoàn tác (đĩa rất có thể đã là bản mới), mà đọc lại
//!   và ghi lại ở lần đồng bộ sau.
//! - **Không tự ghi đè file lạ**: file trên đĩa hỏng, thuộc kho khác, do bản app mới hơn ghi, hoặc
//!   biến mất ⇒ báo lỗi riêng cho từng trường hợp và chờ người dùng quyết định.
//! - **Đổi master password = đổi luôn khoá kho**: mật khẩu cũ + bản sao cũ không mở được những gì
//!   máy này ghi SAU lần đổi (file kho, bản sao lưu, bản cất `oldkey-…`). Không với tới được: bản cũ
//!   trong lịch sử phiên bản / thùng rác của dịch vụ đồng bộ, và những gì một máy CHƯA biết lần đổi
//!   tiếp tục ghi (file kho, bản sao lưu của chính nó) cho tới khi nó mở khoá bằng mật khẩu mới.
//! - **Khoá cũ chỉ còn quyền đọc**: một file trong thư mục đồng bộ chỉ mở được bằng khoá của mật
//!   khẩu chính cũ (ai biết mật khẩu cũ và giữ bản sao cũ cũng làm ra được file như vậy) KHÔNG BAO
//!   GIỜ được tự gộp vào kho. Nó được mã hoá lại bằng khoá hiện tại và cất vào thư mục sao lưu
//!   (`oldkey-…`) để chủ kho tự xem lại và lấy từng mục ra nếu muốn.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::{Config, Rollback};
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
    /// Chỉ ghi bản đang mở sang vị trí mới, mọi thứ ở vị trí cũ được giữ nguyên: luôn đúng với
    /// [`Vault::copy_to`]; với [`Vault::move_to`] là khi file ở vị trí cũ không đọc được (hỏng / biến
    /// mất / của kho khác).
    pub rescued: bool,
}

/// Thông tin đọc từ header của một file kho mà KHÔNG cần mật khẩu (xem [`Vault::peek`]). Header
/// chưa được xác thực: chỉ dùng để hiển thị / gợi ý, không dùng để quyết định tin file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub vault_id: String,
    /// Phiên bản định dạng (1 = do bản app 0.1.x ghi).
    pub version: u16,
    /// Lần đổi master password gần nhất (ms) mà file tự khai.
    pub key_changed_at: i64,
    /// File tự khai là bản sao lưu có từ trước lần đổi mật khẩu (xem `Header::pre_change`).
    pub pre_change: bool,
    pub kdf: KdfParams,
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordChangeReport {
    /// Số bản sao lưu đã được mã hoá lại bằng khoá mới.
    pub backups_reencrypted: usize,
    /// Số bản sao lưu để nguyên vì không đọc / không giải mã được bằng khoá hiện tại hay khoá vừa bị
    /// thay (file hỏng, của kho khác, hoặc chỉ mở được bằng một master password CŨ HƠN nữa).
    pub backups_skipped: usize,
    /// Tên file (trong thư mục sao lưu) của các bản ĐỌC ĐƯỢC mà GHI LẠI không được (đĩa đầy, file bị
    /// dịch vụ đồng bộ / diệt virus giữ), kể cả sau một lần thử lại. Các bản này VẪN mở được bằng
    /// master password vừa bị thay. Không tính vào `backups_skipped`.
    pub backups_failed: Vec<String>,
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
    /// Phiên bản định dạng của file kho chính như lúc mở (xem [`Vault::opened_version`]).
    opened_version: u16,
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

// Test: số lần ghi lại bản sao lưu (lúc đổi mật khẩu) kế tiếp bị giả lập là thất bại.
#[cfg(test)]
thread_local! {
    static REENCRYPT_WRITE_FAULTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reencrypt_write_fault() -> Result<()> {
    REENCRYPT_WRITE_FAULTS.with(|c| match c.get() {
        0 => Ok(()),
        n => {
            c.set(n - 1);
            Err(Error::Io(std::io::Error::other("lỗi ghi giả lập")))
        }
    })
}

#[cfg(not(test))]
#[inline(always)]
fn reencrypt_write_fault() -> Result<()> {
    Ok(())
}

/// Đọc file kho chính (hoặc một bản cùng kho) — file lớn hơn [`fsutil::MAX_VAULT_FILE`] bị coi là
/// file hỏng, không được đọc vào RAM.
fn read_vault_file(path: &Path) -> Result<Vec<u8>> {
    fsutil::read_retry_capped(path, fsutil::MAX_VAULT_FILE)?.ok_or(Error::VaultFileDamaged)
}

/// Như [`read_copy`] nhưng giữ lỗi: file quá lớn ⇒ lỗi `InvalidData` (không đọc vào RAM).
fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    fsutil::read_retry_capped(path, fsutil::MAX_VAULT_FILE)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file lớn hơn {} MiB", fsutil::MAX_VAULT_FILE >> 20),
        )
    })
}

/// Gộp `src` (đọc từ một file định dạng `version`) vào `target`. Bản v1 (0.1.x): tombstone chỉ có
/// hiệu lực với mục KHÔNG được sửa sau lần xoá — so với chính `target` (quy tắc gộp của 0.1.2), vì
/// file v1 có thể chỉ mang lần xoá mà không mang lần sửa sau đó (bản sao lưu ghi giữa hai việc,
/// bản xung đột còn sót).
fn merge_versioned(target: &mut VaultData, src: &VaultData, version: u16) -> MergeStats {
    if version == 1 {
        let mut s = src.clone();
        s.drop_v1_tombstones_superseded_by(target);
        target.merge_from(&s)
    } else {
        target.merge_from(src)
    }
}

/// Đọc một bản (bản sao lưu / bản cạnh kho) để thử; không đọc được hoặc quá lớn ⇒ `None`.
fn read_copy(path: &Path) -> Option<Vec<u8>> {
    fsutil::read_retry_capped(path, fsutil::MAX_VAULT_FILE)
        .ok()
        .flatten()
}

/// Miền của khoá con dùng cho [`Vault::seal_local`].
const LOCAL_DOMAIN: &[u8] = b"pwv/v1/local\0";
/// Đầu của một khối đã niêm phong bằng [`Vault::seal_local`].
const LOCAL_MAGIC: &[u8; 4] = b"PWL1";

/// Khoá con (HKDF-SHA256 từ khoá kho) cho một mục đích `purpose`.
fn local_subkey(vault_key: &[u8; crypto::KEY_LEN], purpose: &str) -> Key {
    let hk = hkdf::Hkdf::<Sha256>::new(None, vault_key);
    let mut info = Zeroizing::new(LOCAL_DOMAIN.to_vec());
    info.extend_from_slice(purpose.as_bytes());
    let mut k = Zeroizing::new([0u8; crypto::KEY_LEN]);
    // 32 byte luôn nằm trong giới hạn đầu ra của HKDF-SHA256.
    hk.expand(&info, k.as_mut())
        .expect("HKDF-SHA256 cho được 32 byte");
    k
}

fn local_aad(purpose: &str, vault_id: &str) -> Vec<u8> {
    let mut aad = LOCAL_DOMAIN.to_vec();
    aad.extend_from_slice(purpose.as_bytes());
    aad.push(0);
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Dấu nhận dạng 64 bit của một khoá kho: SHA-256 có tách miền, không dùng được để dò ra khoá
/// (khoá là 256 bit ngẫu nhiên). Bit thấp luôn bật để không bao giờ bằng 0 (0 = "chưa ghi nhận").
fn key_tag_of(vault_id: &str, key: &[u8; crypto::KEY_LEN]) -> u64 {
    let mut h = Sha256::new();
    h.update(b"pwv/v1/key-tag\0");
    h.update(vault_id.as_bytes());
    h.update([0u8]);
    h.update(key);
    let d = h.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&d[..8]);
    u64::from_le_bytes(first) | 1
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
    version: u16,
}

/// Mở một file kho bằng master password.
fn unlock_bytes(bytes: &[u8], password: &[u8], allow_weak_kdf: bool) -> Result<Unlocked> {
    let raw = format::parse(bytes)?;
    // Bản sao lưu có từ trước lần đổi mật khẩu (xem `Header::pre_change`) không phải là file kho:
    // không bao giờ mở kho từ nó. Báo như file hỏng để chủ kho được mời "khôi phục từ bản sao lưu".
    if raw.header.pre_change {
        return Err(Error::VaultFileDamaged);
    }
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
        version: raw.version,
    })
}

/// Một file đã giải mã được thuộc loại nào.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyUsed {
    /// Khoá kho hiện tại, và file không mang dấu "bản từ trước lần đổi mật khẩu".
    Current,
    /// Một khoá cũ trong `old_keys` (khoá của một mật khẩu chính đã đổi), HOẶC khoá hiện tại nhưng
    /// file mang dấu `Header::pre_change`. Cả hai đều là nội dung từ thời mật khẩu cũ: không đáng tin.
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
        // (Phần thân giải mã được ⇒ header, kể cả dấu `pre_change`, là thật.)
        Ok(d) if raw.header.pre_change => return Ok((d, KeyUsed::Retired)),
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
        /// Phiên bản định dạng của file (1 = bản 0.1.x: xem [`merge_versioned`]).
        version: u16,
    },
    /// Chỉ mở được bằng một khoá cũ. Một máy chưa biết lần đổi mật khẩu ghi ra được file như vậy,
    /// nhưng ai biết mật khẩu CŨ và giữ một bản sao cũ cũng làm được ⇒ KHÔNG BAO GIỜ tự gộp.
    Retired { data: VaultData, version: u16 },
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

/// Bản chỉ mở được bằng khoá cũ, đang chờ được cất NGUYÊN VĂN vào thư mục sao lưu.
///
/// Không bao giờ mã hoá lại nó bằng khoá hiện tại: khi đó thứ duy nhất còn phân biệt nó với một bản
/// đáng tin là TÊN FILE, mà tên file thì ai có quyền ghi vào thư mục đồng bộ cũng đổi được — chỉ cần
/// chuyển bản đã cất ra cạnh file kho là lần đồng bộ sau gộp nó như một bản xung đột bình thường.
/// Giữ nguyên văn thì dù nằm ở đâu, mang tên gì, nó vẫn chỉ mở được bằng khoá cũ ⇒ không bao giờ được gộp.
#[derive(Clone)]
struct PendingOldKey {
    /// SHA-256 của file đã đọc.
    fp: [u8; 32],
    /// Đường dẫn file gốc (để đặt tên bản cất: `oldkey-<ms>-<tên gốc>`).
    origin: PathBuf,
    /// Đúng những byte đã đọc.
    bytes: Vec<u8>,
}

struct Snapshot {
    header: Header,
    key: Key,
    data: VaultData,
    disk_fingerprint: Option<[u8; 32]>,
    dirty: bool,
    pending_old_keys: Vec<PendingOldKey>,
}

/// Kết quả mã hoá lại một bản sao lưu lúc đổi mật khẩu.
enum Reencrypt {
    Done,
    /// Không đọc / không giải mã được bằng khoá hiện tại hay khoá vừa bị thay.
    Skipped,
    /// Không thuộc diện mã hoá lại (của kho khác, đã dùng header hiện tại, file hỏng đã cất).
    Ignored,
    /// Đọc và giải mã được nhưng ghi lại thất bại.
    WriteFailed,
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
            opened_version: format::VERSION,
        }
    }

    /// Mở kho bằng master password.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Vault> {
        Self::open_with(path, password, OpenOptions::default())
    }

    /// Mở kho bằng master password.
    ///
    /// Ngoài file kho chính, mật khẩu vừa nhập còn được thử trên tối đa 2 bản cạnh kho của CÙNG kho
    /// có lần đổi mật khẩu chính MỚI HƠN (xem `absorb_forked_copies` và
    /// `open_via_newer_copy`): đó là cách hai lần đổi mật khẩu trên hai máy chưa kịp đồng bộ được
    /// nối lại, và là cách mở kho khi máy khác vừa đổi mật khẩu.
    ///
    /// Mật khẩu không mở được file chính nhưng mở được TRỌN VẸN một bản sao lưu / bản cạnh kho của
    /// cùng kho, và chứng minh được rằng phần thân của file chính là của kho này (chỉ phần gói khoá
    /// trong header bị sửa / hỏng) ⇒ [`Error::VaultFileDamaged`] chứ không phải [`Error::Decrypt`],
    /// để chủ kho được mời "khôi phục từ bản sao lưu". File chính lớn hơn
    /// [`fsutil::MAX_VAULT_FILE`] cũng là [`Error::VaultFileDamaged`].
    pub fn open_with(path: impl AsRef<Path>, password: &[u8], opts: OpenOptions) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        let bytes = read_vault_file(&path)?;
        let mut v = match unlock_bytes(&bytes, password, opts.allow_weak_kdf) {
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
            Err(Error::Decrypt) => Self::open_via_newer_copy(&path, &bytes, password, opts)?,
            Err(e) => return Err(e),
        };
        v.opened_version = format::peek_versioned(&bytes).map_or(format::VERSION, |(ver, _)| ver);
        fsutil::clean_stale_temps(&v.path);
        Ok(v)
    }

    /// Đọc header của một file kho mà không cần mật khẩu (chỉ đọc phần đầu file, tối đa
    /// [`format::HEADER_PEEK_LEN`] byte). Header CHƯA được xác thực.
    ///
    /// Lỗi: [`Error::Io`] (không đọc được / không có file), [`Error::BadFormat`] (không phải file kho),
    /// [`Error::UnsupportedVersion`] (do bản app mới hơn ghi).
    pub fn peek(path: impl AsRef<Path>) -> Result<FileInfo> {
        let prefix = fsutil::read_prefix(path.as_ref(), format::HEADER_PEEK_LEN)?;
        let (version, h) = format::peek_versioned(&prefix)?;
        Ok(FileInfo {
            vault_id: h.vault_id,
            version,
            key_changed_at: h.key_changed_at,
            pre_change: h.pre_change,
            kdf: h.kdf,
        })
    }

    /// Các bản cạnh kho có `vault_id` này (lọc theo header TRƯỚC khi giới hạn số lượng, để file
    /// `.pwv` rác không chiếm được chỗ của bản xung đột thật), xếp theo tên, tối đa
    /// [`fsutil::MAX_SAME_VAULT_SIBLINGS`] bản.
    fn same_vault_siblings(path: &Path, vault_id: &str) -> Vec<(PathBuf, Header)> {
        fsutil::sibling_files(path)
            .into_iter()
            .filter_map(|p| {
                let h = header_of(&p)?;
                (h.vault_id == vault_id).then_some((p, h))
            })
            .take(fsutil::MAX_SAME_VAULT_SIBLINGS)
            .collect()
    }

    /// Các bản cạnh kho của CÙNG kho có header khác `header` và lần đổi mật khẩu chính MỚI HƠN, mà
    /// tham số Argon2 không vượt `kdf_cap` ở chiều nào — mới nhất trước, tối đa 2 bản. Mỗi lần thử
    /// tốn một lượt Argon2 với tham số do FILE quy định, nên giới hạn này chặn việc ai đó có quyền
    /// ghi vào thư mục đồng bộ cài file bắt máy chạy Argon2 hàng phút mỗi lần mở khoá.
    fn newer_epoch_siblings(path: &Path, header: &Header, kdf_cap: &KdfParams) -> Vec<PathBuf> {
        let mut candidates: Vec<(i64, PathBuf)> = Self::same_vault_siblings(path, &header.vault_id)
            .into_iter()
            .filter_map(|(p, h)| {
                (h != *header
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
            let Some(bytes) = read_copy(&p) else {
                continue;
            };
            let Ok(u) = unlock_bytes(&bytes, password, self.allow_weak_kdf) else {
                continue;
            };
            // Bản đầu tiên mở được đã đưa khoá lên mốc mới hơn; bản tiếp theo phải mới hơn nữa.
            if u.header.key_changed_at <= self.header.key_changed_at {
                continue;
            }
            merge_versioned(&mut self.data, &u.data, u.version);
            if *u.key != **self.vault_key {
                let old: Key = Zeroizing::new(**self.vault_key);
                self.data.push_old_key(&old, u.header.key_changed_at);
                self.vault_key = LockedKey::new(u.key);
            }
            self.header = u.header;
            self.dirty = true;
        }
    }

    /// Mật khẩu không mở được file chính. Nếu có một bản khác của CÙNG kho dùng GÓI KHOÁ KHÁC file
    /// chính (cùng gói khoá thì chắc chắn cũng không mở được, khỏi tốn Argon2) với lần đổi master
    /// password không cũ hơn file chính — bản cạnh kho (máy kia đổi mật khẩu đúng lúc máy này đang
    /// ghi, nên dịch vụ đồng bộ giữ cả hai file), hoặc bản sao lưu (máy chưa biết mật khẩu mới đã ghi
    /// đè file kho mà dịch vụ đồng bộ không giữ lại bản kia; hoặc gói khoá trong header file chính bị
    /// sửa / hỏng) — thì thử mở TRỌN VẸN bản đó (gói khoá + phần thân, nên header của nó được xác
    /// thực; bản `pre_change` bị bỏ qua). Sau đó xét file chính bằng khoá của bản vừa mở:
    ///
    /// - cùng khoá hiện tại ⇒ gộp vào;
    /// - chỉ mở được bằng khoá cũ ⇒ KHÔNG gộp; nó sẽ được cất nguyên văn vào thư mục sao lưu trước
    ///   lần ghi kế tiếp;
    /// - không giải mã được ⇒ KHÔNG mở từ bản này. Lý do: ai biết mật khẩu CŨ và có quyền ghi vào thư
    ///   mục đồng bộ tự làm được một "bản mới hơn" mở bằng mật khẩu cũ (header chưa được xác thực,
    ///   khoá do họ chọn). Nếu chủ kho lỡ gõ mật khẩu cũ mà app mở kho từ bản đó, thì lần "ghi đè file
    ///   hỏng" sau sẽ đưa cả kho về khoá của kẻ đó. Đòi khoá của bản kia mở được file chính là thứ
    ///   chặn điều này (kẻ đó không có khoá hiện tại). Riêng khi phần thân của file chính giải mã được
    ///   bằng khoá đó với header CỦA BẢN KIA làm dữ liệu xác thực — tức file chính đúng là do người có
    ///   khoá này ghi, chỉ header của nó bị đổi sau đó — thì mật khẩu chắc chắn đúng và file chính
    ///   chắc chắn hỏng ⇒ [`Error::VaultFileDamaged`] (không mở từ bản kia: chủ kho đi qua bước khôi
    ///   phục, nơi có các kiểm tra mật khẩu cũ / quay lui).
    ///
    /// Tối đa 2 lượt Argon2 (mỗi "gói khoá" một lượt), tham số bị chặn như `newer_epoch_siblings`.
    /// Lần đồng bộ kế tiếp ghi kết quả ra file chính và cất bản xung đột đi.
    fn open_via_newer_copy(
        path: &Path,
        main_bytes: &[u8],
        password: &[u8],
        opts: OpenOptions,
    ) -> Result<Vault> {
        const MAX_ATTEMPTS: usize = 2; // mỗi lượt thử tốn một lượt Argon2
        let Ok(main) = format::parse(main_bytes) else {
            return Err(Error::Decrypt);
        };
        let mh = &main.header;
        // Mật khẩu chưa mở được gì nên chưa biết tham số "thật"; cho phép tới mức mặc định.
        let cap = kdf_max(&mh.kdf, &KdfParams::DEFAULT);
        let eligible = |h: &Header| {
            h.vault_id == mh.vault_id
                && !h.same_wrap(mh)
                && h.key_changed_at >= mh.key_changed_at
                && kdf_not_costlier(&h.kdf, &cap)
        };
        let mut siblings: Vec<(i64, PathBuf)> = Self::same_vault_siblings(path, &mh.vault_id)
            .into_iter()
            .filter(|(_, h)| eligible(h))
            .map(|(p, h)| (h.key_changed_at, p))
            .collect();
        siblings.sort_by(|a, b| b.cmp(a));
        let mut candidates: Vec<PathBuf> = siblings.into_iter().take(2).map(|(_, p)| p).collect();
        // Bản sao lưu (tự động / bản xung đột đã gộp): lần đổi mật khẩu (tự khai) mới nhất trước.
        let mut backups: Vec<(i64, i64, PathBuf)> = fsutil::list_backups(path)
            .into_iter()
            .filter(|b| matches!(b.kind, BackupKind::Auto | BackupKind::Merged))
            .filter_map(|b| {
                let h = header_of(&b.path)?;
                eligible(&h).then_some((h.key_changed_at, b.timestamp, b.path))
            })
            .collect();
        backups.sort_by(|a, b| b.cmp(a));
        candidates.extend(backups.into_iter().map(|(_, _, p)| p));

        // Các file dùng chung một "gói khoá" (kể cả header bị sửa số `key_changed_at`) chỉ tốn một
        // lượt Argon2; gói đã thử mà sai mật khẩu thì không thử lại.
        let mut tried: Vec<(Header, Option<Key>)> = Vec::new();
        let mut main_proven_damaged = false;
        for p in candidates {
            let Some(bytes) = read_copy(&p) else {
                continue;
            };
            let Ok(raw) = format::parse(&bytes) else {
                continue;
            };
            if raw.header.pre_change {
                continue; // bản từ trước lần đổi mật khẩu: không bao giờ mở kho từ nó
            }
            let known = tried.iter().position(|(h, _)| h.same_wrap(&raw.header));
            let key = match known {
                Some(i) => tried[i].1.clone(),
                None => {
                    if tried.len() >= MAX_ATTEMPTS {
                        continue;
                    }
                    let k = raw.header.unwrap_key(password, opts.allow_weak_kdf).ok();
                    tried.push((raw.header.clone(), k.clone()));
                    k
                }
            };
            let Some(key) = key else {
                continue;
            };
            // Phần thân giải mã được ⇒ header của bản này (kể cả `key_changed_at`) được xác thực.
            let Ok(data) = raw.decrypt_body(&key) else {
                continue;
            };
            let (main_data, used) = match decrypt_with_keys(&main, &key, &data) {
                Ok(x) => x,
                // Phần thân của file chính xác thực được bằng khoá này nhưng nội dung hỏng.
                Err(Error::BadFormat | Error::Json) => {
                    main_proven_damaged = true;
                    continue;
                }
                Err(_) => {
                    // Header của file chính bị đổi sau khi ghi (phần thân nhận header làm AAD): thử
                    // xác thực phần thân của nó với header thật của bản này.
                    if crypto::open(&key, &main.body_nonce, main.body_ct, raw.aad).is_ok() {
                        main_proven_damaged = true;
                    }
                    continue;
                }
            };
            let main_fp = fingerprint(main_bytes);
            let mut v = Vault::assemble(
                path.to_path_buf(),
                raw.header.clone(),
                key,
                data,
                Some(main_fp),
                true,
                opts.allow_weak_kdf,
            );
            match used {
                KeyUsed::Current => {
                    merge_versioned(&mut v.data, &main_data, main.version);
                }
                KeyUsed::Retired => v.queue_old_key_archive(main_fp, main_bytes),
            }
            return Ok(v);
        }
        Err(if main_proven_damaged {
            Error::VaultFileDamaged
        } else {
            Error::Decrypt
        })
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
    /// Giới hạn 40 bản chỉ tính những bản THÊM được gì đó vào kết quả (gốc tính là một): file rác
    /// (không giải mã được), bản trùng từng byte với bản đã gộp, hay bản cũ không thêm gì đều không
    /// chiếm chỗ của các bản thật. File lớn hơn [`fsutil::MAX_VAULT_FILE`] bị bỏ qua.
    ///
    /// Nếu gốc cũ hơn lần đổi mật khẩu mới nhất mà thư mục sao lưu ghi nhận (`password` là mật khẩu
    /// CŨ) thì trả về [`Error::OlderPasswordBackups`] — dựng lại từ đó sẽ đưa kho về mật khẩu cũ và
    /// làm mất các thay đổi sau lần đổi. Chỉ khi chủ kho chọn rõ ràng (`allow_older`) mới làm vậy.
    /// Cũng vậy khi `password` chỉ mở được các bản `pre_change` mà một gói khoá khác tự khai là mới
    /// hơn; nếu không có gói nào như thế thì là [`Error::OnlyPreChangeBackups`].
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
        const MAX_PASSWORD_ATTEMPTS: usize = 5; // mỗi gói khoá tốn một lượt Argon2
        const MAX_FILES_MERGED: usize = 40;
        let path = path.as_ref().to_path_buf();
        // (xếp mới nhất trước)
        let candidates: Vec<(BackupFile, Header)> = fsutil::list_backups(&path)
            .into_iter()
            .filter(|b| !matches!(b.kind, BackupKind::Damaged | BackupKind::OldKey))
            .filter_map(|b| header_of(&b.path).map(|h| (b, h)))
            .collect();
        // Nhóm theo "gói khoá" (vault_id + tham số KDF + muối + khoá đã gói). `key_changed_at` KHÔNG
        // thuộc gói khoá và chưa được xác thực ở bước này: ai có quyền ghi cũng chép được một header
        // thật rồi sửa con số đó. Mỗi gói khoá chỉ tốn một lượt Argon2.
        let mut wraps: Vec<&Header> = Vec::new();
        for (_, h) in &candidates {
            if !wraps.iter().any(|w| w.same_wrap(h)) {
                wraps.push(h);
            }
        }
        // Thứ tự thử: kho mà file chính (nếu còn đọc được header) thuộc về trước, rồi gói khoá có
        // lần đổi mật khẩu chính (tự khai) mới nhất trước.
        let main_id = header_of(&path).map(|h| h.vault_id);
        let claimed = |w: &Header| {
            candidates
                .iter()
                .filter(|(_, h)| h.same_wrap(w))
                .map(|(_, h)| h.key_changed_at)
                .max()
                .unwrap_or(w.key_changed_at)
        };
        wraps.sort_by_key(|w| {
            (
                main_id.as_deref() != Some(w.vault_id.as_str()),
                std::cmp::Reverse(claimed(w)),
            )
        });
        // Có bản sao lưu của cùng kho, dùng gói khoá KHÁC `h`, tự khai là mới hơn `h`: rất có thể mật
        // khẩu vừa nhập là mật khẩu CŨ. Con số đó chưa được xác thực (ta không có khoá của bản ấy),
        // nên đây chỉ là lý do để DỪNG và hỏi lại chủ kho, không phải kết luận.
        let newer_elsewhere = |h: &Header| {
            candidates.iter().any(|(_, o)| {
                o.vault_id == h.vault_id && !o.same_wrap(h) && o.key_changed_at > h.key_changed_at
            })
        };
        let mut last_err = Error::NoUsableBackup;
        // Gốc = bản MỚI NHẤT mà phần thân giải mã được bằng khoá mở ra từ chính header của nó. Phần
        // thân nhận header làm dữ liệu xác thực (AAD), nên header của gốc — kể cả `key_changed_at`
        // — là header thật, không phải một bản chép bị sửa.
        // (header, khoá, dữ liệu, (SHA-256, thời điểm) của file gốc nếu dữ liệu của nó đã được lấy)
        type Base = (Header, Key, VaultData, Option<([u8; 32], i64)>);
        let mut base: Option<Base> = None;
        // Gốc chỉ còn là bản có từ trước lần đổi mật khẩu (xem `Header::pre_change`).
        let mut base_is_pre_change = false;
        for w in wraps.into_iter().take(MAX_PASSWORD_ATTEMPTS) {
            let key = match w.unwrap_key(password, opts.allow_weak_kdf) {
                Ok(k) => k,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            // Bản đầu tiên (mới nhất) giải mã được và không mang dấu `pre_change`. Không giới hạn số
            // file xét: file rác mang tên "mới nhất" không được đẩy bản thật ra ngoài.
            let mut first_pre_change: Option<Header> = None;
            let mut trusted: Option<Base> = None;
            for (b, _) in candidates.iter().filter(|(_, h)| h.same_wrap(w)) {
                let Some(bytes) = read_copy(&b.path) else {
                    continue;
                };
                let Ok(raw) = format::parse(&bytes) else {
                    continue;
                };
                let Ok(data) = raw.decrypt_body(&key) else {
                    continue;
                };
                if raw.header.pre_change {
                    first_pre_change.get_or_insert_with(|| raw.header.clone());
                    continue;
                }
                let origin = Some((fingerprint(&bytes), b.timestamp));
                trusted = Some((raw.header.clone(), key.clone(), data, origin));
                break;
            }
            if trusted.is_some() {
                base = trusted;
                break;
            }
            if let Some(mut header) = first_pre_change {
                // Mật khẩu mở được, nhưng chỉ còn các bản có từ trước lần đổi mật khẩu: không tự dùng.
                // Nếu một gói khoá khác tự khai là mới hơn thì rất có thể đây là mật khẩu CŨ — đừng
                // để người gọi nói với chủ kho rằng "mật khẩu đúng, các bản mới hơn đã mất".
                if !allow_older {
                    return Err(if newer_elsewhere(&header) {
                        Error::OlderPasswordBackups
                    } else {
                        Error::OnlyPreChangeBackups
                    });
                }
                header.pre_change = false;
                base = Some((header, key, VaultData::default(), None));
                base_is_pre_change = true;
                break;
            }
            // Mở được gói khoá mà không bản nào giải mã được: nhóm này chỉ còn file hỏng.
            last_err = Error::NoUsableBackup;
        }
        let Some((header, key, mut data, origin)) = base else {
            return Err(last_err);
        };
        if !allow_older && newer_elsewhere(&header) {
            return Err(Error::OlderPasswordBackups);
        }
        // Gốc tính là một bản đã dùng; SHA-256 của mọi bản đã gộp để bỏ qua bản trùng từng byte.
        let mut merged: Vec<[u8; 32]> = Vec::new();
        let (mut used, mut newest) = (0usize, 0i64);
        if let Some((fp, ts)) = origin {
            merged.push(fp);
            used = 1;
            newest = ts;
        }
        for (b, _) in candidates
            .iter()
            .filter(|(_, h)| h.vault_id == header.vault_id)
        {
            if used >= MAX_FILES_MERGED {
                break;
            }
            // Chỉ nhận đúng khoá gốc: bản ghi bằng khoá cũ / khoá lạ trong thư mục đồng bộ không
            // được tự gộp (xem quy tắc ở đầu file).
            let Some(bytes) = read_copy(&b.path) else {
                continue;
            };
            let fp = fingerprint(&bytes);
            if merged.contains(&fp) {
                continue;
            }
            let Ok(raw) = format::parse(&bytes) else {
                continue;
            };
            // Bản có từ trước lần đổi mật khẩu chỉ được dùng khi chính gốc cũng là bản như vậy (chủ
            // kho đã chọn rõ ràng); còn bản đáng tin nào thì không bao giờ trộn chúng vào.
            if raw.header.pre_change && !base_is_pre_change {
                continue;
            }
            let Ok(d) = raw.decrypt_body(&key) else {
                continue;
            };
            merged.push(fp);
            let before = data.clone();
            data.merge_from(&d);
            // Bản không thêm được gì (ví dụ một bản sao lưu cũ bị chép ra nhiều bản mang tên "mới
            // nhất") không tính vào giới hạn.
            if data != before || used == 0 {
                used += 1;
                newest = newest.max(b.timestamp);
            }
        }
        if used == 0 {
            return Err(Error::NoUsableBackup);
        }
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
        v.opened_version = u.version;
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
        let (remote, adopt, version) = match self.decrypt_same_vault(bytes)? {
            Decrypted::Current {
                data,
                adopt_header,
                version,
            } => (data, adopt_header, version),
            Decrypted::Retired { .. } => {
                self.disk_fingerprint = Some(fp);
                return Ok(false);
            }
        };
        let before = self.data.clone();
        merge_versioned(&mut self.data, &remote, version);
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

    /// Phiên bản định dạng của file kho chính như lúc mở khoá (1 = do bản app 0.1.x ghi). Không
    /// theo dõi các lần đọc sau đó. Kho tạo mới / dựng lại từ sao lưu: [`format::VERSION`].
    pub fn opened_version(&self) -> u16 {
        self.opened_version
    }

    /// Niêm phong một khối nhỏ (ví dụ bản nháp chưa lưu) để cất trong thư mục RIÊNG của app trên máy
    /// này: XChaCha20-Poly1305, nonce ngẫu nhiên, khoá con HKDF-SHA256 từ khoá kho (info =
    /// `"pwv/v1/local\0" + purpose`), AAD = `"pwv/v1/local\0" + purpose + "\0" + vault_id`.
    /// Kết quả: `"PWL1"` + nonce (24 byte) + bản mã. Mở lại bằng [`Vault::open_local`] với đúng
    /// `purpose`.
    pub fn seal_local(&self, purpose: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sub = local_subkey(&self.vault_key, purpose);
        let nonce = crypto::random_nonce();
        let ct = crypto::seal(
            &sub,
            &nonce,
            plaintext,
            &local_aad(purpose, self.vault_id()),
        )?;
        let mut out = Vec::with_capacity(LOCAL_MAGIC.len() + nonce.len() + ct.len());
        out.extend_from_slice(LOCAL_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Mở một khối do [`Vault::seal_local`] niêm phong: thử khoá kho hiện tại, rồi từng khoá cũ
    /// (khối niêm phong trước một lần đổi mật khẩu — kể cả đổi ở máy khác — vẫn mở được). Sai mục
    /// đích, của kho khác, bị sửa, cụt, rác ⇒ `None` (không bao giờ panic).
    pub fn open_local(&self, purpose: &str, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let rest = sealed.strip_prefix(LOCAL_MAGIC.as_slice())?;
        if rest.len() < crypto::NONCE_LEN + crypto::TAG_LEN {
            return None;
        }
        let (nonce, ct) = rest.split_at(crypto::NONCE_LEN);
        let nonce: [u8; crypto::NONCE_LEN] = nonce.try_into().ok()?;
        let aad = local_aad(purpose, self.vault_id());
        std::iter::once(&**self.vault_key)
            .chain(self.data.old_keys.iter().map(|k| &k.key))
            .find_map(|k| {
                let sub = local_subkey(k, purpose);
                crypto::open(&sub, &nonce, ct, &aad).ok()
            })
    }

    /// Số bản sao lưu (tự động / bản xung đột đã gộp; tối đa 300 bản mới nhất; bỏ qua `oldkey-…`,
    /// `damaged-…`) của kho này mà phần thân giải mã được bằng KHOÁ KHO HIỆN TẠI nhưng header dùng
    /// một gói khoá khác (không mang dấu `pre_change`): tức là một master password KHÁC mật khẩu
    /// hiện tại (thường là mật khẩu đã đổi bằng bản app 0.1.x, vốn đổi mật khẩu mà giữ nguyên khoá)
    /// vẫn mở ra được khoá hiện tại từ các bản đó. Khác 0 ⇒ nên mời chủ kho đổi master password một
    /// lần (đổi mật khẩu sinh khoá mới và mã hoá lại các bản này).
    ///
    /// Không chạy Argon2 (chỉ giải mã phần thân). File lỗi đọc riêng lẻ bị bỏ qua; không đọc được
    /// thư mục sao lưu ⇒ lỗi (không có thư mục ⇒ 0).
    pub fn backups_under_other_password(&self) -> Result<usize> {
        const MAX_SCANNED: usize = 300;
        match fs::read_dir(fsutil::backup_dir(&self.path)) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        }
        let n = fsutil::list_backups(&self.path)
            .into_iter()
            .filter(|b| matches!(b.kind, BackupKind::Auto | BackupKind::Merged))
            .take(MAX_SCANNED)
            .filter(|b| {
                let Some(h) = header_of(&b.path) else {
                    return false;
                };
                if h.vault_id != self.header.vault_id || h.same_wrap(&self.header) || h.pre_change {
                    return false;
                }
                read_copy(&b.path).is_some_and(|bytes| {
                    format::parse(&bytes).is_ok_and(|raw| {
                        !raw.header.pre_change && raw.decrypt_body(&self.vault_key).is_ok()
                    })
                })
            })
            .count();
        Ok(n)
    }

    /// Bản sao khoá giải mã có được khoá trong RAM (không bị ghi xuống pagefile) hay không.
    pub fn memory_locked(&self) -> bool {
        self.vault_key.is_locked()
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf
    }

    /// Dấu nhận dạng của khoá kho hiện tại (không bí mật, không suy ngược ra khoá được; khác 0).
    /// Máy ghi nhớ dấu này để lần mở sau biết kho có còn "nối tiếp" kho nó từng dùng hay không.
    pub fn key_tag(&self) -> u64 {
        key_tag_of(&self.header.vault_id, &self.vault_key)
    }

    /// Kho này có biết khoá mang dấu `tag` không: đó là khoá hiện tại, hoặc một khoá cũ nằm trong
    /// phần đã mã hoá. Người chỉ biết một mật khẩu chính CŨ không thể làm ra một kho "biết" khoá mà
    /// máy này dùng lần trước (họ không có khoá đó).
    pub fn knows_key_tag(&self, tag: u64) -> bool {
        tag == self.key_tag()
            || self
                .data
                .old_keys
                .iter()
                .any(|k| key_tag_of(&self.header.vault_id, &k.key) == tag)
    }

    /// So kho đang mở với mốc mà máy này đã ghi nhận trong `config`: file cũ hơn bản từng thấy,
    /// dùng mật khẩu chính cũ hơn, hoặc dùng một khoá KHÔNG nối tiếp từ khoá máy này dùng lần trước.
    pub fn rollback_against(&self, config: &Config) -> Option<Rollback> {
        let seen = config.seen_key_tag(self.vault_id());
        let key_known = seen == 0 || self.knows_key_tag(seen);
        config.rollback_of(
            self.vault_id(),
            self.modified_at(),
            self.key_changed_at(),
            key_known,
        )
    }

    /// Ghi nhận trạng thái hiện tại vào mốc "đã thấy" (các mốc chỉ tăng). Dấu khoá chỉ được cập
    /// nhật khi khoá hiện tại nối tiếp khoá đã ghi nhận — nếu không, cảnh báo phải còn nguyên cho
    /// tới khi chủ kho chấp nhận ([`Vault::accept_as_seen`]). Trả về true nếu `config` thay đổi.
    ///
    /// Nếu kho này nằm đúng ở đường dẫn kho đang cấu hình (`config.vault`) thì `vault_id` của nó cũng
    /// được ghi vào `config.last_vault_id`.
    pub fn note_seen_in(&self, config: &mut Config) -> bool {
        let seen = config.seen_key_tag(self.vault_id());
        let key_known = seen == 0 || self.knows_key_tag(seen);
        let changed = config.note_seen(
            self.vault_id(),
            self.modified_at(),
            self.key_changed_at(),
            if key_known { self.key_tag() } else { 0 },
        );
        config.note_last_vault(&self.path, self.vault_id()) || changed
    }

    /// Chủ kho đã biết và chấp nhận trạng thái hiện tại (vừa khôi phục từ sao lưu, hoặc đã đọc
    /// cảnh báo): lấy nó làm mốc mới.
    /// Như [`Vault::note_seen_in`], cũng ghi `config.last_vault_id`.
    pub fn accept_as_seen(&self, config: &mut Config) {
        config.set_seen(
            self.vault_id(),
            self.modified_at(),
            self.key_changed_at(),
            self.key_tag(),
        );
        config.note_last_vault(&self.path, self.vault_id());
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

    /// Thêm một mục vừa nhập từ file CSV, trả về id. Khác [`Vault::add`]: các trường mang thời điểm
    /// [`crate::model::IMPORTED_AT`] nên thua mọi lần sửa thật — nhập lại cùng file CSV trên một máy
    /// chưa đồng bộ không đè lên các thay đổi đã làm ở máy khác.
    pub fn add_imported(&mut self, entry: Entry) -> String {
        self.dirty = true;
        self.data.add_imported_at(entry, now_ms())
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

    /// Xoá vĩnh viễn ĐÚNG các mục có id trong `ids` và đang nằm trong thùng rác. Mục khác trong thùng
    /// rác — ví dụ vừa được máy khác chuyển vào sau khi chủ kho xem danh sách và bấm xác nhận — không
    /// bị đụng tới. Trả về số mục đã xoá.
    pub fn purge_trashed(&mut self, ids: &[String]) -> usize {
        let now = now_ms();
        let mut n = 0;
        for id in ids {
            if self.data.get_trashed(id).is_some() && self.data.purge_at(id, now).is_ok() {
                n += 1;
            }
        }
        if n > 0 {
            self.dirty = true;
        }
        n
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
                version: raw.version,
            }),
            Ok((data, KeyUsed::Retired)) => Ok(Decrypted::Retired {
                data,
                version: raw.version,
            }),
            Err(Error::Decrypt) if newer_epoch => Err(Error::PasswordChangedElsewhere),
            Err(Error::Decrypt) | Err(Error::BadFormat) | Err(Error::Json) => {
                Err(Error::VaultFileDamaged)
            }
            Err(e) => Err(e),
        }
    }

    /// Ghi nhớ một bản chỉ mở được bằng khoá cũ để cất nó (nguyên văn) trước lần ghi kế tiếp.
    fn queue_old_key_archive(&mut self, fp: [u8; 32], bytes: &[u8]) {
        if self.pending_old_keys.iter().all(|p| p.fp != fp) {
            self.pending_old_keys.push(PendingOldKey {
                fp,
                origin: self.path.clone(),
                bytes: bytes.to_vec(),
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
            match fsutil::read_retry_capped(&self.path, fsutil::MAX_VAULT_FILE) {
                Ok(Some(b)) => break b,
                // File khổng lồ ở chỗ file kho: không đọc vào RAM, coi như file hỏng.
                Ok(None) => return Err(Error::VaultFileDamaged),
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
        let (remote, adopt, version) = match self.decrypt_same_vault(&bytes)? {
            Decrypted::Current {
                data,
                adopt_header,
                version,
            } => (data, adopt_header, version),
            Decrypted::Retired { .. } => {
                self.queue_old_key_archive(fp, &bytes);
                self.disk_fingerprint = Some(fp);
                return Ok(Refreshed::default());
            }
        };
        let disk_header = format::peek_header(&bytes)?;
        let stats = merge_versioned(&mut self.data, &remote, version);
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

    /// Cất NGUYÊN VĂN (xem [`PendingOldKey`]) các bản chỉ mở được bằng khoá cũ đang chờ.
    /// Lỗi ⇒ trả lỗi: không được ghi đè file kho khi bản có thể là duy nhất chứa thay đổi chưa gộp
    /// của một máy khác còn chưa được cất an toàn.
    fn archive_pending_old_keys(&mut self) -> Result<usize> {
        let mut n = 0;
        for i in 0..self.pending_old_keys.len() {
            let p = &self.pending_old_keys[i];
            if self.archived_old_keys.contains(&p.fp) {
                continue;
            }
            fsutil::write_archive(
                &self.path,
                BackupKind::OldKey,
                now_ms(),
                &p.origin,
                &p.bytes,
            )?;
            let fp = p.fp;
            self.archived_old_keys.push(fp);
            n += 1;
        }
        Ok(n)
    }

    /// Ghi bản trong RAM ra đĩa (nguyên tử, có đọc lại kiểm tra) và giữ sao lưu:
    ///
    /// - TRƯỚC khi ghi: bản ghi bằng khoá cũ đang chờ (xem `refresh`) được cất nguyên văn (`oldkey-…`).
    /// - TRƯỚC khi ghi (`keep_previous`): nếu nội dung đang nằm trên đĩa chưa chắc đã có trong thư
    ///   mục sao lưu (do máy khác / bản app cũ ghi, hoặc là lần ghi đầu của phiên) thì chép nó lại —
    ///   trừ khi đó là bản ghi bằng khoá cũ (đã được cất ở bước trên; chép thêm một bản mang tên
    ///   "tự động" chỉ làm nó trông như một bản sao lưu bình thường).
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
        read_capped(&self.path)
    }

    /// File vừa ghi có đúng là `bytes` không. Đọc lại; sai/lỗi ⇒ chờ một chút rồi đọc lại lần nữa
    /// (dịch vụ đồng bộ / diệt virus thường chỉ giữ file trong chốc lát); vẫn sai ⇒ ghi lại một lần
    /// nữa rồi kiểm tra. Không ghi lại nếu thứ đọc được là một file hợp lệ của kho này mà máy khác vừa
    /// ghi (đè lên là làm mất nó khỏi file kho) — lần đọc sau sẽ gộp nó như bình thường.
    fn verify_written(&self, bytes: &[u8]) -> bool {
        let first = self.read_back();
        if first.as_ref().is_ok_and(|b| b == bytes) {
            return true;
        }
        // Ở BẤT KỲ lần đọc lại nào mà thấy file của máy khác thì không ghi lại nữa (lần đọc thứ
        // hai có thể lỗi vì dịch vụ đồng bộ đang giữ chính file đó).
        let mut foreign = first
            .as_ref()
            .is_ok_and(|b| self.written_by_someone_else(b));
        std::thread::sleep(Duration::from_millis(200));
        match self.read_back() {
            Ok(b) if b == bytes => return true,
            Ok(b) if self.written_by_someone_else(&b) => foreign = true,
            _ => {}
        }
        if foreign {
            return false;
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
        fsutil::prune_backups(&self.path, |p| self.is_same_vault_file(p));
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
                let fp = fingerprint(&bytes);
                // Bản trong RAM là bản tốt DUY NHẤT: chép nó vào thư mục sao lưu TRƯỚC khi ghi
                // (`write_new` ghi thẳng vào tên cuối — mất điện giữa chừng thì file kho dở dang).
                if fsutil::backup_bytes(&self.path, now_ms(), &bytes).is_ok() {
                    self.backed_up = Some(fp);
                }
                fsutil::write_new(&self.path, &bytes)?;
                self.pending_old_keys.clear();
                self.archived_old_keys.clear();
                if !self.read_back().is_ok_and(|b| b == bytes) {
                    self.disk_fingerprint = None;
                    self.dirty = true;
                    return Err(Error::WriteVerifyFailed);
                }
                self.disk_fingerprint = Some(fp);
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
        // Khoá sắp bị thay. Bản sao lưu nào mở được bằng ĐÚNG khoá này thì chắc chắn do người có
        // khoá hiện tại ghi ra ⇒ được mã hoá lại tại chỗ (xem `reencrypt_backups`).
        let retiring: Key = Zeroizing::new(**self.vault_key);
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
        let mut report = self.reencrypt_backups(&retiring);
        report.save = save;
        Ok(report)
    }

    /// Ngay sau khi đổi master password: mã hoá lại các file trong thư mục sao lưu bằng khoá + mật
    /// khẩu hiện tại — CHỈ những file mở được bằng `retiring` (khoá vừa bị thay ở chính lần đổi này)
    /// hoặc bằng khoá hiện tại — và gắn cho chúng dấu `Header::pre_change`.
    ///
    /// Vì sao phải gắn dấu: trước lần đổi, người biết mật khẩu (sắp thành) cũ có đủ khoá để đặt vào
    /// thư mục sao lưu một file do họ tự làm. Mã hoá lại file ấy thành một bản sao lưu bình thường là
    /// trao cho nó sự tin cậy của khoá mới — lần khôi phục sau sẽ gộp nó vào kho. Có dấu thì mọi thứ
    /// có từ trước lần đổi vĩnh viễn là "lịch sử để xem": mật khẩu cũ không đọc được nó nữa, chủ kho
    /// vẫn xem và khôi phục từng mục được, nhưng app không bao giờ tự dùng nó.
    ///
    /// File chỉ mở được bằng một khoá cũ HƠN nữa thì để nguyên (tính vào `backups_skipped`). Thư mục
    /// sao lưu nằm trong thư mục đồng bộ, nên người biết một mật khẩu chính CŨ có thể đặt vào đó
    /// một file do họ tự mã hoá bằng khoá cũ; nếu file ấy được mã hoá lại bằng khoá hiện tại thì nó
    /// trở thành "bản sao lưu đáng tin" và lần khôi phục sau sẽ gộp nó vào kho. Vì vậy không có chỗ
    /// nào khác mã hoá lại bản sao lưu: file ghi bằng khoá cũ mãi là "bản ghi bằng khoá cũ" — chủ kho
    /// vẫn xem và khôi phục từng mục từ nó được ([`Vault::read_backup`]), nhưng nó không bao giờ được
    /// tự gộp.
    ///
    /// Mỗi bản được đánh dấu cũng nhận mọi khoá trong `old_keys` của kho hiện tại (kể cả khoá vừa bị
    /// thay): kho dựng lại từ CHỈ các bản này (chủ kho chọn rõ ràng) vẫn đọc được các file của thời
    /// khoá cũ (`oldkey-…`, file của máy chưa biết lần đổi) thay vì coi chúng là file hỏng.
    ///
    /// Bản đọc được mà ghi lại thất bại được thử lại một lần ở cuối; vẫn thất bại ⇒ tên file vào
    /// `backups_failed` (chúng vẫn mở được bằng mật khẩu vừa bị thay).
    fn reencrypt_backups(&self, retiring: &Key) -> PasswordChangeReport {
        let mut report = PasswordChangeReport::default();
        let mut failed: Vec<BackupFile> = Vec::new();
        for b in fsutil::list_backups(&self.path) {
            match self.reencrypt_one(&b, retiring) {
                Reencrypt::Done => report.backups_reencrypted += 1,
                Reencrypt::Skipped => report.backups_skipped += 1,
                Reencrypt::Ignored => {}
                Reencrypt::WriteFailed => failed.push(b),
            }
        }
        for b in failed {
            match self.reencrypt_one(&b, retiring) {
                Reencrypt::Done => report.backups_reencrypted += 1,
                Reencrypt::Skipped => report.backups_skipped += 1,
                Reencrypt::Ignored => {}
                Reencrypt::WriteFailed => report.backups_failed.push(
                    b.path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                ),
            }
        }
        report
    }

    fn reencrypt_one(&self, b: &BackupFile, retiring: &Key) -> Reencrypt {
        // File hỏng đã cất (`damaged-…`) vốn không giải mã được bằng bất kỳ mật khẩu nào: bỏ qua,
        // không tính vào số "chưa mã hoá lại được".
        let unreadable = if b.kind == BackupKind::Damaged {
            Reencrypt::Ignored
        } else {
            Reencrypt::Skipped
        };
        let Ok(bytes) = fsutil::read_retry(&b.path) else {
            return unreadable;
        };
        let Ok(raw) = format::parse(&bytes) else {
            return unreadable;
        };
        // File của kho khác, hoặc đã dùng header hiện tại (bản sao lưu của chính lần ghi đổi mật
        // khẩu, hay bản đã được đánh dấu ở một lần chạy trước).
        let current = raw.header.same_wrap(&self.header)
            && raw.header.key_changed_at == self.header.key_changed_at;
        if raw.header.vault_id != self.header.vault_id || current {
            return Reencrypt::Ignored;
        }
        let Ok(mut data) = raw
            .decrypt_body(&self.vault_key)
            .or_else(|_| raw.decrypt_body(retiring))
        else {
            return unreadable;
        };
        for k in &self.data.old_keys {
            data.push_old_key(&k.key, k.retired_at);
        }
        let marked = Header {
            pre_change: true,
            ..self.header.clone()
        };
        let written = format::serialize(&marked, &data, &self.vault_key).and_then(|out| {
            reencrypt_write_fault()?;
            fsutil::atomic_write(&b.path, &out)
        });
        match written {
            Ok(()) => Reencrypt::Done,
            Err(_) => Reencrypt::WriteFailed,
        }
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
        Self::same_vault_siblings(&self.path, &self.header.vault_id)
            .into_iter()
            .map(|(p, _)| p)
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
    fn merge_remote(
        &mut self,
        remote: &VaultData,
        adopt: Option<Header>,
        version: u16,
    ) -> (MergeStats, bool) {
        let before = self.data.clone();
        let stats = merge_versioned(&mut self.data, remote, version);
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
        let unchanged = read_capped(path).is_ok_and(|b| fingerprint(&b) == fp);
        unchanged && fsutil::archive_file(&self.path, kind, now_ms(), path).is_ok()
    }

    /// Đồng bộ với thư mục: nạp thay đổi của máy khác, gộp các bản xung đột, **ghi lại file kho nếu
    /// bản trong RAM có thứ mà file trên đĩa không có**, rồi mới cất các bản xung đột đã gộp vào
    /// thư mục sao lưu (không bao giờ cất trước khi kho đã được ghi thành công, và chỉ cất nếu file
    /// vẫn đúng là bản đã gộp).
    ///
    /// Với từng bản cạnh kho:
    /// - mở được bằng khoá hiện tại ⇒ gộp, rồi cất (`merged-…`);
    /// - chỉ mở được bằng khoá cũ ⇒ KHÔNG gộp; chuyển nó NGUYÊN VĂN vào thư mục sao lưu
    ///   (`oldkey-…`), báo [`Error::RetiredKeyCopy`];
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
        let mut retired: Vec<(PathBuf, [u8; 32])> = Vec::new();
        for path in self.conflict_copies() {
            let bytes = match read_capped(&path) {
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
                Ok(Decrypted::Current {
                    data,
                    adopt_header,
                    version,
                }) => {
                    let (stats, adopted) = self.merge_remote(&data, adopt_header, version);
                    report.adopted_remote_password |= adopted;
                    merged.push((report.conflicts.len(), fp));
                    Ok(stats)
                }
                Ok(Decrypted::Retired { .. }) => {
                    retired.push((path, fp));
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
        for (path, fp) in retired {
            let archived = self.archive_if_unchanged(&path, fp, BackupKind::OldKey);
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
        self.read_backup_checked(path).map(|(d, _)| d)
    }

    /// Như [`Vault::read_backup`], kèm cờ `true` nếu bản này CHỈ mở được bằng khoá của một mật khẩu
    /// chính cũ. Bản như vậy có thể là bản sao lưu thật từ trước lần đổi mật khẩu, nhưng cũng có thể
    /// do người biết mật khẩu cũ đặt vào thư mục sao lưu — giao diện phải nói rõ điều đó trước khi
    /// chủ kho khôi phục mục nào từ nó.
    pub fn read_backup_checked(&self, path: &Path) -> Result<(VaultData, bool)> {
        if !fsutil::is_within(path, &fsutil::backup_dir(&self.path)) {
            return Err(Error::BadFormat);
        }
        let bytes = read_capped(path)?;
        let raw = format::parse(&bytes)?;
        if raw.header.vault_id != self.header.vault_id {
            return Err(Error::DifferentVault);
        }
        decrypt_with_keys(&raw, &self.vault_key, &self.data)
            .map(|(d, used)| (d, used == KeyUsed::Retired))
    }

    // ------------------------------------------------------------------ chuyển kho

    fn file_matches_memory(&self, path: &Path) -> bool {
        read_capped(path).ok().is_some_and(|b| {
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
        self.relocate(new_path.as_ref(), false)
    }

    /// "Lưu bản đang mở ra chỗ khác" (ví dụ từ thông báo "file kho có vấn đề"): ghi bản đang mở ra
    /// `new_path`, đọc lại và giải mã thử, rồi chuyển kho sang dùng file mới. KHÔNG BAO GIỜ đụng tới
    /// bất cứ thứ gì ở chỗ cũ — không ghi file kho cũ, không cất bản xung đột, không chuyển thư mục
    /// sao lưu, không xoá file cũ — dù lúc đó file cũ có đọc được trở lại hay không.
    ///
    /// Trước khi ghi, file ở chỗ cũ được ĐỌC và gộp vào (chỉ khi mở được bằng khoá hiện tại); đọc
    /// không được thì dùng đúng bản trong RAM. [`MoveReport::rescued`] luôn là `true`.
    pub fn copy_to(&mut self, new_path: impl AsRef<Path>) -> Result<MoveReport> {
        self.relocate(new_path.as_ref(), true)
    }

    fn relocate(&mut self, new_path: &Path, copy_only: bool) -> Result<MoveReport> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let new_path = std::path::absolute(new_path)?;
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
        if copy_only {
            // Chỉ ĐỌC chỗ cũ (gộp nếu được); lỗi gì cũng cứu đúng bản trong RAM.
            report.rescued = true;
            let _ = self.refresh();
        } else {
            self.sync_before_move(&mut report)?;
        }
        let left_behind = self.disk_fingerprint;

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
        test_hook("move:before-delete");
        report.old_removed = self.remove_old_location(&old_path, left_behind);
        Ok(report)
    }

    /// Bước 1 của [`Vault::move_to`]: đồng bộ chỗ cũ. File ở chỗ cũ không dùng được nữa ⇒ đánh dấu
    /// "cứu" (chỉ ghi bản mới); lỗi khác ⇒ huỷ chuyển.
    fn sync_before_move(&mut self, report: &mut MoveReport) -> Result<()> {
        match self.sync() {
            Ok(s) => {
                report.conflicts_merged = s.conflicts.iter().filter(|c| c.result.is_ok()).count();
            }
            // File ở chỗ cũ thật sự không dùng được nữa ⇒ "cứu" bản đang mở sang chỗ mới.
            Err(
                Error::VaultFileMissing(_)
                | Error::VaultFileDamaged
                | Error::DifferentVault
                | Error::UnsupportedVersion(_),
            ) => report.rescued = true,
            // Mọi lỗi khác (đọc/ghi tạm thời, đĩa đầy, máy khác đã đổi mật khẩu…): HUỶ chuyển. Nếu
            // cứ "cứu" thì sẽ có hai file kho cùng sống ở hai thư mục, lặng lẽ tách nhau ra.
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Bước cuối của [`Vault::move_to`]: xoá file ở chỗ cũ — chỉ khi nó vẫn đúng là thứ bước 1 để lại
    /// (`left_behind`). Máy khác có thể đã ghi vào đó trong lúc chuyển (chép thư mục sao lưu sang ổ
    /// khác mất vài giây): khi đó gộp nó (chỉ nhận khoá hiện tại) vào kho ở chỗ mới và lưu, rồi mới
    /// xoá. Bất kỳ bước nào không chắc chắn ⇒ để nguyên file cũ (trả về false).
    fn remove_old_location(&mut self, old: &Path, left_behind: Option<[u8; 32]>) -> bool {
        let Ok(bytes) = read_capped(old) else {
            return false;
        };
        let fp = fingerprint(&bytes);
        if Some(fp) != left_behind {
            let Ok(Decrypted::Current {
                data,
                adopt_header,
                version,
            }) = self.decrypt_same_vault(&bytes)
            else {
                return false;
            };
            self.merge_remote(&data, adopt_header, version);
            if self.dirty && self.save().is_err() {
                return false;
            }
            // Lại vừa bị ghi nữa: để lần sau.
            if read_capped(old).ok().map(|b| fingerprint(&b)) != Some(fp) {
                return false;
            }
        }
        // Kiểm tra bản mới thêm một lần nữa ngay trước khi xoá bản cũ.
        let new_path = self.path.clone();
        self.file_matches_memory(&new_path) && fsutil::retry(|| fs::remove_file(old)).is_ok()
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

    fn fail_readbacks(faults: Vec<std::io::Result<Vec<u8>>>) {
        READBACK_FAULTS.with(|q| *q.borrow_mut() = faults.into());
    }

    fn readback_faults_left() -> usize {
        READBACK_FAULTS.with(|q| q.borrow().len())
    }

    fn garbage() -> std::io::Result<Vec<u8>> {
        Ok(b"doc lai ra rac".to_vec())
    }

    /// Rà soát "verify-rollback": đọc lại sau khi ghi thất bại (file đã bị thay) mà vẫn hoàn tác RAM
    /// ⇒ RAM và đĩa lệch nhau. Giờ: giữ trạng thái mới, báo `unverified`, đọc/ghi lại ở lần sau.
    #[test]
    fn unverifiable_write_keeps_the_new_state_instead_of_rolling_back() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        let mut v = Vault::create(&p, PW, opts()).unwrap();
        v.transact(|v| Ok(v.add(Entry::new("A")))).unwrap();

        // Đọc lại sai cả 3 lần (lần đầu, lần đọc lại, sau khi ghi lại).
        fail_readbacks(vec![
            garbage(),
            Err(std::io::Error::other("bị khoá")),
            garbage(),
        ]);
        let (_, r) = v.transact(|v| Ok(v.add(Entry::new("B")))).unwrap();
        assert_eq!(readback_faults_left(), 0);
        assert!(r.unverified);
        assert_eq!(titles(&v), ["A", "B"], "không hoàn tác");
        assert!(v.has_unsaved_changes());
        assert_eq!(titles(&open(&p)), titles(&v));
        // Lần đồng bộ sau đọc lại file thật: đúng rồi thì không cần ghi gì.
        let r = v.sync().unwrap();
        assert!(!r.wrote && !r.unverified && !v.has_unsaved_changes());
        // Bản sao lưu mới nhất vẫn được tạo từ bản tốt.
        let newest = &fsutil::list_backups(&p)[0];
        assert_eq!(fs::read(&newest.path).unwrap(), fs::read(&p).unwrap());

        // Đọc lại sai đúng một lần (file bị giữ trong chốc lát): lần đọc lại xác minh được.
        fail_readbacks(vec![garbage()]);
        let (_, r) = v.transact(|v| Ok(v.add(Entry::new("C")))).unwrap();
        assert!(!r.unverified && !v.has_unsaved_changes());

        // Thứ đọc được là một file hợp lệ do máy khác vừa ghi: KHÔNG ghi đè lên nó.
        let other = fs::read(&p).unwrap();
        fail_readbacks(vec![Ok(other.clone()), Ok(other), garbage()]);
        let (_, r) = v.transact(|v| Ok(v.add(Entry::new("D")))).unwrap();
        assert!(r.unverified);
        assert_eq!(readback_faults_left(), 1, "không có lần ghi lại thứ hai");
        fail_readbacks(vec![]);
        assert_eq!(titles(&open(&p)), ["A", "B", "C", "D"]);
    }

    /// Đổi mật khẩu mà lần ghi không xác minh được: trước đây RAM quay về khoá cũ trong khi file đã
    /// dùng khoá mới ⇒ chủ kho bị báo "thất bại", rồi bị khoá ngoài kho.
    #[test]
    fn password_change_with_unverifiable_write_does_not_roll_back_the_key() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        let mut v = Vault::create(&p, PW, opts()).unwrap();
        v.transact(|v| Ok(v.add(Entry::new("A")))).unwrap();
        fail_readbacks(vec![garbage(), garbage(), garbage()]);
        let r = v
            .change_password(b"mat khau moi", KdfParams::INSECURE_TEST)
            .unwrap();
        assert_eq!(readback_faults_left(), 0);
        assert!(r.save.unverified);
        assert!(v.verify_password(b"mat khau moi") && !v.verify_password(PW));
        let o = OpenOptions {
            allow_weak_kdf: true,
        };
        let fresh = Vault::open_with(&p, b"mat khau moi", o).unwrap();
        assert_eq!(fresh.entries(), v.entries());
        assert!(Vault::open_with(&p, PW, o).is_err());
        // Dùng tiếp bình thường, không có "mật khẩu đã đổi ở máy khác".
        let r = v.sync().unwrap();
        assert!(!r.wrote);
        v.transact(|v| Ok(v.add(Entry::new("B")))).unwrap();
        assert_eq!(
            Vault::open_with(&p, b"mat khau moi", o)
                .unwrap()
                .entries()
                .len(),
            2
        );
    }

    /// Rà soát "move-delete-unchecked": máy khác ghi vào file ở chỗ cũ trong lúc đang chuyển kho
    /// (ví dụ đang chép thư mục sao lưu sang ổ khác). Trước đây file cũ bị xoá luôn, mất lần ghi đó.
    #[test]
    fn a_write_landing_on_the_old_file_during_a_move_is_merged_not_deleted() {
        let d = tempfile::tempdir().unwrap();
        let old = d.path().join("Documents").join("vault.pwv");
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        let mut v = Vault::create(&old, PW, opts()).unwrap();
        v.transact(|v| Ok(v.add(Entry::new("A")))).unwrap();
        let mut laptop = open(&old);
        let old2 = old.clone();
        set_hook("move:before-delete", move || {
            laptop
                .transact(|v| Ok(v.add(Entry::new("Từ laptop, giữa lúc chuyển"))))
                .unwrap();
            assert!(old2.exists());
        });
        let new = d.path().join("Dropbox").join("vault.pwv");
        let r = v.move_to(&new);
        clear_hook();
        let r = r.unwrap();
        assert!(r.old_removed && !r.rescued);
        assert!(!old.exists());
        assert_eq!(titles(&v), ["A", "Từ laptop, giữa lúc chuyển"]);
        assert_eq!(titles(&open(&new)), ["A", "Từ laptop, giữa lúc chuyển"]);
    }

    #[test]
    fn an_unmergeable_old_file_is_left_in_place_after_a_move() {
        let d = tempfile::tempdir().unwrap();
        let old = d.path().join("a").join("vault.pwv");
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        let mut v = Vault::create(&old, PW, opts()).unwrap();
        v.transact(|v| Ok(v.add(Entry::new("A")))).unwrap();
        let old2 = old.clone();
        set_hook("move:before-delete", move || {
            fs::write(&old2, b"dong bo do dang").unwrap();
        });
        let new = d.path().join("b").join("vault.pwv");
        let r = v.move_to(&new);
        clear_hook();
        let r = r.unwrap();
        assert!(!r.old_removed);
        assert_eq!(fs::read(&old).unwrap(), b"dong bo do dang");
        assert_eq!(titles(&open(&new)), ["A"]);
    }

    /// Rà soát "force-missing-nobackup": tạo lại file kho đã biến mất ghi thẳng vào tên cuối và không
    /// sao lưu ⇒ mất điện giữa chừng là mất bản tốt duy nhất (trong RAM). Giờ: sao lưu TRƯỚC, đọc
    /// lại kiểm tra SAU.
    #[test]
    fn recreating_a_missing_vault_backs_up_first_and_verifies() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        let mut v = Vault::create(&p, PW, opts()).unwrap();
        v.transact(|v| Ok(v.add(Entry::new("A")))).unwrap();
        fs::remove_file(&p).unwrap();
        let n = fsutil::list_backups(&p).len();
        assert!(v.force_write().unwrap().is_none());
        let backups = fsutil::list_backups(&p);
        assert_eq!(backups.len(), n + 1);
        assert_eq!(fs::read(&backups[0].path).unwrap(), fs::read(&p).unwrap());
        assert!(!v.has_unsaved_changes());

        // Đọc lại không khớp: báo lỗi, vẫn coi là chưa lưu.
        fs::remove_file(&p).unwrap();
        fail_readbacks(vec![garbage()]);
        assert!(matches!(v.force_write(), Err(Error::WriteVerifyFailed)));
        fail_readbacks(vec![]);
        assert!(v.has_unsaved_changes());
        assert_eq!(titles(&open(&p)), ["A"]);
        // Lần lưu sau đọc lại file thật và mọi thứ trở lại bình thường.
        v.save().unwrap();
        assert!(!v.has_unsaved_changes());
    }

    /// Rà soát core-fix-review-2#5 (2): lần đọc lại đầu thấy file hợp lệ của máy khác, lần thứ hai
    /// lỗi (dịch vụ đồng bộ đang giữ chính file đó) ⇒ không xác minh được, và KHÔNG ghi lại lần nữa.
    #[test]
    fn a_foreign_file_seen_once_is_never_overwritten_even_if_the_next_read_fails() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        let mut v = Vault::create(&p, PW, opts()).unwrap();
        v.transact(|v| Ok(v.add(Entry::new("A")))).unwrap();
        let other = fs::read(&p).unwrap();
        fail_readbacks(vec![
            Ok(other),
            Err(std::io::Error::other("bị giữ")),
            garbage(),
        ]);
        let (_, r) = v.transact(|v| Ok(v.add(Entry::new("B")))).unwrap();
        assert!(r.unverified);
        assert_eq!(
            readback_faults_left(),
            1,
            "không ghi lại, không đọc lại lần ba"
        );
        fail_readbacks(vec![]);
        assert!(v.has_unsaved_changes());
    }

    fn set_reencrypt_write_faults(n: usize) {
        REENCRYPT_WRITE_FAULTS.with(|c| c.set(n));
    }

    /// Rà soát cli-fix-review#3: bản sao lưu đọc được mà ghi lại thất bại lúc đổi mật khẩu (vẫn mở
    /// được bằng mật khẩu vừa bị thay) từng bị tính chung vào "để nguyên: không đọc được".
    #[test]
    fn reencryption_write_failures_are_retried_then_reported_by_name() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        let mut v = Vault::create(&p, PW, opts()).unwrap();
        v.transact(|v| Ok(v.add(Entry::new("A")))).unwrap();
        v.transact(|v| Ok(v.add(Entry::new("B")))).unwrap();
        // Lỗi thoáng qua: lần thử lại ở cuối thành công.
        set_reencrypt_write_faults(1);
        let r = v
            .change_password(b"moi 1", KdfParams::INSECURE_TEST)
            .unwrap();
        assert!(r.backups_failed.is_empty() && r.backups_skipped == 0);
        assert!(r.backups_reencrypted >= 2);
        // Lỗi kéo dài: tên các file được báo riêng, không tính vào `backups_skipped`.
        set_reencrypt_write_faults(usize::MAX);
        let r = v.change_password(b"moi 2", KdfParams::INSECURE_TEST);
        set_reencrypt_write_faults(0);
        let r = r.unwrap();
        assert_eq!((r.backups_reencrypted, r.backups_skipped), (0, 0));
        assert!(r.backups_failed.len() >= 2, "{:?}", r.backups_failed);
        for name in &r.backups_failed {
            let bytes = fs::read(fsutil::backup_dir(&p).join(name)).unwrap();
            let h = format::parse(&bytes).unwrap().header;
            assert!(
                h.unwrap_key(b"moi 1", true).is_ok(),
                "vẫn mở bằng mật khẩu vừa bị thay"
            );
        }
    }

    #[test]
    fn local_blobs_are_sealed_under_the_vault_key() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pwv");
        let mut v = Vault::create(&p, PW, opts()).unwrap();
        let secret = b"mat khau ngan hang vua tao: X7#kq";
        let sealed = v.seal_local("draft", secret).unwrap();
        assert!(sealed.starts_with(b"PWL1"));
        assert!(!sealed.windows(secret.len()).any(|w| w == secret));
        assert_eq!(&**v.open_local("draft", &sealed).unwrap(), secret);
        // Hai lần niêm phong khác nhau (nonce ngẫu nhiên).
        assert_ne!(v.seal_local("draft", secret).unwrap(), sealed);
        // Sai mục đích, cụt, bị sửa, rác: None.
        assert!(v.open_local("generated", &sealed).is_none());
        for n in 0..sealed.len() {
            assert!(v.open_local("draft", &sealed[..n]).is_none());
        }
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(v.open_local("draft", &bad).is_none());
        assert!(v.open_local("draft", b"").is_none());
        // Kho khác (dù cùng mật khẩu) không mở được.
        let other = Vault::create(d.path().join("khac.pwv"), PW, opts()).unwrap();
        assert!(other.open_local("draft", &sealed).is_none());
        // Niêm phong trước lần đổi mật khẩu (khoá giờ là khoá cũ) vẫn mở được.
        v.change_password(b"moi", KdfParams::INSECURE_TEST).unwrap();
        assert_eq!(&**v.open_local("draft", &sealed).unwrap(), secret);
        let after = v.seal_local("draft", secret).unwrap();
        assert_eq!(&**v.open_local("draft", &after).unwrap(), secret);
        // Cùng khoá kho nhưng vault_id khác (AAD) ⇒ không mở được.
        let mut forged = Vault::assemble(
            d.path().join("x.pwv"),
            Header {
                vault_id: "khac".into(),
                ..v.header.clone()
            },
            Zeroizing::new(**v.vault_key),
            VaultData::default(),
            None,
            false,
            true,
        );
        assert!(forged.open_local("draft", &after).is_none());
        forged.header.vault_id = v.header.vault_id.clone();
        assert!(forged.open_local("draft", &after).is_some());
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
