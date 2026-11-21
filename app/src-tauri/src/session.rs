//! Trạng thái phiên làm việc và toàn bộ logic của app, không phụ thuộc Tauri (test được).
//!
//! Nguyên tắc:
//! - Mật khẩu, secret 2FA và ghi chú **không** được gửi sang giao diện (JavaScript) trừ khi người
//!   dùng bấm "hiện". Sao chép được làm trực tiếp từ Rust vào clipboard.
//! - Mọi thao tác sửa đều là một giao dịch ([`Vault::transact`]): gộp file trên đĩa trước, ghi ngay,
//!   và nếu ghi lỗi thì hoàn tác — thứ hiện trong danh sách luôn là thứ đã nằm trên đĩa.
//! - File kho trên đĩa có vấn đề (hỏng, biến mất, bị thay bằng kho khác…) thì KHÔNG tự ghi đè:
//!   ghi nhận vào `disk_problem` để giao diện hiện cảnh báo cố định và chờ người dùng quyết định.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use pwv_generator::{
    check_master_password, estimate_strength, generate_passphrase, generate_password,
    PassphraseOptions, PasswordOptions, Strength,
};
use pwv_health::BreachQuery;
use pwv_vault_core::config::{
    is_uri, Config, CLIPBOARD_CLEAR_SECS_MAX, CLIPBOARD_CLEAR_SECS_MIN, MAX_AUTO_LOCK_MINUTES,
};
use pwv_vault_core::fsutil::{self, BackupKind};
use pwv_vault_core::{
    CreateOptions, Entry, Error as VaultError, KdfParams, MergeStats, OpenOptions, SaveReport,
    SyncReport, Totp, Vault,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Lỗi gửi sang giao diện: `code` để giao diện biết phải làm gì, `message` để hiện cho người dùng.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppError {
    pub code: String,
    pub message: String,
    /// Dữ liệu kèm theo cho giao diện (hiện chỉ dùng cho `older_than_seen`: hai mốc thời gian).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<ErrorDetail>,
}

/// Hai mốc thời gian (ms) đi kèm lỗi `older_than_seen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    /// Thời điểm sửa của bản vừa dựng lại.
    pub file_modified_at: i64,
    /// Thời điểm của bản mới nhất máy này từng thấy.
    pub seen_modified_at: i64,
}

impl AppError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            detail: None,
        }
    }
    fn locked() -> Self {
        Self::new("locked", "Kho đang khoá")
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for AppError {
    fn from(message: String) -> Self {
        Self::new("error", message)
    }
}

impl From<&str> for AppError {
    fn from(message: &str) -> Self {
        Self::new("error", message)
    }
}

impl From<VaultError> for AppError {
    fn from(e: VaultError) -> Self {
        let code = match &e {
            VaultError::Decrypt => "wrong_password",
            VaultError::PasswordChangedElsewhere => "password_changed",
            VaultError::VaultFileMissing(_) => "file_missing",
            VaultError::VaultFileDamaged | VaultError::BadFormat | VaultError::Json => {
                "file_damaged"
            }
            VaultError::UnsupportedVersion(_) => "unsupported_version",
            VaultError::DifferentVault => "different_vault",
            VaultError::ReadOnly => "read_only",
            VaultError::EntryNotFound(_) => "not_found",
            // Khôi phục từ sao lưu: mật khẩu vừa nhập là mật khẩu chính CŨ ⇒ giao diện giải thích và
            // chỉ khôi phục từ các bản cũ khi chủ kho chọn rõ ràng.
            VaultError::OlderPasswordBackups => "older_password",
            VaultError::OnlyPreChangeBackups => "old_backups_only",
            VaultError::NoUsableBackup => "no_backup",
            VaultError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => "file_missing",
            _ => "error",
        };
        Self::new(code, e.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

fn err<E: std::fmt::Display>(e: E) -> AppError {
    AppError::new("error", e.to_string())
}

/// Cấu hình làm nền cho một lần ghi: bản trên đĩa (`disk` = nội dung config.json) nếu đọc được,
/// nếu không thì bản trong RAM.
///
/// Vì sao: CLI (hoặc một lần chạy app khác) có thể đã sửa config.json trong lúc app đang mở — đổi
/// vị trí kho, cài đặt, mốc "đã thấy". Nếu app ghi lại nguyên bản nó nạp lúc khởi động thì những thay
/// đổi đó mất. File không có / hỏng thì dùng bản trong RAM (giữ được vị trí kho đang dùng thay vì
/// ghi đè bằng cấu hình mặc định).
fn config_base(disk: Option<&[u8]>, mem: &Config) -> Config {
    match disk.and_then(|b| serde_json::from_slice::<Config>(b).ok()) {
        Some(mut c) => {
            c.sanitize();
            c
        }
        None => mem.clone(),
    }
}

/// Ghi MỘT thay đổi vào cấu hình: đọc lại config.json → áp `change` → ghi → giữ kết quả trong RAM.
/// `persist == false` (test): chỉ áp vào bản trong RAM.
fn update_config_in(
    config: &mut Config,
    persist: bool,
    change: impl FnOnce(&mut Config),
) -> AppResult<()> {
    if !persist {
        change(config);
        return Ok(());
    }
    let disk = Config::file().and_then(|f| std::fs::read(f).ok());
    let mut fresh = config_base(disk.as_deref(), config);
    change(&mut fresh);
    // Giữ kết quả trong RAM kể cả khi ghi lỗi: app tiếp tục chạy đúng với thay đổi vừa làm.
    let saved = fresh.save();
    *config = fresh;
    saved.map_err(err)
}

/// Số lần ĐỒNG BỘ NỀN liên tiếp phải ghi lại file trước khi app ngừng tự ghi. Thuật toán gộp bảo
/// đảm hai máy hội tụ sau tối đa 2 lần ghi; con số này chỉ là cầu chì phòng lỗi chưa biết.
const MAX_CONSECUTIVE_WRITEBACKS: u32 = 6;
/// File CSV lớn hơn mức này bị từ chối (chống file rác làm treo app).
const MAX_CSV_BYTES: u64 = 20 * 1024 * 1024;

// ----------------------------------------------------------------------------- hoạt động & khoá

/// Đồng hồ "lần hoạt động gần nhất", đọc/ghi được mà KHÔNG cần khoá phiên: lệnh `touch` (gửi mỗi
/// lần rê chuột) không bao giờ phải chờ một thao tác đĩa chậm, và luồng tự khoá biết đã hết giờ
/// kể cả khi một luồng khác đang giữ khoá phiên.
pub struct Activity {
    base: Instant,
    /// ms kể từ `base` (có thể âm trong test).
    last_ms: AtomicI64,
}

impl Default for Activity {
    fn default() -> Self {
        Self::new()
    }
}

impl Activity {
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            last_ms: AtomicI64::new(0),
        }
    }
    fn now_ms(&self) -> i64 {
        i64::try_from(self.base.elapsed().as_millis()).unwrap_or(i64::MAX)
    }
    pub fn touch(&self) {
        self.last_ms.store(self.now_ms(), Ordering::SeqCst);
    }
    /// Thời gian không hoạt động.
    pub fn idle(&self) -> Duration {
        let d = self
            .now_ms()
            .saturating_sub(self.last_ms.load(Ordering::SeqCst));
        Duration::from_millis(u64::try_from(d).unwrap_or(0))
    }
    #[cfg(test)]
    pub fn backdate(&self, by: Duration) {
        let by = i64::try_from(by.as_millis()).unwrap_or(i64::MAX);
        self.last_ms.store(self.now_ms() - by, Ordering::SeqCst);
    }
}

/// Lý do của một lần khoá được yêu cầu từ bên ngoài khoá phiên (xem [`Shared::request_lock`]).
pub const LOCK_IDLE: u8 = 1;
pub const LOCK_SUSPEND: u8 = 2;
pub const LOCK_CLOSE: u8 = 3;

/// Phiên + "lệnh khoá đang chờ". Khi phải khoá (hết giờ, máy vừa ngủ, đóng cửa sổ) mà một luồng
/// khác đang giữ khoá phiên trong một thao tác đĩa treo, luồng tự khoá KHÔNG chờ: nó ghi một yêu
/// cầu khoá vào đây (không cần khoá phiên), báo trang vứt bí mật ngay, rồi chờ khoá phiên ở luồng
/// riêng. MỌI lần lấy khoá phiên ([`Shared::lock`], [`Shared::try_lock`]) đều thực hiện yêu cầu
/// đang chờ TRƯỚC khi trả phiên cho người gọi — nên không lệnh nào đến sau đó (kể cả `status` của
/// trang vừa nạp lại) thấy được kho đang mở.
pub struct Shared {
    session: Mutex<Session>,
    pub activity: Arc<Activity>,
    pending: AtomicU8,
}

impl Shared {
    pub fn new(s: Session) -> Self {
        Self {
            activity: s.activity.clone(),
            session: Mutex::new(s),
            pending: AtomicU8::new(0),
        }
    }

    /// Lấy khoá phiên (kể cả khi mutex "nhiễm độc" vì một lệnh trước panic) rồi thực hiện yêu cầu
    /// khoá đang chờ, nếu có.
    pub fn lock(&self) -> MutexGuard<'_, Session> {
        let mut g = self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.apply_pending(&mut g);
        g
    }

    /// Như [`Shared::lock`] nhưng không chờ: `None` nếu luồng khác đang giữ khoá phiên.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, Session>> {
        let mut g = match self.session.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        self.apply_pending(&mut g);
        Some(g)
    }

    /// Yêu cầu khoá (không cần khoá phiên). Trả về true nếu đây là yêu cầu mới.
    pub fn request_lock(&self, reason: u8) -> bool {
        self.pending
            .compare_exchange(0, reason, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    #[cfg(test)]
    pub fn lock_pending(&self) -> bool {
        self.pending.load(Ordering::SeqCst) != 0
    }

    fn apply_pending(&self, s: &mut Session) {
        match self.pending.swap(0, Ordering::SeqCst) {
            0 => {}
            _ if s.vault.is_none() => {}
            LOCK_IDLE => s.lock_because("Kho đã tự khoá do không sử dụng."),
            LOCK_SUSPEND => s.lock_because("Kho đã tự khoá vì máy vừa ngủ hoặc app bị tạm dừng."),
            _ => s.lock(),
        }
    }
}

// ----------------------------------------------------------------------------- bản nháp (stash)

/// Mục đích niêm phong (`Vault::seal_local`) của bản nháp + mật khẩu vừa tạo.
const STASH_PURPOSE: &str = "stash";
/// Bản nháp lớn hơn mức này không được giữ.
pub const MAX_DRAFT_BYTES: usize = 256 * 1024;
const MAX_STASH_FILE: u64 = 4 * 1024 * 1024;
/// Chỉ giữ chừng này mật khẩu vừa tạo, và không giữ quá 30 ngày.
pub const MAX_GENERATED: usize = 20;
pub const GENERATED_MAX_AGE_MS: i64 = 30 * 86_400_000;

#[derive(Serialize, Deserialize, Default)]
struct StashData {
    #[serde(default)]
    draft: Option<Zeroizing<String>>,
    #[serde(default)]
    generated: Vec<GeneratedItem>,
}

#[derive(Serialize, Deserialize)]
struct GeneratedItem {
    id: String,
    value: Zeroizing<String>,
    at: i64,
    #[serde(default)]
    label: Option<String>,
}

impl StashData {
    fn prune(&mut self, now: i64) {
        self.generated.retain(|g| g.at > now - GENERATED_MAX_AGE_MS);
        self.generated.sort_by_key(|g| std::cmp::Reverse(g.at));
        self.generated.truncate(MAX_GENERATED);
    }
    fn is_empty(&self) -> bool {
        self.draft.is_none() && self.generated.is_empty()
    }
}

/// Bản stash đã niêm phong (không có bản rõ) của một kho.
struct SealedStash {
    vault_id: String,
    sealed: Vec<u8>,
}

/// Một mật khẩu vừa tạo, KHÔNG kèm giá trị.
#[derive(Debug, Serialize)]
pub struct GeneratedView {
    pub id: String,
    pub at: i64,
    pub label: Option<String>,
}

/// Tên file trong thư mục riêng chỉ dùng mã kho gồm ký tự an toàn.
fn safe_id(id: &str) -> Option<&str> {
    (!id.is_empty()
        && id.len() <= 100
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .then_some(id)
}

pub struct Session {
    pub vault: Option<Vault>,
    pub config: Config,
    /// Đồng hồ "lần hoạt động gần nhất" — nằm NGOÀI khoá phiên (xem [`Activity`]).
    pub activity: Arc<Activity>,
    /// Tham số KDF khi tạo kho mới (test dùng tham số thấp).
    pub create_opts: CreateOptions,
    /// Ghi config.json thật (test đặt false để không đụng vào cấu hình của máy chạy test).
    pub persist_config: bool,
    /// Vấn đề đang tồn tại với file kho trên đĩa — hiện thành cảnh báo cố định cho tới khi hết.
    pub disk_problem: Option<AppError>,
    /// Lý do kho vừa bị khoá (hiện ở màn hình mở khoá), ví dụ "mật khẩu đã đổi ở máy khác".
    pub lock_note: Option<String>,
    /// Thư mục (ngoài thư mục đồng bộ) để ghi bản cứu hộ khi phải khoá mà chưa ghi được ra đĩa.
    pub rescue_dir: Option<PathBuf>,
    writebacks: u32,
    last_import: Option<PathBuf>,
    /// Điều cần báo cho người dùng từ những lần ghi mà lệnh gọi không trả kết quả ghi về giao diện
    /// (★, khôi phục mục, dọn thùng rác, nhập CSV, đổi mật khẩu chính…): ví dụ "đã cất một bản ghi
    /// bằng mật khẩu cũ", "đã ghi nhưng chưa kiểm tra lại được". Được gộp vào kết quả của lần đồng
    /// bộ tới (giao diện đồng bộ mỗi 20 giây) để không bị mất.
    pending: SyncResult,
    /// Bản nháp + mật khẩu vừa tạo của kho (đã niêm phong bằng khoá kho) — giữ qua lần khoá.
    stash: Option<SealedStash>,
    /// Kho có file stash trên đĩa không mở được: trước lần ghi đầu, file đó được đổi tên để giữ lại.
    stash_unreadable: Option<String>,
    /// Kho mà bản lưu riêng (`last-<id>.pwv`) đã được gộp / kiểm tra trong phiên này.
    local_checked: Option<String>,
    /// Trạng thái kho của lần ghi bản lưu riêng gần nhất (để không ghi lại khi không có gì mới).
    local_written: Option<(String, i64, i64, u64, usize, usize)>,
    /// Có bản sao lưu mở được khoá hiện tại bằng một mật khẩu chính khác (đổi mật khẩu kiểu 0.1.x).
    rekey_advised: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            vault: None,
            config: Config::load(),
            activity: Arc::new(Activity::new()),
            create_opts: CreateOptions::default(),
            persist_config: true,
            disk_problem: None,
            lock_note: None,
            rescue_dir: None,
            writebacks: 0,
            last_import: None,
            pending: SyncResult::default(),
            stash: None,
            stash_unreadable: None,
            local_checked: None,
            local_written: None,
            rekey_advised: false,
        }
    }
}

// ----------------------------------------------------------------------------- DTO

#[derive(Debug, Serialize)]
pub struct Status {
    pub unlocked: bool,
    pub read_only: bool,
    pub vault_path: Option<String>,
    /// Đã từng chọn/tạo kho trên máy này (dù file hiện có thể không còn ở đó).
    pub vault_configured: bool,
    pub vault_exists: bool,
    pub conflict_copies: usize,
    pub memory_locked: bool,
    pub entry_count: usize,
    pub trash_count: usize,
    /// Lần sửa nội dung gần nhất của kho đang mở (ms).
    pub modified_at: i64,
    pub disk_problem: Option<AppError>,
    pub lock_note: Option<String>,
    pub auto_lock_minutes: u32,
    /// Kho đang khoá: máy này còn giữ một bản lưu riêng của kho đã cấu hình (thời điểm ghi, ms).
    pub local_copy_at: Option<i64>,
    /// Nên đổi mật khẩu chính một lần để thay khoá mã hoá (xem [`Session::check_rekey`]).
    pub rekey_advised: bool,
}

#[derive(Debug, Serialize)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub has_totp: bool,
    pub updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct EntryDetail {
    pub id: String,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_password: bool,
    /// Ghi chú có thể chứa mã khôi phục, câu trả lời bảo mật ⇒ chỉ gửi khi người dùng bấm "hiện".
    pub has_notes: bool,
    pub has_totp: bool,
    pub totp_label: Option<String>,
    /// Secret 2FA đã lưu không đọc được (ví dụ nhập từ CSV sai định dạng).
    pub totp_error: Option<String>,
    pub history_count: usize,
    pub strength: Strength,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Dữ liệu từ form. Khi SỬA (có `id`), trường nào là `None` thì giữ nguyên: giao diện chỉ gửi
/// những trường người dùng thực sự thay đổi, để không đè lên thay đổi vừa đồng bộ về từ máy khác.
#[derive(Deserialize, Default)]
pub struct EntryInput {
    pub id: Option<String>,
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    pub urls: Option<Vec<String>>,
    pub notes: Option<Zeroizing<String>>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
    /// `None` = giữ nguyên; `Some("")` = xoá; còn lại = secret mới.
    pub totp: Option<Zeroizing<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GenRequest {
    Password(PasswordOptions),
    Passphrase(PassphraseOptions),
}

#[derive(Serialize)]
pub struct Generated {
    pub value: String,
    pub entropy_bits: f64,
    pub strength: Strength,
}

#[derive(Debug, Serialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining: u64,
    pub period: u64,
}

#[derive(Serialize)]
pub struct HistoryView {
    pub password: String,
    pub replaced_at: i64,
}

#[derive(Debug, Serialize, Default)]
pub struct SyncResult {
    pub changed: bool,
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub conflicts_merged: usize,
    /// Bản xung đột không gộp được (giữ nguyên tại chỗ) — mỗi dòng ổn định để giao diện không
    /// phải hiện lại cùng một thông báo mỗi 20 giây.
    pub errors: Vec<String>,
    /// Máy khác chạy bản app cũ đã đổi master password: từ nay dùng mật khẩu mới.
    pub password_changed_elsewhere: bool,
    /// App vừa ghi lại file kho vì bản đang mở có thứ mà file trên đĩa thiếu.
    pub wrote: bool,
    pub backup_failed: bool,
    /// Số bản của kho (file kho chính hoặc bản xung đột) chỉ mở được bằng mật khẩu chính CŨ: KHÔNG
    /// được gộp mà được cất vào thư mục sao lưu (`oldkey-…`) để chủ kho tự xem lại.
    pub old_key_archived: usize,
    /// Đã ghi file kho nhưng đọc lại không kiểm tra được (bản trong RAM được giữ; lần đồng bộ sau
    /// đọc lại và ghi lại nếu cần).
    pub unverified: bool,
    /// File kho trên đĩa đang có vấn đề (xem `Status::disk_problem`).
    pub problem: Option<AppError>,
}

impl SyncResult {
    fn add(&mut self, s: MergeStats) {
        self.added += s.added;
        self.updated += s.updated;
        self.deleted += s.deleted;
        self.changed |= s.changed();
    }
    fn from_save(r: SaveReport) -> Self {
        let mut out = SyncResult {
            password_changed_elsewhere: r.adopted_remote_password,
            backup_failed: r.backup_failed,
            old_key_archived: usize::from(r.old_key_archived),
            unverified: r.unverified,
            ..Default::default()
        };
        if let Some(s) = r.merged_remote {
            out.add(s);
        }
        out
    }
    fn from_sync(r: SyncReport) -> Self {
        let mut out = SyncResult {
            password_changed_elsewhere: r.adopted_remote_password,
            backup_failed: r.backup_failed,
            wrote: r.wrote,
            old_key_archived: r.old_key_archived,
            unverified: r.unverified,
            ..Default::default()
        };
        if let Some(s) = r.merged_remote {
            out.add(s);
        }
        for c in r.conflicts {
            let name = c
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            match c.result {
                Ok(s) => {
                    out.add(s);
                    out.conflicts_merged += 1;
                }
                // Thông báo của lõi nói "đã cất vào thư mục sao lưu" — chỉ đúng khi cất được. Không
                // cất được thì file vẫn nằm nguyên tại chỗ và lần đồng bộ sau sẽ thử lại.
                Err(VaultError::RetiredKeyCopy) if !c.archived => out.errors.push(format!(
                    "{name}: bản này được ghi bằng mật khẩu chính CŨ nên không được tự gộp. Chưa cất \
                     được nó vào thư mục sao lưu — file vẫn để nguyên tại chỗ, app sẽ thử lại ở lần \
                     đồng bộ sau."
                )),
                // Đã cất xong: thông báo riêng về "bản ghi bằng mật khẩu cũ" (`old_key_archived`) đã
                // nói đủ — không báo thêm một dòng "chưa gộp được" cho cùng một việc.
                Err(VaultError::RetiredKeyCopy) => {}
                Err(e) => out.errors.push(format!("{name}: {e}")),
            }
        }
        out
    }
    /// Gộp thêm một kết quả (của các lần ghi trước đó) vào kết quả này. `problem` giữ của kết quả
    /// này: nó là trạng thái mới nhất của file trên đĩa.
    fn absorb(&mut self, other: SyncResult) {
        self.changed |= other.changed;
        self.added += other.added;
        self.updated += other.updated;
        self.deleted += other.deleted;
        self.conflicts_merged += other.conflicts_merged;
        for e in other.errors {
            if !self.errors.contains(&e) {
                self.errors.push(e);
            }
        }
        self.password_changed_elsewhere |= other.password_changed_elsewhere;
        self.wrote |= other.wrote;
        self.backup_failed |= other.backup_failed;
        self.old_key_archived += other.old_key_archived;
        self.unverified |= other.unverified;
    }
    /// Chỉ giữ những điều cần báo cho người dùng (không tính số mục đã gộp: danh sách đã được tải
    /// lại sau lệnh vừa làm).
    fn notices_only(self) -> SyncResult {
        SyncResult {
            errors: self.errors,
            password_changed_elsewhere: self.password_changed_elsewhere,
            backup_failed: self.backup_failed,
            old_key_archived: self.old_key_archived,
            unverified: self.unverified,
            ..Default::default()
        }
    }
}

/// File kho vừa mở cũ hơn bản mà máy này từng thấy.
#[derive(Debug, Serialize)]
pub struct RollbackView {
    pub seen_modified_at: i64,
    pub file_modified_at: i64,
    pub older_password: bool,
    /// Khoá của kho vừa mở không nối tiếp từ khoá máy này dùng lần trước (mở bằng mật khẩu chính
    /// cũ, hoặc file đã bị thay bằng file do người biết mật khẩu cũ làm ra).
    pub unknown_key: bool,
}

#[derive(Debug, Serialize, Default)]
pub struct UnlockInfo {
    pub rollback: Option<RollbackView>,
    /// Số bản cứu hộ (ghi khi app phải khoá mà chưa lưu được) vừa được gộp lại vào kho.
    pub rescued: usize,
    /// Số bản cứu hộ KHÔNG gộp được (ví dụ ghi bằng một mật khẩu chính khác): vẫn được giữ nguyên
    /// trong thư mục riêng của app, lần mở khoá sau thử lại.
    pub rescue_kept: usize,
    pub sync: SyncResult,
    /// Bản nháp (form đang sửa dở) giữ từ trước khi kho bị khoá — chuỗi do giao diện tự định nghĩa.
    pub draft: Option<String>,
    /// File kho vừa mở thiếu thay đổi mà máy này đã lưu; đã gộp lại từ bản lưu riêng trên máy.
    pub local_restored: Option<LocalRestoredView>,
    /// File kho vừa được một máy chạy bản 0.1.x ghi lại (sau khi máy này đã mở nó bằng bản mới).
    pub old_version_wrote: bool,
}

/// Số mục vừa lấy lại từ bản lưu riêng trên máy này.
#[derive(Debug, Serialize, Clone, Copy)]
pub struct LocalRestoredView {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
}

/// File vừa chọn có vẻ là bản xung đột của một file kho khác cùng thư mục (cùng kho).
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ConflictHint {
    pub picked_name: String,
    pub original_path: String,
    pub original_name: String,
}

#[derive(Debug, Serialize)]
pub struct RecoverInfo {
    pub entries: usize,
    pub files_used: usize,
    pub newest_backup_at: i64,
    /// Nơi file hỏng được cất.
    pub archived: Option<String>,
    /// Số bản cứu hộ không gộp được (vẫn được giữ lại, xem [`UnlockInfo::rescue_kept`]).
    pub rescue_kept: usize,
    /// Không còn bản sao lưu dùng được: kho được dựng lại từ bản lưu riêng / bản cứu hộ trên máy này.
    pub from_local_copy: bool,
}

/// Các lựa chọn rõ ràng của chủ kho khi khôi phục.
#[derive(Debug, Default, Clone, Copy)]
pub struct RecoverOpts {
    /// Chấp nhận các bản sao lưu từ trước lần đổi mật khẩu chính gần nhất (mật khẩu cũ).
    pub allow_older: bool,
    /// Chấp nhận bản dựng lại CŨ HƠN dữ liệu máy này từng thấy (`older_than_seen`).
    pub allow_stale: bool,
    /// File kho chính báo "định dạng mới hơn": vẫn cất nó đi (`damaged-…`) và thay bằng bản dựng lại.
    pub replace_newer: bool,
}

#[derive(Debug, Serialize)]
pub struct HealthItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub severity: u8,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthView {
    pub score: u8,
    pub checked: usize,
    pub breached: usize,
    pub reused: usize,
    pub weak: usize,
    pub old: usize,
    pub breach_check_done: bool,
    pub breach_error: Option<String>,
    pub items: Vec<HealthItem>,
}

#[derive(Debug, Serialize)]
pub struct ImportView {
    pub imported: usize,
    pub duplicates: usize,
    pub skipped: usize,
    /// Mục đã nhập nhưng có vẻ trùng (cùng trang web + username + mật khẩu) với mục khác.
    pub similar: Vec<String>,
    /// Mục có mã 2FA không đọc được (giá trị gốc được giữ trong ghi chú).
    pub bad_totp: Vec<String>,
    pub detected: String,
}

#[derive(Debug, Serialize)]
pub struct MoveView {
    pub old_path: String,
    pub new_path: String,
    pub backups_moved: bool,
    pub old_removed: bool,
    pub conflicts_merged: usize,
    pub rescued: bool,
}

#[derive(Debug, Serialize)]
pub struct PasswordChangeView {
    pub backups_reencrypted: usize,
    /// Bản sao lưu để nguyên, không mã hoá lại: không đọc được, hoặc chỉ mở được bằng một mật khẩu
    /// chính cũ HƠN NỮA (lõi cố ý không bao giờ mã hoá lại những bản đó).
    pub backups_skipped: usize,
    /// Mật khẩu ĐÃ được đổi và file kho đã được ghi, nhưng đọc lại không kiểm tra được.
    pub unverified: bool,
    /// Tên các bản sao lưu ĐỌC được nhưng GHI LẠI không được: chúng vẫn mở được bằng mật khẩu CŨ.
    pub backups_failed: Vec<String>,
}

/// Kết quả "dọn sạch thùng rác".
#[derive(Debug, Serialize)]
pub struct EmptyTrashView {
    /// Số mục đã xoá vĩnh viễn (chỉ trong số các mục người dùng đã thấy khi xác nhận).
    pub purged: usize,
    /// Số mục còn lại trong thùng rác sau đó (ví dụ máy khác vừa chuyển thêm mục vào).
    pub remaining: usize,
}

#[derive(Debug, Serialize)]
pub struct TrashItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub deleted_at: i64,
}

#[derive(Debug, Serialize)]
pub struct BackupView {
    /// Tên file trong thư mục sao lưu (dùng làm khoá khi gọi lại).
    pub name: String,
    /// "auto" | "merged" | "damaged" | "oldkey"
    pub kind: &'static str,
    pub timestamp: i64,
    /// Số mục đang dùng trong bản sao lưu (None = không đọc được).
    pub entries: Option<usize>,
    /// Bản này CHỈ mở được bằng khoá của một mật khẩu chính cũ: có thể là bản sao lưu thật từ trước
    /// lần đổi mật khẩu, nhưng cũng có thể do người biết mật khẩu cũ đặt vào ⇒ giao diện cảnh báo
    /// trước khi khôi phục mục nào từ nó.
    pub retired_key: bool,
}

#[derive(Debug, Serialize)]
pub struct BackupEntryView {
    pub id: String,
    pub title: String,
    pub username: String,
    /// "changed" (khác bản hiện tại) | "in_trash" | "missing" (hiện không còn).
    pub status: &'static str,
    /// Tên các trường khác với bản hiện tại (không kèm giá trị).
    pub changed_fields: Vec<&'static str>,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_secs: u32,
    #[serde(default = "yes")]
    pub check_updates: bool,
}

fn yes() -> bool {
    true
}

// ----------------------------------------------------------------------------- logic

pub fn check_master_strength(pw: &str) -> AppResult<()> {
    let c = check_master_password(pw);
    if c.ok {
        Ok(())
    } else {
        Err(AppError::new(
            "weak_password",
            format!("Mật khẩu chính chưa đủ mạnh. {}", c.message),
        ))
    }
}

fn clean_list(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Các trường nội dung khác nhau giữa hai phiên bản của một mục (chỉ tên, không kèm giá trị).
fn diff_fields(a: &Entry, b: &Entry) -> Vec<&'static str> {
    let mut out = Vec::new();
    if a.title != b.title {
        out.push("tiêu đề");
    }
    if a.username != b.username {
        out.push("tên đăng nhập");
    }
    if a.password != b.password {
        out.push("mật khẩu");
    }
    if a.urls != b.urls {
        out.push("trang web");
    }
    if a.notes != b.notes {
        out.push("ghi chú");
    }
    if a.totp != b.totp {
        out.push("mã 2FA");
    }
    if a.tags != b.tags {
        out.push("nhóm");
    }
    if a.favorite != b.favorite {
        out.push("yêu thích");
    }
    out
}

impl Session {
    pub fn touch(&mut self) {
        self.activity.touch();
    }

    fn open_opts(&self) -> OpenOptions {
        OpenOptions {
            allow_weak_kdf: self.create_opts.allow_weak_kdf,
        }
    }

    /// Ghi một thay đổi cấu hình (xem [`update_config_in`]).
    fn update_config(&mut self, change: impl FnOnce(&mut Config)) -> AppResult<()> {
        update_config_in(&mut self.config, self.persist_config, change)
    }

    /// Trả về true nếu vừa tự khoá.
    pub fn auto_lock_if_idle(&mut self) -> bool {
        let mins = self.config.auto_lock_minutes;
        if mins == 0 || self.vault.is_none() {
            return false;
        }
        if self.activity.idle() >= Duration::from_secs(u64::from(mins) * 60) {
            self.lock_because("Kho đã tự khoá do không sử dụng.");
            return true;
        }
        false
    }

    fn vault(&self) -> AppResult<&Vault> {
        self.vault.as_ref().ok_or_else(AppError::locked)
    }

    fn vault_mut(&mut self) -> AppResult<&mut Vault> {
        self.vault.as_mut().ok_or_else(AppError::locked)
    }

    fn entry(&self, id: &str) -> AppResult<&Entry> {
        self.vault()?
            .get(id)
            .ok_or_else(|| AppError::new("not_found", "Không tìm thấy mục này (có thể đã bị xoá)"))
    }

    pub fn status(&self) -> Status {
        let v = self.vault.as_ref();
        let path = v
            .map(|v| v.path().to_path_buf())
            .or_else(|| self.config.vault.clone());
        Status {
            unlocked: v.is_some(),
            read_only: v.is_some_and(Vault::is_read_only),
            vault_configured: self.config.vault.is_some(),
            // Đường dẫn dạng URI (Android) không kiểm tra được bằng is_file ⇒ coi như có.
            vault_exists: path.as_ref().is_some_and(|p| is_uri(p) || p.is_file()),
            vault_path: path.map(|p| p.display().to_string()),
            conflict_copies: v.map_or(0, |v| v.conflict_copies().len()),
            memory_locked: v.is_some_and(Vault::memory_locked),
            entry_count: v.map_or(0, |v| v.entries().len()),
            trash_count: v.map_or(0, |v| v.trash().len()),
            modified_at: v.map_or(0, Vault::modified_at),
            disk_problem: self.disk_problem.clone(),
            lock_note: self.lock_note.clone(),
            auto_lock_minutes: self.config.auto_lock_minutes,
            local_copy_at: if v.is_some() {
                None
            } else {
                self.configured_local_copy_at()
            },
            rekey_advised: v.is_some() && self.rekey_advised,
        }
    }

    // ------------------------------------------------------------------ xử lý lỗi & ghi nhận

    /// Phân loại lỗi từ lõi kho: đổi mật khẩu ở máy khác ⇒ khoá để người dùng nhập mật khẩu mới;
    /// file trên đĩa có vấn đề ⇒ ghi nhận để hiện cảnh báo cố định.
    fn vault_error(&mut self, e: VaultError) -> AppError {
        let app: AppError = e.into();
        match app.code.as_str() {
            "password_changed" => {
                self.lock_with(Some(app.message.clone()));
            }
            "file_missing" | "file_damaged" | "unsupported_version" | "different_vault" => {
                self.disk_problem = Some(app.clone());
            }
            _ => {}
        }
        app
    }

    /// Sau mỗi lần đọc/ghi thành công: ghi nhớ "mốc mới nhất đã thấy" của kho (để lần sau phát
    /// hiện file bị thay bằng bản cũ hơn).
    fn after_success(&mut self) {
        self.disk_problem = None;
        self.write_local_copy();
        let Some(v) = self.vault.as_ref().filter(|v| !v.is_read_only()) else {
            return;
        };
        // Hàm này chạy sau MỖI lần đọc/ghi (mỗi 20 giây): chỉ đụng tới config.json khi mốc thật sự
        // thay đổi, và áp thay đổi lên bản vừa đọc lại từ đĩa.
        let mut probe = self.config.clone();
        if v.note_seen_in(&mut probe) {
            let _ = update_config_in(&mut self.config, self.persist_config, |c| {
                v.note_seen_in(c);
            });
        }
    }

    /// Chạy một thay đổi trong giao dịch (gộp trước – sửa – ghi – hoàn tác nếu lỗi).
    fn mutate<T>(
        &mut self,
        f: impl FnOnce(&mut Vault) -> pwv_vault_core::Result<T>,
    ) -> AppResult<(T, SyncResult)> {
        self.touch();
        let result = self.vault_mut()?.transact(f);
        match result {
            Ok((t, report)) => {
                self.writebacks = 0;
                self.after_success();
                Ok((t, SyncResult::from_save(report)))
            }
            Err(e) => Err(self.vault_error(e)),
        }
    }

    // ------------------------------------------------------------------ tạo / mở / khoá

    pub fn create_vault(&mut self, path: &Path, password: &str) -> AppResult<()> {
        check_master_strength(password)?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(err)?;
        }
        let v = Vault::create(path, password.as_bytes(), self.create_opts)?;
        let vault_path = v.path().to_path_buf();
        self.update_config(|c| c.set_vault_path(&vault_path))?;
        self.vault = Some(v);
        self.pending = SyncResult::default();
        self.lock_note = None;
        self.after_success();
        self.touch();
        Ok(())
    }

    /// Thư mục định đặt kho mới đã có dấu vết của một kho khác chưa (thư mục sao lưu, file .pwv)?
    /// Dùng để cảnh báo ở máy thứ hai: file kho có thể chưa kịp đồng bộ về — tạo kho mới ở đây sẽ
    /// sinh ra HAI kho khác nhau trùng tên.
    pub fn existing_vault_traces(path: &Path) -> Vec<String> {
        let mut out = Vec::new();
        if fsutil::backup_dir(path).is_dir() {
            out.push(
                fsutil::backup_dir(path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            );
        }
        for p in fsutil::sibling_candidates(path) {
            out.push(
                p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            );
        }
        out
    }

    pub fn unlock(&mut self, path: &Path, password: &str) -> AppResult<UnlockInfo> {
        let v = match Vault::open_with(path, password.as_bytes(), self.open_opts()) {
            Ok(v) => v,
            Err(e) => return Err(self.explain_unlock_error(path, e)),
        };
        // Bản mới đã từng mở kho này (có dấu khoá) mà file lại là định dạng 1 và đã đổi kể từ lần
        // thấy gần nhất ⇒ một máy còn chạy bản 0.1.x vừa ghi lại nó.
        let old_version_wrote = v.opened_version() == 1
            && self.config.seen_key_tag(v.vault_id()) != 0
            && self
                .config
                .seen
                .get(v.vault_id())
                .is_some_and(|m| m.modified_at != v.modified_at());
        if self.config.vault.as_deref() != Some(v.path()) {
            let vault_path = v.path().to_path_buf();
            self.update_config(|c| c.set_vault_path(&vault_path))?;
        }
        let rollback = v.rollback_against(&self.config).map(|r| RollbackView {
            seen_modified_at: r.seen_modified_at,
            file_modified_at: r.file_modified_at,
            older_password: r.older_password,
            unknown_key: r.unknown_key,
        });
        self.vault = Some(v);
        self.lock_note = None;
        self.disk_problem = None;
        self.writebacks = 0;
        self.pending = SyncResult::default();
        self.rekey_advised = false;
        self.touch();
        // Bản lưu riêng trên máy này: gộp lại những gì máy này đã lưu mà file kho vừa mở thiếu (ví dụ
        // một máy khác ghi đè file khi chưa đồng bộ xong). Gộp là phép hợp an toàn: không bao giờ
        // làm sống lại mục đã xoá hay đè lên thay đổi mới hơn.
        let local_restored = self.merge_local_copy().map(|m| LocalRestoredView {
            added: m.added,
            updated: m.updated,
            deleted: m.deleted,
        });
        let (merged, rescue_kept) = self.merge_rescue_copies();
        // Ghi lại ngay những gì vừa gộp (bản lưu riêng, bản cứu hộ, bản xung đột). Vấn đề với file
        // trên đĩa không chặn việc mở kho (nằm trong `sync.problem`); chỉ "mật khẩu đã đổi ở máy
        // khác" mới trả lỗi.
        let sync = self.sync()?;
        if sync.problem.is_none() {
            self.delete_rescue_copies(&merged);
        }
        let draft = self.load_stash().draft.map(|d| d.to_string());
        Ok(UnlockInfo {
            rollback,
            rescued: merged.len(),
            rescue_kept,
            sync,
            draft,
            local_restored,
            old_version_wrote,
        })
    }

    /// Thông báo mở khoá thất bại, kèm gợi ý khi máy này biết file đang ở trạng thái bất thường.
    fn explain_unlock_error(&self, path: &Path, e: VaultError) -> AppError {
        let mut app: AppError = e.into();
        if app.code == "wrong_password" {
            let known = fsutil::read_prefix(path, pwv_vault_core::format::HEADER_PEEK_LEN)
                .ok()
                .and_then(|b| pwv_vault_core::format::peek_header(&b).ok())
                .and_then(|h| {
                    self.config
                        .seen
                        .get(&h.vault_id)
                        .map(|s| h.key_changed_at < s.key_changed_at)
                });
            if known == Some(true) {
                app.message.push_str(
                    ". Lưu ý: file kho hiện tại CŨ HƠN lần đổi mật khẩu chính gần nhất mà máy này \
                     biết — có thể dịch vụ đồng bộ chưa tải xong hoặc đã khôi phục một bản cũ. \
                     Hãy chờ đồng bộ xong rồi thử lại.",
                );
            }
        }
        app
    }

    /// Kho không mở được vì file hỏng: dựng lại từ thư mục sao lưu (và các bản cứu hộ), rồi ghi
    /// ra đĩa. File hỏng được cất vào thư mục sao lưu, không bị xoá.
    ///
    /// `allow_older`: chủ kho đã đọc giải thích và chọn rõ ràng khôi phục từ các bản sao lưu tạo
    /// TRƯỚC lần đổi mật khẩu chính gần nhất (mật khẩu vừa nhập là mật khẩu cũ). Không có cờ này thì
    /// trường hợp đó trả lỗi `older_password`.
    #[cfg(test)]
    pub fn recover(
        &mut self,
        path: &Path,
        password: &str,
        allow_older: bool,
    ) -> AppResult<RecoverInfo> {
        self.recover_with(
            path,
            password,
            RecoverOpts {
                allow_older,
                ..Default::default()
            },
        )
    }

    /// Như [`Session::recover`], với mọi lựa chọn rõ ràng của chủ kho ([`RecoverOpts`]).
    ///
    /// Thứ tự: dựng lại từ thư mục sao lưu (không có bản nào dùng được ⇒ từ bản lưu riêng rồi các
    /// bản cứu hộ trên máy này); kiểm tra "mật khẩu cũ"; gộp bản lưu riêng + bản cứu hộ; kiểm tra
    /// "cũ hơn dữ liệu máy này từng thấy" (`older_than_seen`) — tất cả TRƯỚC khi ghi gì vào thư mục kho.
    pub fn recover_with(
        &mut self,
        path: &Path,
        password: &str,
        o: RecoverOpts,
    ) -> AppResult<RecoverInfo> {
        let (v, files_used, newest_backup_at, from_local, local_archived) =
            match Vault::recover_from_backups_opts(
                path,
                password.as_bytes(),
                self.open_opts(),
                o.allow_older,
            ) {
                Ok((v, n, t)) => {
                    // Lõi chỉ so với các bản trong thư mục sao lưu — mà ai có quyền ghi vào thư mục
                    // đồng bộ cũng xoá được các bản mới hơn. Máy này còn nhớ mốc riêng (ngoài thư
                    // mục đồng bộ): nếu nó đã biết một lần đổi mật khẩu mới hơn, hoặc một khoá mà kho
                    // dựng lại không hề biết, thì mật khẩu vừa nhập là mật khẩu CŨ ⇒ không ghi gì.
                    if !o.allow_older
                        && v.rollback_against(&self.config)
                            .is_some_and(|r| r.older_password || r.unknown_key)
                    {
                        drop(v);
                        return Err(VaultError::OlderPasswordBackups.into());
                    }
                    (v, n, t, false, None)
                }
                Err(VaultError::NoUsableBackup) => {
                    let (v, archived) = self.recover_from_local(path, password, o)?;
                    let t = v.modified_at();
                    (v, 1, t, true, archived)
                }
                Err(e) => return Err(e.into()),
            };
        self.vault = Some(v);
        self.lock_note = None;
        self.disk_problem = None;
        self.pending = SyncResult::default();
        self.rekey_advised = false;
        self.merge_local_copy();
        let (merged, rescue_kept) = self.merge_rescue_copies();
        if !from_local && !o.allow_older && !o.allow_stale {
            let stale = self
                .vault()?
                .rollback_against(&self.config)
                .filter(|r| r.file_modified_at < r.seen_modified_at);
            if let Some(r) = stale {
                self.vault = None;
                return Err(older_than_seen(r.file_modified_at, r.seen_modified_at));
            }
        }
        if o.replace_newer && matches!(Vault::peek(path), Err(VaultError::UnsupportedVersion(_))) {
            if let Err(e) = fsutil::archive_file(
                path,
                BackupKind::Damaged,
                pwv_vault_core::model::now_ms(),
                path,
            ) {
                self.vault = None;
                return Err(err(e));
            }
        }
        let archived = match self.vault_mut()?.force_write() {
            Ok(a) => a.or(local_archived),
            Err(e) => {
                self.vault = None;
                return Err(e.into());
            }
        };
        self.delete_rescue_copies(&merged);
        let Some(v) = self.vault.as_ref() else {
            return Err(AppError::locked());
        };
        let path = v.path().to_path_buf();
        // Người dùng chủ động dựng lại kho ⇒ lấy trạng thái này làm mốc "đã thấy" mới.
        update_config_in(&mut self.config, self.persist_config, |c| {
            c.set_vault_path(&path);
            v.accept_as_seen(c);
        })?;
        self.after_success();
        self.touch();
        Ok(RecoverInfo {
            entries: self.vault()?.entries().len(),
            files_used,
            newest_backup_at,
            archived: archived.map(|p| p.display().to_string()),
            rescue_kept,
            from_local_copy: from_local,
        })
    }

    /// Không có bản sao lưu dùng được: lấy bản lưu riêng, rồi các bản cứu hộ (mới nhất trước) của
    /// kho làm gốc. Mọi kiểm tra được làm trên bản đọc từ RAM; chỉ khi qua hết mới cất file hỏng và
    /// ghi gốc đó thành file kho (không bao giờ ghi đè: `write_new`). Trả về kho và nơi cất file hỏng.
    fn recover_from_local(
        &mut self,
        path: &Path,
        password: &str,
        o: RecoverOpts,
    ) -> AppResult<(Vault, Option<PathBuf>)> {
        let no_backup = || AppError::from(VaultError::NoUsableBackup);
        let configured = self.config.vault.as_deref() == Some(path);
        let id = configured
            .then(|| self.config.last_vault_id.clone())
            .flatten()
            .or_else(|| Vault::peek(path).ok().map(|i| i.vault_id));
        let Some(id) = id else {
            return Err(no_backup());
        };
        let mut files: Vec<PathBuf> = self
            .local_copy_path(&id)
            .filter(|p| p.is_file())
            .into_iter()
            .collect();
        let mut rescues = self.rescue_files(&id);
        rescues.sort();
        rescues.reverse();
        files.extend(rescues);
        let mut wrong = false;
        let mut found = None;
        for f in files {
            let Ok(Some(bytes)) = fsutil::read_retry_capped(&f, fsutil::MAX_VAULT_FILE) else {
                continue;
            };
            match Vault::open_bytes_with(path, &bytes, password.as_bytes(), self.open_opts()) {
                Ok(ro) if ro.vault_id() == id => {
                    found = Some((ro, bytes));
                    break;
                }
                Err(VaultError::Decrypt) => wrong = true,
                _ => {}
            }
        }
        let Some((ro, bytes)) = found else {
            return Err(if wrong {
                VaultError::Decrypt.into()
            } else {
                no_backup()
            });
        };
        if let Some(r) = ro.rollback_against(&self.config) {
            if !o.allow_older && (r.older_password || r.unknown_key) {
                return Err(VaultError::OlderPasswordBackups.into());
            }
            if !o.allow_older && !o.allow_stale && r.file_modified_at < r.seen_modified_at {
                return Err(older_than_seen(r.file_modified_at, r.seen_modified_at));
            }
        }
        // File kho chính còn đọc được header: không bao giờ thay một file của kho khác, một file ghi
        // lần đổi mật khẩu mới hơn bản này, hay (trừ khi chủ kho chọn) một file định dạng mới hơn.
        match Vault::peek(path) {
            Ok(info) if info.vault_id != id => return Err(VaultError::DifferentVault.into()),
            Ok(info) if info.key_changed_at > ro.key_changed_at() && !o.allow_older => {
                return Err(VaultError::OlderPasswordBackups.into())
            }
            Err(VaultError::UnsupportedVersion(n)) if !o.replace_newer => {
                return Err(VaultError::UnsupportedVersion(n).into())
            }
            _ => {}
        }
        drop(ro);
        let archived = if path.exists() {
            Some(
                fsutil::archive_file(
                    path,
                    BackupKind::Damaged,
                    pwv_vault_core::model::now_ms(),
                    path,
                )
                .map_err(err)?,
            )
        } else {
            None
        };
        fsutil::write_new(path, &bytes)?;
        let v = Vault::open_with(path, password.as_bytes(), self.open_opts())?;
        Ok((v, archived))
    }

    /// Mở kho chỉ đọc từ dữ liệu thô (điện thoại).
    pub fn unlock_bytes(&mut self, label: &str, bytes: &[u8], password: &str) -> AppResult<()> {
        let v = Vault::open_bytes_with(label, bytes, password.as_bytes(), self.open_opts())?;
        self.vault = Some(v);
        self.lock_note = None;
        self.touch();
        Ok(())
    }

    /// Nạp một bản khác của cùng kho vào kho chỉ đọc (gộp, không bao giờ đi lùi).
    /// Trả về true nếu có thay đổi.
    pub fn reload_bytes(&mut self, bytes: &[u8]) -> AppResult<bool> {
        self.touch();
        let r = self.vault_mut()?.replace_from_bytes(bytes);
        r.map_err(|e| self.vault_error(e))
    }

    /// Toàn bộ kho đang mở (đã mã hoá) — điện thoại dùng để lưu bản xem ngoại tuyến.
    pub fn export_bytes(&self) -> AppResult<Vec<u8>> {
        Ok(self.vault()?.export_bytes()?)
    }

    /// Khoá kho. Nếu kho vốn đã khoá thì giữ nguyên lý do khoá đang hiện (để một lệnh khoá thừa —
    /// đóng cửa sổ, trang được nạp lại — không xoá mất lời nhắn "vì sao kho bị khoá").
    pub fn lock(&mut self) {
        if self.vault.is_none() {
            return;
        }
        self.lock_with(None);
    }

    /// Khoá kèm lý do để hiện ở màn hình mở khoá.
    pub fn lock_because(&mut self, note: &str) {
        self.lock_with(Some(note.to_string()));
    }

    fn lock_with(&mut self, note: Option<String>) {
        if let Some(v) = self.vault.as_mut() {
            if !v.is_read_only() && (v.has_unsaved_changes() || self.disk_problem.is_some()) {
                // Bản trong RAM đang là bản tốt duy nhất: cố ghi lần cuối; không được thì để lại
                // một bản cứu hộ (đã mã hoá) ngoài thư mục đồng bộ, lần mở khoá sau sẽ gộp lại.
                let saved = v.has_unsaved_changes() && v.save().is_ok();
                if !saved {
                    self.write_rescue_copy();
                }
            }
        }
        self.write_local_copy();
        self.vault = None;
        self.rekey_advised = false;
        self.disk_problem = None;
        self.pending = SyncResult::default();
        self.lock_note = note;
    }

    fn rescue_files(&self, vault_id: &str) -> Vec<PathBuf> {
        let Some(dir) = self.rescue_dir.as_ref() else {
            return Vec::new();
        };
        let Ok(rd) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let prefix = format!("{vault_id}-");
        rd.filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(&prefix))
            })
            .collect()
    }

    fn write_rescue_copy(&self) {
        let (Some(v), Some(dir)) = (self.vault.as_ref(), self.rescue_dir.as_ref()) else {
            return;
        };
        let Ok(bytes) = v.export_bytes() else {
            return;
        };
        let _ = std::fs::create_dir_all(dir);
        let name = format!("{}-{}.pwv", v.vault_id(), pwv_vault_core::model::now_ms());
        let _ = fsutil::atomic_write(&dir.join(name), &bytes);
    }

    /// Gộp các bản cứu hộ của kho đang mở. Trả về (các file đã gộp được, số file KHÔNG gộp được).
    fn merge_rescue_copies(&mut self) -> (Vec<PathBuf>, usize) {
        let Some(id) = self.vault.as_ref().map(|v| v.vault_id().to_string()) else {
            return (Vec::new(), 0);
        };
        let files = self.rescue_files(&id);
        let Some(v) = self.vault.as_mut() else {
            return (Vec::new(), 0);
        };
        let (merged, failed): (Vec<PathBuf>, Vec<PathBuf>) =
            files.into_iter().partition(|f| v.merge_file(f).is_ok());
        (merged, failed.len())
    }

    /// Xoá ĐÚNG các bản cứu hộ đã gộp được (`merged`), và chỉ khi kho đã được GHI thành công. Bản
    /// nào không gộp được (ví dụ ghi bằng một mật khẩu chính khác) có thể là bản duy nhất còn giữ dữ
    /// liệu chưa lưu ⇒ không bao giờ bị xoá ở đây; lần mở khoá sau thử gộp lại.
    fn delete_rescue_copies(&self, merged: &[PathBuf]) {
        let Some(v) = self.vault.as_ref() else {
            return;
        };
        if v.has_unsaved_changes() {
            return;
        }
        for f in merged {
            let _ = std::fs::remove_file(f);
        }
    }

    /// Người dùng đã đọc cảnh báo "file kho cũ hơn bản từng thấy" và chấp nhận dùng bản hiện tại.
    pub fn accept_rollback(&mut self) -> AppResult<()> {
        let Some(v) = self.vault.as_ref() else {
            return Err(AppError::locked());
        };
        update_config_in(&mut self.config, self.persist_config, |c| {
            v.accept_as_seen(c)
        })
    }

    /// Ghi nhớ vị trí kho mới mà không khoá kho đang mở (chọn lại file trên điện thoại).
    pub fn set_vault_location_keep_open(&mut self, location: &str) -> AppResult<()> {
        self.update_config(|c| c.set_vault_path(Path::new(location)))
    }

    pub fn set_vault_path(&mut self, path: &Path) -> AppResult<()> {
        self.lock();
        // Lời nhắn "vì sao kho bị khoá" là của kho cũ, không còn đúng với kho vừa chọn.
        self.lock_note = None;
        self.update_config(|c| c.set_vault_path(path))
    }

    /// Lần ghi vừa rồi thành công nhưng lệnh không trả kết quả ghi về giao diện: giữ lại những điều
    /// cần báo để lần đồng bộ tới trả về.
    fn defer_notices(&mut self, r: SyncResult) {
        self.pending.absorb(r.notices_only());
    }

    // ------------------------------------------------------------------ đọc

    pub fn list(&self, query: &str) -> AppResult<Vec<EntrySummary>> {
        Ok(self
            .vault()?
            .search(query)
            .into_iter()
            .map(|e| EntrySummary {
                id: e.id.clone(),
                title: e.title.clone(),
                username: e.username.clone(),
                url: e.urls.first().cloned(),
                favorite: e.favorite,
                tags: e.tags.clone(),
                has_totp: e.totp.is_some(),
                updated_at: e.updated_at,
            })
            .collect())
    }

    pub fn detail(&self, id: &str) -> AppResult<EntryDetail> {
        let e = self.entry(id)?;
        let parsed = e.totp.as_deref().map(Totp::parse);
        let totp_label = parsed.as_ref().and_then(|r| r.as_ref().ok()).map(|t| {
            match (t.issuer.clone(), t.account.clone()) {
                (Some(i), Some(a)) => format!("{i} ({a})"),
                (Some(x), None) | (None, Some(x)) => x,
                (None, None) => "Mã 2FA".into(),
            }
        });
        let totp_error = parsed.as_ref().and_then(|r| r.as_ref().err()).map(|e| {
            format!("Secret 2FA đã lưu không đọc được ({e}) — hãy sửa mục này và nhập lại.")
        });
        Ok(EntryDetail {
            id: e.id.clone(),
            title: e.title.clone(),
            username: e.username.clone(),
            urls: e.urls.clone(),
            tags: e.tags.clone(),
            favorite: e.favorite,
            has_password: !e.password.is_empty(),
            has_notes: !e.notes.is_empty(),
            has_totp: e.totp.is_some(),
            totp_label,
            totp_error,
            history_count: e.password_history.len(),
            strength: estimate_strength(&e.password, &[&e.username, &e.title]),
            created_at: e.created_at,
            updated_at: e.updated_at,
        })
    }

    pub fn reveal_password(&mut self, id: &str) -> AppResult<String> {
        self.touch();
        Ok(self.entry(id)?.password.clone())
    }

    pub fn reveal_notes(&mut self, id: &str) -> AppResult<String> {
        self.touch();
        Ok(self.entry(id)?.notes.clone())
    }

    /// Secret 2FA nguyên văn (để người dùng chép sang app xác thực khác / sửa lại khi sai).
    pub fn reveal_totp_secret(&mut self, id: &str) -> AppResult<String> {
        self.touch();
        Ok(self.entry(id)?.totp.clone().unwrap_or_default())
    }

    pub fn history(&mut self, id: &str) -> AppResult<Vec<HistoryView>> {
        self.touch();
        Ok(self
            .entry(id)?
            .password_history
            .iter()
            .map(|h| HistoryView {
                password: h.password.clone(),
                replaced_at: h.replaced_at,
            })
            .collect())
    }

    /// Giá trị cần sao chép. `field`: "password" | "username" | "totp" | "notes" | "url" (địa chỉ
    /// đầu tiên) | "url:<số thứ tự>" | "history:<số thứ tự>" (mật khẩu cũ).
    #[cfg(test)]
    pub fn field_value(&mut self, id: &str, field: &str) -> AppResult<Zeroizing<String>> {
        self.field_value_checked(id, field, None)
    }

    /// Như [`Session::field_value`]. `shown_updated_at`: thời điểm sửa của mục mà giao diện đang
    /// hiện — khác với mục hiện tại (vừa đồng bộ về thay đổi) ⇒ lỗi `entry_changed`, để chỉ số
    /// (`url:<i>`, `history:<i>`) không bao giờ chép nhầm một mục khác với thứ đang hiện.
    pub fn field_value_checked(
        &mut self,
        id: &str,
        field: &str,
        shown_updated_at: Option<i64>,
    ) -> AppResult<Zeroizing<String>> {
        self.touch();
        let e = self.entry(id)?;
        if shown_updated_at.is_some_and(|t| t != e.updated_at) {
            return Err(AppError::new(
                "entry_changed",
                "Mục này vừa thay đổi (có thể do đồng bộ từ máy khác) nên đã được tải lại — hãy bấm sao chép lại.",
            ));
        }
        let v = match field {
            "password" => e.password.clone(),
            "username" => e.username.clone(),
            "notes" => e.notes.clone(),
            "url" => e.urls.first().cloned().unwrap_or_default(),
            "totp" => {
                let t =
                    Totp::parse(e.totp.as_deref().ok_or("Mục này chưa có mã 2FA")?).map_err(err)?;
                t.now().0
            }
            other => {
                let index = |prefix: &str| {
                    other
                        .strip_prefix(prefix)
                        .and_then(|i| i.parse::<usize>().ok())
                };
                if let Some(i) = index("history:") {
                    e.password_history
                        .get(i)
                        .map(|h| h.password.clone())
                        .unwrap_or_default()
                } else if let Some(i) = index("url:") {
                    e.urls.get(i).cloned().unwrap_or_default()
                } else {
                    return Err(err(format!("Trường không hợp lệ: {field}")));
                }
            }
        };
        if v.is_empty() {
            return Err("Trường này đang trống".into());
        }
        Ok(Zeroizing::new(v))
    }

    pub fn totp(&self, id: &str) -> AppResult<TotpCode> {
        let e = self.entry(id)?;
        let t = Totp::parse(e.totp.as_deref().ok_or("Mục này chưa có mã 2FA")?).map_err(err)?;
        let (code, remaining) = t.now();
        Ok(TotpCode {
            code,
            remaining,
            period: t.period,
        })
    }

    // ------------------------------------------------------------------ sửa

    pub fn save_entry(&mut self, input: EntryInput) -> AppResult<(String, SyncResult)> {
        let title = input.title.as_deref().map(str::trim);
        if title == Some("") || (input.id.is_none() && title.is_none()) {
            return Err("Tiêu đề không được để trống".into());
        }
        let totp = match input.totp.as_ref().map(|t| t.trim()) {
            None => None,
            Some("") => Some(None),
            Some(t) => {
                Totp::parse(t).map_err(err)?;
                Some(Some(t.to_string()))
            }
        };
        let urls = input.urls.as_deref().map(clean_list);
        let tags = input.tags.as_deref().map(clean_list);
        let existing = input.id.clone().filter(|id| !id.is_empty());
        let saved = self.mutate(|v| match existing {
            Some(id) => {
                v.update(&id, |e| {
                    if let Some(t) = title {
                        e.title = t.to_string();
                    }
                    if let Some(u) = &input.username {
                        e.username = u.trim().to_string();
                    }
                    if let Some(p) = &input.password {
                        e.password = p.to_string();
                    }
                    if let Some(u) = urls {
                        e.urls = u;
                    }
                    if let Some(n) = &input.notes {
                        e.notes = n.to_string();
                    }
                    if let Some(t) = tags {
                        e.tags = t;
                    }
                    if let Some(f) = input.favorite {
                        e.favorite = f;
                    }
                    if let Some(t) = totp {
                        e.totp = t;
                    }
                })?;
                Ok(id)
            }
            None => {
                let mut e = Entry::new(title.unwrap_or_default());
                e.username = input.username.as_deref().unwrap_or("").trim().to_string();
                e.password = input
                    .password
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                e.urls = urls.unwrap_or_default();
                e.notes = input
                    .notes
                    .as_ref()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                e.tags = tags.unwrap_or_default();
                e.favorite = input.favorite.unwrap_or(false);
                e.totp = totp.flatten();
                Ok(v.add(e))
            }
        })?;
        // Đã lưu ⇒ bản nháp của form này không còn cần (xoá trong CÙNG lệnh, để một lần app chết
        // giữa "đã lưu" và "đã xoá nháp" không thể làm sống lại một bản nháp cũ).
        let _ = self.set_draft(None);
        Ok(saved)
    }

    /// Xoá = chuyển vào thùng rác.
    pub fn delete_entry(&mut self, id: &str) -> AppResult<SyncResult> {
        Ok(self.mutate(|v| v.delete(id))?.1)
    }

    pub fn toggle_favorite(&mut self, id: &str) -> AppResult<bool> {
        let (fav, r) = self.mutate(|v| {
            let now = !v
                .get(id)
                .ok_or_else(|| VaultError::EntryNotFound(id.to_string()))?
                .favorite;
            v.update(id, |e| e.favorite = now)?;
            Ok(now)
        })?;
        self.defer_notices(r);
        Ok(fav)
    }

    // ------------------------------------------------------------------ thùng rác

    pub fn list_trash(&self) -> AppResult<Vec<TrashItem>> {
        let mut items: Vec<TrashItem> = self
            .vault()?
            .trash()
            .iter()
            .map(|e| TrashItem {
                id: e.id.clone(),
                title: e.title.clone(),
                username: e.username.clone(),
                deleted_at: e.trashed_at(),
            })
            .collect();
        items.sort_by_key(|i| std::cmp::Reverse(i.deleted_at));
        Ok(items)
    }

    pub fn restore_entry(&mut self, id: &str) -> AppResult<()> {
        let ((), r) = self.mutate(|v| v.restore(id))?;
        self.defer_notices(r);
        Ok(())
    }

    /// Xoá vĩnh viễn một mục trong thùng rác (trên mọi thiết bị).
    pub fn purge_entry(&mut self, id: &str) -> AppResult<()> {
        let ((), r) = self.mutate(|v| {
            if v.get_trashed(id).is_none() {
                return Err(VaultError::EntryNotFound(id.to_string()));
            }
            v.purge(id)
        })?;
        self.defer_notices(r);
        Ok(())
    }

    /// "Dọn sạch thùng rác": xoá vĩnh viễn ĐÚNG các mục `ids` mà người dùng đã thấy khi bấm xác
    /// nhận. Mục mà máy khác vừa chuyển vào thùng rác trong lúc đó (được gộp về ngay trước khi xoá)
    /// KHÔNG bị xoá — `remaining` cho giao diện biết để báo.
    pub fn empty_trash(&mut self, ids: &[String]) -> AppResult<EmptyTrashView> {
        let ((purged, remaining), r) = self.mutate(|v| {
            let n = v.purge_trashed(ids);
            Ok((n, v.trash().len()))
        })?;
        self.defer_notices(r);
        Ok(EmptyTrashView { purged, remaining })
    }

    // ------------------------------------------------------------------ đồng bộ

    /// Nạp thay đổi từ máy khác, gộp các bản xung đột, ghi lại nếu cần.
    /// Vấn đề với file trên đĩa được trả về trong `problem` (không phải lỗi ném ra) để giao diện
    /// hiện cảnh báo cố định; riêng "mật khẩu đã đổi ở máy khác" thì kho bị khoá và trả lỗi.
    pub fn sync(&mut self) -> AppResult<SyncResult> {
        // Cầu chì: nếu đồng bộ nền cứ phải ghi lại mãi thì chỉ nạp, không ghi nữa.
        let fuse_blown = self.writebacks >= MAX_CONSECUTIVE_WRITEBACKS;
        let v = self.vault_mut()?;
        if v.is_read_only() {
            return Ok(SyncResult::default());
        }
        let result = if fuse_blown {
            v.reload().map(|stats| SyncReport {
                merged_remote: stats,
                ..Default::default()
            })
        } else {
            v.sync()
        };
        match result {
            Ok(report) => {
                let mut out = SyncResult::from_sync(report);
                out.absorb(std::mem::take(&mut self.pending));
                if out.wrote {
                    self.writebacks += 1;
                } else if self.writebacks < MAX_CONSECUTIVE_WRITEBACKS {
                    self.writebacks = 0;
                }
                self.after_success();
                if self.writebacks >= MAX_CONSECUTIVE_WRITEBACKS {
                    out.errors.push(
                        "App đã phải ghi lại file kho nhiều lần liên tiếp nên tạm ngừng tự ghi. \
                         Hãy khoá app trên các máy khác rồi sửa một mục bất kỳ ở máy này."
                            .into(),
                    );
                }
                Ok(out)
            }
            Err(e) => {
                let app = self.vault_error(e);
                if app.code == "password_changed" {
                    return Err(app);
                }
                Ok(SyncResult {
                    problem: Some(app),
                    ..Default::default()
                })
            }
        }
    }

    /// Người dùng đã xác nhận: ghi bản đang mở đè lên file hỏng / tạo lại file đã biến mất.
    /// Trả về nơi file hỏng được cất (nếu có).
    pub fn force_write(&mut self) -> AppResult<Option<String>> {
        self.touch();
        let r = self.vault_mut()?.force_write();
        match r {
            Ok(archived) => {
                self.after_success();
                Ok(archived.map(|p| p.display().to_string()))
            }
            Err(e) => Err(self.vault_error(e)),
        }
    }

    // ------------------------------------------------------------------ master password

    pub fn change_master_password(
        &mut self,
        current: &str,
        new: &str,
    ) -> AppResult<PasswordChangeView> {
        self.touch();
        check_master_strength(new)?;
        let kdf = if self.create_opts.allow_weak_kdf {
            self.create_opts.kdf
        } else {
            KdfParams::DEFAULT
        };
        let v = self.vault_mut()?;
        if !v.verify_password(current.as_bytes()) {
            return Err(AppError::new(
                "wrong_password",
                "Mật khẩu chính hiện tại không đúng",
            ));
        }
        // Lõi tự đồng bộ đầy đủ trước khi đổi (bản xung đột còn dùng khoá hiện tại phải được gộp
        // TRƯỚC khi khoá đó thành khoá cũ), nhưng không trả kết quả của lần đồng bộ ấy. Đồng bộ ở đây
        // trước để những điều cần báo (bản ghi bằng mật khẩu cũ vừa được cất, bản không gộp được…)
        // không bị mất; lần đồng bộ bên trong lõi khi đó không còn gì mới. Lỗi ⇒ CHƯA đổi gì.
        let synced = v.sync();
        let synced = match synced {
            Ok(r) => SyncResult::from_sync(r),
            Err(e) => return Err(self.vault_error(e)),
        };
        self.defer_notices(synced);
        let Some(v) = self.vault.as_mut() else {
            return Err(AppError::locked());
        };
        let r = v.change_password(new.as_bytes(), kdf);
        match r {
            Ok(report) => {
                // Khoá mới ⇒ không còn bản sao lưu nào mở được khoá này bằng mật khẩu khác.
                self.rekey_advised = false;
                self.after_success();
                // Ghi chưa kiểm tra lại được vẫn là đổi XONG: báo trong kết quả, không báo lỗi.
                self.defer_notices(SyncResult {
                    unverified: false,
                    ..SyncResult::from_save(report.save)
                });
                Ok(PasswordChangeView {
                    backups_reencrypted: report.backups_reencrypted,
                    backups_skipped: report.backups_skipped,
                    unverified: report.save.unverified,
                    backups_failed: report.backups_failed,
                })
            }
            Err(e) => Err(self.vault_error(e)),
        }
    }

    // ------------------------------------------------------------------ sức khoẻ mật khẩu

    /// Chuẩn bị các câu hỏi gửi Have I Been Pwned (không chứa mật khẩu). Việc gọi mạng được làm
    /// BÊN NGOÀI khoá phiên để mạng treo không làm treo app và không chặn tự khoá.
    pub fn breach_queries(&self) -> AppResult<Vec<BreachQuery>> {
        Ok(pwv_health::breach_queries(self.vault()?.entries()))
    }

    /// Báo cáo sức khoẻ. `breaches`: kết quả kiểm tra rò rỉ (nếu đã làm xong); `breach_error`:
    /// lý do không kiểm tra được.
    pub fn health(
        &self,
        breaches: Option<&HashMap<String, u64>>,
        breach_error: Option<String>,
    ) -> AppResult<HealthView> {
        use pwv_health::{apply_breaches, offline_report, Issue};
        let v = self.vault()?;
        let mut report = offline_report(v.entries());
        if let Some(found) = breaches {
            apply_breaches(&mut report, found);
        }
        let mut items: Vec<HealthItem> = report
            .issues
            .iter()
            .filter_map(|(id, issues)| {
                v.get(id).map(|e| HealthItem {
                    id: id.clone(),
                    title: e.title.clone(),
                    username: e.username.clone(),
                    severity: issues[0].severity(),
                    issues: issues.iter().map(Issue::describe).collect(),
                })
            })
            .collect();
        items.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        Ok(HealthView {
            score: report.score(),
            checked: report.checked,
            breached: report.count(|i| matches!(i, Issue::Breached { .. })),
            reused: report.count(|i| matches!(i, Issue::Reused { .. })),
            weak: report.count(|i| matches!(i, Issue::Weak { .. })),
            old: report.count(|i| matches!(i, Issue::Old { .. })),
            breach_check_done: report.breach_check_done,
            breach_error,
            items,
        })
    }

    // ------------------------------------------------------------------ nhập CSV

    /// Nhập CSV. KHÔNG tự xoá file: người dùng xem kết quả rồi mới quyết định
    /// (xem [`Session::delete_imported_csv`]).
    pub fn import_csv(&mut self, path: &Path) -> AppResult<ImportView> {
        let size = std::fs::metadata(path).map_err(err)?.len();
        if size > MAX_CSV_BYTES {
            return Err("File CSV quá lớn (tối đa 20 MB)".into());
        }
        let bytes = Zeroizing::new(std::fs::read(path).map_err(err)?);
        // Đọc thử trước để báo đúng lỗi định dạng (thiếu cột mật khẩu, file quá dài…).
        pwv_vault_core::import::import_csv(bytes.as_slice(), &[]).map_err(err)?;
        let (view, r) = self.mutate(|v| {
            // Đọc CSV bên trong giao dịch để việc bỏ trùng dùng dữ liệu vừa gộp từ máy khác.
            let res = pwv_vault_core::import::import_csv(bytes.as_slice(), v.entries())
                .map_err(|e| VaultError::Io(std::io::Error::other(e.to_string())))?;
            let view = ImportView {
                imported: res.entries.len(),
                duplicates: res.duplicates,
                skipped: res.skipped,
                similar: res.similar.clone(),
                bad_totp: res.bad_totp.clone(),
                detected: res.detected.to_string(),
            };
            for e in res.entries {
                v.add_imported(e);
            }
            Ok(view)
        })?;
        self.defer_notices(r);
        self.last_import = Some(path.to_path_buf());
        Ok(view)
    }

    /// Xoá file CSV vừa nhập (chỉ đúng file đó — giao diện không tự chỉ định được file khác).
    pub fn delete_imported_csv(&mut self) -> AppResult<()> {
        let path = self
            .last_import
            .take()
            .ok_or("Không có file CSV nào vừa được nhập")?;
        std::fs::remove_file(&path).map_err(err)
    }

    // ------------------------------------------------------------------ sao lưu

    pub fn backups_dir(&self) -> Option<PathBuf> {
        self.vault
            .as_ref()
            .filter(|v| !v.is_read_only())
            .map(|v| fsutil::backup_dir(v.path()))
    }

    pub fn list_backups(&self) -> AppResult<Vec<BackupView>> {
        let v = self.vault()?;
        Ok(v.backups()
            .into_iter()
            .map(|b| {
                let read = v.read_backup_checked(&b.path).ok();
                BackupView {
                    name: b
                        .path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    kind: match b.kind {
                        BackupKind::Auto => "auto",
                        BackupKind::Merged => "merged",
                        BackupKind::Damaged => "damaged",
                        BackupKind::OldKey => "oldkey",
                    },
                    timestamp: b.timestamp,
                    entries: read.as_ref().map(|(d, _)| d.entries.len()),
                    retired_key: read.is_some_and(|(_, retired)| retired),
                }
            })
            .collect())
    }

    fn backup_path(&self, name: &str) -> AppResult<PathBuf> {
        if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") {
            return Err("Tên bản sao lưu không hợp lệ".into());
        }
        Ok(fsutil::backup_dir(self.vault()?.path()).join(name))
    }

    /// Những mục trong bản sao lưu KHÁC với hiện tại (đã sửa, đang trong thùng rác, hoặc không còn).
    pub fn backup_diff(&mut self, name: &str) -> AppResult<Vec<BackupEntryView>> {
        self.touch();
        let path = self.backup_path(name)?;
        let v = self.vault()?;
        let old = v.read_backup(&path)?;
        let mut out: Vec<BackupEntryView> = old
            .entries
            .iter()
            .filter_map(|e| {
                let (status, changed_fields) = match (v.get(&e.id), v.get_trashed(&e.id)) {
                    (Some(cur), _) => {
                        let d = diff_fields(e, cur);
                        if d.is_empty() {
                            return None;
                        }
                        ("changed", d)
                    }
                    (None, Some(_)) => ("in_trash", Vec::new()),
                    (None, None) => ("missing", Vec::new()),
                };
                Some(BackupEntryView {
                    id: e.id.clone(),
                    title: e.title.clone(),
                    username: e.username.clone(),
                    status,
                    changed_fields,
                    updated_at: e.updated_at,
                })
            })
            .collect();
        out.sort_by_key(|e| e.title.to_lowercase());
        Ok(out)
    }

    /// Đưa các mục `ids` trở về phiên bản trong bản sao lưu `name`. Đây là "một lần sửa mới" nên
    /// lan sang mọi thiết bị; mật khẩu đang dùng (nếu khác) được giữ trong lịch sử của mục.
    pub fn restore_from_backup(&mut self, name: &str, ids: &[String]) -> AppResult<usize> {
        let path = self.backup_path(name)?;
        let old = self.vault()?.read_backup(&path)?;
        let (n, r) = self.mutate(|v| {
            Ok(ids
                .iter()
                .filter_map(|id| old.get(id))
                .filter(|e| v.reinstate(e))
                .count())
        })?;
        self.defer_notices(r);
        Ok(n)
    }

    // ------------------------------------------------------------------ chuyển kho / cài đặt

    /// Chuyển kho đang mở sang vị trí mới và ghi nhớ vị trí đó. `copy_only` ("lưu sang chỗ khác"
    /// từ cảnh báo file kho có vấn đề): CHỈ ghi một bản sao, không đụng gì ở chỗ cũ.
    ///
    /// Lỗi ở đây là lỗi của VIỆC CHUYỂN (thường là ở chỗ mới: ổ đĩa không có, file đã tồn tại…):
    /// trả mã `move_failed` và KHÔNG ghi nhận thành vấn đề của file kho hiện tại.
    pub fn move_vault(&mut self, new_path: &Path, copy_only: bool) -> AppResult<MoveView> {
        self.touch();
        let old_path = self.vault()?.path().display().to_string();
        let v = self.vault_mut()?;
        let r = if copy_only {
            v.copy_to(new_path)
        } else {
            v.move_to(new_path)
        };
        let r = match r {
            Ok(r) => r,
            Err(VaultError::PasswordChangedElsewhere) => {
                return Err(self.vault_error(VaultError::PasswordChangedElsewhere))
            }
            Err(e) => {
                return Err(AppError::new(
                    "move_failed",
                    format!("Chưa ghi được sang vị trí mới: {e}. Kho vẫn ở vị trí cũ."),
                ))
            }
        };
        let new_path = self.vault()?.path().to_path_buf();
        self.update_config(|c| c.set_vault_path(&new_path))?;
        self.after_success();
        Ok(MoveView {
            old_path,
            new_path: new_path.display().to_string(),
            backups_moved: r.backups_moved,
            old_removed: r.old_removed,
            conflicts_merged: r.conflicts_merged,
            rescued: r.rescued,
        })
    }

    // ------------------------------------------------------------------ bản nháp & mật khẩu vừa tạo

    fn stash_path(&self, id: &str) -> Option<PathBuf> {
        Some(
            self.rescue_dir
                .as_ref()?
                .join(format!("stash-{}.bin", safe_id(id)?)),
        )
    }

    /// Kho đang mở, ghi được (bản nháp chỉ có ở máy tính).
    fn writable_vault(&self) -> AppResult<&Vault> {
        let v = self.vault()?;
        if v.is_read_only() {
            return Err(VaultError::ReadOnly.into());
        }
        Ok(v)
    }

    /// Mở stash của kho đang mở: bản trong RAM (giữ qua lần khoá) nếu là của kho này, không thì file
    /// trong thư mục riêng của app. Không mở được (khoá khác, hỏng) ⇒ coi như trống; file đó được
    /// để nguyên cho tới lần ghi đầu tiên, khi nó được đổi tên để giữ lại.
    fn load_stash(&mut self) -> StashData {
        let Ok(v) = self.writable_vault() else {
            return StashData::default();
        };
        let id = v.vault_id().to_string();
        let (sealed, from_disk) = match &self.stash {
            Some(st) if st.vault_id == id => (Some(st.sealed.clone()), false),
            _ => (
                self.stash_path(&id)
                    .and_then(|p| fsutil::read_retry_capped(&p, MAX_STASH_FILE).ok().flatten()),
                true,
            ),
        };
        let Some(sealed) = sealed else {
            return StashData::default();
        };
        let opened = v
            .open_local(STASH_PURPOSE, &sealed)
            .and_then(|pt| serde_json::from_slice::<StashData>(&pt).ok());
        match opened {
            Some(mut data) => {
                data.prune(pwv_vault_core::model::now_ms());
                data
            }
            None => {
                if from_disk {
                    self.stash_unreadable = Some(id);
                }
                StashData::default()
            }
        }
    }

    /// Niêm phong và cất stash: trong RAM, và (cố gắng) ghi nguyên tử vào thư mục riêng của app.
    fn store_stash(&mut self, mut data: StashData) -> AppResult<()> {
        data.prune(pwv_vault_core::model::now_ms());
        let v = self.writable_vault()?;
        let id = v.vault_id().to_string();
        let empty = data.is_empty();
        let plain = Zeroizing::new(serde_json::to_vec(&data).map_err(err)?);
        drop(data);
        let sealed = v.seal_local(STASH_PURPOSE, &plain)?;
        drop(plain);
        if let Some(p) = self.stash_path(&id) {
            if self.stash_unreadable.as_deref() == Some(id.as_str()) && p.exists() {
                let kept = p.with_file_name(format!(
                    "stash-{id}.unreadable-{}.bin",
                    pwv_vault_core::model::now_ms()
                ));
                let _ = std::fs::rename(&p, kept);
            }
            self.stash_unreadable = None;
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if empty {
                let _ = std::fs::remove_file(&p);
            } else {
                let _ = fsutil::atomic_write(&p, &sealed);
            }
        }
        self.stash = Some(SealedStash {
            vault_id: id,
            sealed,
        });
        Ok(())
    }

    /// Đặt (`Some`) hoặc xoá (`None`) bản nháp. Bản nháp quá lớn ⇒ không giữ (bản cũ cũng bị xoá
    /// để không bao giờ khôi phục một bản nháp lỗi thời) và trả lỗi `draft_too_large`.
    pub fn set_draft(&mut self, draft: Option<Zeroizing<String>>) -> AppResult<()> {
        self.writable_vault()?;
        let too_large = draft.as_ref().is_some_and(|d| d.len() > MAX_DRAFT_BYTES);
        let mut data = self.load_stash();
        if data.draft.is_none() && draft.is_none() && !too_large {
            return Ok(());
        }
        data.draft = if too_large { None } else { draft };
        self.store_stash(data)?;
        if too_large {
            return Err(AppError::new(
                "draft_too_large",
                "Bản nháp quá lớn, chưa được giữ.",
            ));
        }
        Ok(())
    }

    /// Bản nháp đang giữ (nếu có).
    pub fn draft(&mut self) -> AppResult<Option<String>> {
        self.writable_vault()?;
        Ok(self.load_stash().draft.map(|d| d.to_string()))
    }

    /// Ghi nhớ một mật khẩu vừa rời bộ tạo mật khẩu (đã sao chép / đã dùng). `label`: tiêu đề mục
    /// đang sửa, nếu có. Giữ 20 mật khẩu mới nhất, không quá 30 ngày.
    pub fn record_generated(
        &mut self,
        value: Zeroizing<String>,
        label: Option<String>,
    ) -> AppResult<()> {
        self.touch();
        self.writable_vault()?;
        if value.is_empty() {
            return Err("Không có gì để ghi nhớ".into());
        }
        let label = label
            .map(|l| l.trim().chars().take(200).collect::<String>())
            .filter(|l| !l.is_empty());
        let mut data = self.load_stash();
        let now = pwv_vault_core::model::now_ms();
        if let Some(g) = data.generated.iter_mut().find(|g| g.value == value) {
            g.at = now;
            if label.is_some() {
                g.label = label;
            }
        } else {
            let mut n = now;
            while data.generated.iter().any(|g| g.id == format!("g{n}")) {
                n += 1;
            }
            data.generated.push(GeneratedItem {
                id: format!("g{n}"),
                value,
                at: now,
                label,
            });
        }
        self.store_stash(data)
    }

    /// Các mật khẩu vừa tạo (mới nhất trước), KHÔNG kèm giá trị.
    pub fn list_generated(&mut self) -> AppResult<Vec<GeneratedView>> {
        self.writable_vault()?;
        Ok(self
            .load_stash()
            .generated
            .iter()
            .map(|g| GeneratedView {
                id: g.id.clone(),
                at: g.at,
                label: g.label.clone(),
            })
            .collect())
    }

    /// Giá trị của một mật khẩu vừa tạo (để hiện hoặc sao chép).
    pub fn generated_value(&mut self, id: &str) -> AppResult<Zeroizing<String>> {
        self.touch();
        self.writable_vault()?;
        self.load_stash()
            .generated
            .iter()
            .find(|g| g.id == id)
            .map(|g| g.value.clone())
            .ok_or_else(|| {
                AppError::new(
                    "not_found",
                    "Không còn mật khẩu này trong danh sách (đã quá 30 ngày hoặc đã bị xoá)",
                )
            })
    }

    pub fn clear_generated(&mut self) -> AppResult<()> {
        self.writable_vault()?;
        let mut data = self.load_stash();
        data.generated.clear();
        self.store_stash(data)
    }

    // ------------------------------------------------------------------ bản lưu riêng trên máy này

    fn local_copy_path(&self, id: &str) -> Option<PathBuf> {
        Some(
            self.rescue_dir
                .as_ref()?
                .join(format!("last-{}.pwv", safe_id(id)?)),
        )
    }

    /// Thời điểm (ms) của bản lưu riêng của kho đã cấu hình, nếu có (cho màn hình "không thấy file").
    fn configured_local_copy_at(&self) -> Option<i64> {
        let id = self.config.last_vault_id.as_deref()?;
        let m = std::fs::metadata(self.local_copy_path(id)?).ok()?;
        let t = m
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(i64::try_from(t.as_millis()).unwrap_or(i64::MAX))
    }

    /// Đổi tên một bản lưu riêng không gộp được thành tên bản cứu hộ (`<vault_id>-<ms>.pwv`), để nó
    /// vào luồng "bản cứu hộ" sẵn có (được giữ, đếm, thử gộp lại) thay vì bị ghi đè.
    fn preserve_local_copy(&self, p: &Path, id: &str) {
        let Some(dir) = p.parent() else {
            return;
        };
        let mut ts = pwv_vault_core::model::now_ms();
        let mut target = dir.join(format!("{id}-{ts}.pwv"));
        while target.exists() {
            ts += 1;
            target = dir.join(format!("{id}-{ts}.pwv"));
        }
        let _ = std::fs::rename(p, target);
    }

    /// Ghi (nguyên tử, cố gắng) toàn bộ kho đang mở vào thư mục riêng của app: `last-<id>.pwv`.
    /// Gọi sau mỗi lần đọc/ghi thành công và khi khoá; chỉ ghi khi trạng thái kho đổi.
    fn write_local_copy(&mut self) {
        let Some(v) = self.vault.as_ref().filter(|v| !v.is_read_only()) else {
            return;
        };
        let id = v.vault_id().to_string();
        // Dấu nhận biết "trạng thái kho đã đổi". Số mục / số mục trong thùng rác cũng tham gia: một lần
        // gộp chỉ mang về thứ CŨ hơn lần sửa gần nhất của máy này (mục máy khác thêm, lệnh xoá của
        // máy khác) không làm đổi `modified_at`, nhưng bản lưu riêng vẫn nên có nó.
        let sig = (
            id.clone(),
            v.modified_at(),
            v.key_changed_at(),
            v.key_tag(),
            v.entries().len(),
            v.trash().len(),
        );
        let Some(p) = self.local_copy_path(&id) else {
            return;
        };
        if self.local_written.as_ref() == Some(&sig) && p.exists() {
            return;
        }
        let Ok(bytes) = v.export_bytes() else {
            return;
        };
        // Bản có sẵn mà phiên này chưa gộp / kiểm tra được thì không bao giờ bị ghi đè.
        if self.local_checked.as_deref() != Some(id.as_str()) && p.exists() {
            self.preserve_local_copy(&p, &id);
        }
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if fsutil::atomic_write(&p, &bytes).is_ok() {
            self.local_written = Some(sig);
            self.local_checked = Some(id);
        }
    }

    /// Gộp bản lưu riêng của kho đang mở. Trả về số mục thay đổi nếu nó thêm được gì. Không gộp được
    /// (khoá mà kho này không biết, hỏng) ⇒ đổi tên thành bản cứu hộ ngay (được giữ và đếm).
    fn merge_local_copy(&mut self) -> Option<MergeStats> {
        let id = self
            .vault
            .as_ref()
            .filter(|v| !v.is_read_only())?
            .vault_id()
            .to_string();
        let p = self.local_copy_path(&id)?;
        if !p.exists() {
            self.local_checked = Some(id);
            return None;
        }
        let r = self.vault.as_mut()?.merge_file(&p);
        self.local_checked = Some(id.clone());
        match r {
            Ok(m) => m.changed().then_some(m),
            Err(_) => {
                self.preserve_local_copy(&p, &id);
                self.local_written = None;
                None
            }
        }
    }

    /// Kho đang khoá và file kho đã cấu hình không còn: ghi bản lưu riêng của nó ra đúng vị trí đó.
    /// Không bao giờ ghi đè một file đã có (kể cả file vừa được dịch vụ đồng bộ đưa về).
    pub fn restore_local_copy(&mut self) -> AppResult<()> {
        if self.vault.is_some() {
            return Err("Hãy khoá kho trước".into());
        }
        let path = self.config.vault.clone().ok_or("Chưa chọn file kho")?;
        let id = self
            .config
            .last_vault_id
            .clone()
            .ok_or("Máy này không có bản lưu riêng của kho này")?;
        let src = self
            .local_copy_path(&id)
            .ok_or("Máy này không có bản lưu riêng của kho này")?;
        let bytes = fsutil::read_retry_capped(&src, fsutil::MAX_VAULT_FILE)
            .map_err(err)?
            .ok_or("Bản lưu riêng quá lớn")?;
        match Vault::peek(&src) {
            Ok(info) if info.vault_id == id => {}
            _ => return Err("Bản lưu riêng trên máy này không đọc được".into()),
        }
        fsutil::write_new(&path, &bytes).map_err(|e| match e {
            VaultError::AlreadyExists(_) => AppError::new(
                "error",
                "Đã có một file ở vị trí kho (có thể dịch vụ đồng bộ vừa đưa file về) — app không ghi đè. Hãy bấm “Thử lại”.",
            ),
            other => AppError::from(other),
        })?;
        self.lock_note = None;
        Ok(())
    }

    // ------------------------------------------------------------------ đổi khoá một lần (0.1.x)

    /// Kho này từng được đổi mật khẩu chính bằng bản 0.1.x (đổi mật khẩu mà giữ nguyên khoá)? Quét
    /// thư mục sao lưu một lần cho mỗi khoá (ghi nhớ trong cấu hình khi không thấy gì).
    pub fn check_rekey(&mut self) -> AppResult<bool> {
        let v = self.vault()?;
        if v.is_read_only() {
            return Ok(false);
        }
        let (id, tag) = (v.vault_id().to_string(), v.key_tag());
        if self.config.wrap_scan_clean(&id, tag) {
            self.rekey_advised = false;
            return Ok(false);
        }
        let Ok(n) = v.backups_under_other_password() else {
            return Ok(self.rekey_advised);
        };
        if n == 0 {
            self.rekey_advised = false;
            let _ = self.update_config(|c| {
                c.set_wrap_scan_clean(&id, tag);
            });
        } else {
            self.rekey_advised = true;
        }
        Ok(self.rekey_advised)
    }

    // ------------------------------------------------------------------ chọn file kho

    /// File vừa chọn có vẻ là BẢN XUNG ĐỘT (do dịch vụ đồng bộ tạo) của một file kho khác trong cùng
    /// thư mục: cùng mã kho, và tên của nó bắt đầu bằng tên file kia rồi dài hơn (`vault (1)`,
    /// `vault (conflicted copy …)`, `vault-PC2`). Chỉ đọc header, không cần mật khẩu.
    pub fn conflict_hint(picked: &Path) -> Option<ConflictHint> {
        let info = Vault::peek(picked).ok()?;
        let stem = picked.file_stem()?.to_string_lossy().to_string();
        let dir = picked.parent()?;
        let mut best: Option<(usize, PathBuf)> = None;
        for p in std::fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .take(2000)
        {
            if p == picked || p.extension().is_none_or(|e| !e.eq_ignore_ascii_case("pwv")) {
                continue;
            }
            let Some(other) = p.file_stem().map(|s| s.to_string_lossy().to_string()) else {
                continue;
            };
            if other.is_empty() || stem.len() <= other.len() || !stem.starts_with(&other) {
                continue;
            }
            if best.as_ref().is_some_and(|(n, _)| *n >= other.len()) {
                continue;
            }
            if Vault::peek(&p).is_ok_and(|o| o.vault_id == info.vault_id) {
                best = Some((other.len(), p));
            }
        }
        let (_, orig) = best?;
        let name = |p: &Path| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        };
        Some(ConflictHint {
            picked_name: name(picked),
            original_name: name(&orig),
            original_path: orig.display().to_string(),
        })
    }

    pub fn settings(&self) -> Settings {
        Settings {
            auto_lock_minutes: self.config.auto_lock_minutes,
            clipboard_clear_secs: self.config.clipboard_clear_secs,
            check_updates: self.config.check_updates,
        }
    }

    pub fn set_settings(&mut self, s: Settings) -> AppResult<()> {
        self.update_config(|c| {
            c.auto_lock_minutes = s.auto_lock_minutes.min(MAX_AUTO_LOCK_MINUTES);
            c.clipboard_clear_secs = s
                .clipboard_clear_secs
                .clamp(CLIPBOARD_CLEAR_SECS_MIN, CLIPBOARD_CLEAR_SECS_MAX);
            c.check_updates = s.check_updates;
        })
    }
}

/// Lỗi `older_than_seen`: bản dựng lại cũ hơn dữ liệu máy này từng thấy (kèm hai mốc thời gian).
fn older_than_seen(file_modified_at: i64, seen_modified_at: i64) -> AppError {
    AppError {
        code: "older_than_seen".into(),
        message: "Bản dựng lại được cũ hơn dữ liệu máy này từng thấy — có thể các bản sao lưu mới hơn chưa đồng bộ về máy này.".into(),
        detail: Some(ErrorDetail {
            file_modified_at,
            seen_modified_at,
        }),
    }
}

pub fn generate(req: GenRequest) -> AppResult<Generated> {
    let (value, entropy_bits) = match req {
        GenRequest::Password(o) => (generate_password(&o).map_err(err)?, o.entropy_bits()),
        GenRequest::Passphrase(o) => (generate_passphrase(&o).map_err(err)?, o.entropy_bits()),
    };
    let strength = estimate_strength(&value, &[]);
    Ok(Generated {
        value: value.to_string(),
        entropy_bits,
        strength,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwv_vault_core::fsutil::backup_dir;

    fn session() -> (Session, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        let s = Session {
            vault: None,
            config: Config::default(),
            activity: Arc::new(Activity::new()),
            create_opts: CreateOptions {
                kdf: KdfParams::INSECURE_TEST,
                allow_weak_kdf: true,
            },
            persist_config: false,
            disk_problem: None,
            lock_note: None,
            rescue_dir: Some(d.path().join("rescue")),
            writebacks: 0,
            last_import: None,
            pending: SyncResult::default(),
            stash: None,
            stash_unreadable: None,
            local_checked: None,
            local_written: None,
            rekey_advised: false,
        };
        (s, d)
    }

    const MP: &str = "ngua-pin-kep-dung-bien-xanh-42";
    const MP2: &str = "mot-cum-tu-moi-rat-dai-khac-han-77";

    fn z(s: &str) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(s.to_string()))
    }

    fn input(title: &str, pw: Option<&str>) -> EntryInput {
        EntryInput {
            title: Some(title.into()),
            username: Some("u".into()),
            password: pw.and_then(z),
            urls: Some(vec![" https://a.vn ".into(), "".into()]),
            ..Default::default()
        }
    }

    fn patch(id: &str) -> EntryInput {
        EntryInput {
            id: Some(id.into()),
            ..Default::default()
        }
    }

    fn open(s: &mut Session, d: &tempfile::TempDir) -> PathBuf {
        let p = d.path().join("kho").join("v.pwv");
        s.create_vault(&p, MP).unwrap();
        p
    }

    fn titles(s: &Session) -> Vec<String> {
        let mut t: Vec<String> = s.list("").unwrap().into_iter().map(|e| e.title).collect();
        t.sort();
        t
    }

    /// Một "máy khác" mở cùng file.
    fn other_device(p: &Path) -> Vault {
        Vault::open_with(
            p,
            MP.as_bytes(),
            OpenOptions {
                allow_weak_kdf: true,
            },
        )
        .unwrap()
    }

    #[test]
    fn rejects_weak_master_password() {
        assert!(check_master_strength("123456789012").is_err());
        assert!(check_master_strength("short").is_err());
        assert_eq!(
            check_master_strength("nguyenvanan1990").unwrap_err().code,
            "weak_password"
        );
        assert!(check_master_strength(MP).is_ok());
        let (mut s, d) = session();
        assert!(s
            .create_vault(&d.path().join("x.pwv"), "Matkhau@2024")
            .is_err());
        assert!(!d.path().join("x.pwv").exists());
    }

    #[test]
    fn crud_and_secrets_stay_in_rust() {
        let (mut s, d) = session();
        open(&mut s, &d);
        let mut i = input("Gmail", Some("S3cret-pass!"));
        i.notes = z("mã khôi phục BÍ-MẬT-NOTE");
        let (id, _) = s.save_entry(i).unwrap();
        let list = s.list("").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].url.as_deref(), Some("https://a.vn"));
        // DTO gửi sang JS không chứa mật khẩu lẫn ghi chú.
        let json = serde_json::to_string(&s.detail(&id).unwrap()).unwrap()
            + &serde_json::to_string(&list).unwrap();
        assert!(!json.contains("S3cret-pass!") && !json.contains("BÍ-MẬT-NOTE"));
        assert!(s.detail(&id).unwrap().has_notes);
        assert_eq!(s.reveal_password(&id).unwrap(), "S3cret-pass!");
        assert_eq!(s.reveal_notes(&id).unwrap(), "mã khôi phục BÍ-MẬT-NOTE");
        assert_eq!(
            *s.field_value(&id, "notes").unwrap(),
            "mã khôi phục BÍ-MẬT-NOTE"
        );

        // Sửa chỉ tiêu đề ⇒ mọi trường khác giữ nguyên.
        let mut upd = patch(&id);
        upd.title = Some("Gmail 2".into());
        s.save_entry(upd).unwrap();
        assert_eq!(s.reveal_password(&id).unwrap(), "S3cret-pass!");
        assert_eq!(s.detail(&id).unwrap().title, "Gmail 2");
        assert_eq!(s.detail(&id).unwrap().urls, ["https://a.vn"]);

        // Đổi password ⇒ vào lịch sử, và sao chép được mật khẩu cũ từ Rust.
        let mut upd = patch(&id);
        upd.password = z("new");
        s.save_entry(upd).unwrap();
        assert_eq!(s.history(&id).unwrap()[0].password, "S3cret-pass!");
        assert_eq!(*s.field_value(&id, "history:0").unwrap(), "S3cret-pass!");
        assert!(s.field_value(&id, "history:7").is_err());
        assert!(s.field_value(&id, "khong-co").is_err());

        // Mục có nhiều địa chỉ: sao chép được từng địa chỉ.
        let mut upd = patch(&id);
        upd.urls = Some(vec!["https://a.vn".into(), "https://b.vn/login".into()]);
        s.save_entry(upd).unwrap();
        assert_eq!(*s.field_value(&id, "url").unwrap(), "https://a.vn");
        assert_eq!(*s.field_value(&id, "url:0").unwrap(), "https://a.vn");
        assert_eq!(*s.field_value(&id, "url:1").unwrap(), "https://b.vn/login");
        assert!(s.field_value(&id, "url:2").is_err());
        assert!(s.field_value(&id, "url:x").is_err());

        // Tiêu đề rỗng bị từ chối, cả khi tạo lẫn khi sửa.
        let mut bad = patch(&id);
        bad.title = Some("  ".into());
        assert!(s.save_entry(bad).is_err());
        assert!(s.save_entry(EntryInput::default()).is_err());

        s.delete_entry(&id).unwrap();
        assert!(s.list("").unwrap().is_empty());
        assert_eq!(s.detail(&id).unwrap_err().code, "not_found");
    }

    #[test]
    fn trash_restore_purge() {
        let (mut s, d) = session();
        open(&mut s, &d);
        let (a, _) = s.save_entry(input("A", Some("a"))).unwrap();
        let (b, _) = s.save_entry(input("B", Some("b"))).unwrap();
        s.delete_entry(&a).unwrap();
        s.delete_entry(&b).unwrap();
        assert_eq!(s.status().trash_count, 2);
        assert_eq!(s.list_trash().unwrap().len(), 2);
        s.restore_entry(&a).unwrap();
        assert_eq!(titles(&s), ["A"]);
        assert_eq!(s.reveal_password(&a).unwrap(), "a");
        // Chỉ xoá vĩnh viễn được thứ đang nằm trong thùng rác.
        assert_eq!(s.purge_entry(&a).unwrap_err().code, "not_found");
        s.purge_entry(&b).unwrap();
        assert!(s.list_trash().unwrap().is_empty());
        s.delete_entry(&a).unwrap();
        let seen: Vec<String> = s.list_trash().unwrap().into_iter().map(|i| i.id).collect();
        let r = s.empty_trash(&seen).unwrap();
        assert_eq!((r.purged, r.remaining), (1, 0));
        assert_eq!(s.status().trash_count, 0);
    }

    /// "Dọn sạch thùng rác" chỉ xoá những mục người dùng đã thấy khi xác nhận: mục máy khác vừa
    /// chuyển vào thùng rác trong lúc đó còn nguyên, và được báo lại.
    #[test]
    fn empty_trash_only_purges_the_items_the_owner_saw() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        let (a, _) = s.save_entry(input("A", Some("a"))).unwrap();
        let (b, _) = s.save_entry(input("B", Some("b"))).unwrap();
        s.delete_entry(&a).unwrap();
        let seen: Vec<String> = s.list_trash().unwrap().into_iter().map(|i| i.id).collect();
        assert_eq!(seen, std::slice::from_ref(&a));
        // Máy khác chuyển B vào thùng rác trước khi lệnh xoá chạy.
        let mut pc2 = other_device(&p);
        pc2.transact(|v| v.delete(&b)).unwrap();
        let r = s.empty_trash(&seen).unwrap();
        assert_eq!((r.purged, r.remaining), (1, 1));
        let left: Vec<String> = s.list_trash().unwrap().into_iter().map(|i| i.id).collect();
        assert_eq!(left, [b]);
    }

    #[test]
    fn totp_set_keep_remove() {
        let (mut s, d) = session();
        open(&mut s, &d);
        let mut i = input("G", Some("x"));
        i.totp = z("JBSWY3DPEHPK3PXP");
        let (id, _) = s.save_entry(i).unwrap();
        assert_eq!(s.totp(&id).unwrap().code.len(), 6);
        assert!(!serde_json::to_string(&s.detail(&id).unwrap())
            .unwrap()
            .contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(s.reveal_totp_secret(&id).unwrap(), "JBSWY3DPEHPK3PXP");
        let mut i = patch(&id);
        i.notes = z("x");
        s.save_entry(i).unwrap();
        assert!(s.detail(&id).unwrap().has_totp, "None = giữ nguyên");
        let mut i = patch(&id);
        i.totp = z("");
        s.save_entry(i).unwrap();
        assert!(!s.detail(&id).unwrap().has_totp, "chuỗi rỗng = xoá");
        let mut bad = input("B", None);
        bad.totp = z("!!");
        assert!(s.save_entry(bad).is_err());
    }

    #[test]
    fn auto_lock() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.config.auto_lock_minutes = 1;
        assert!(!s.auto_lock_if_idle());
        s.activity.backdate(Duration::from_secs(61));
        assert!(s.auto_lock_if_idle());
        assert!(s.vault.is_none());
        assert_eq!(s.list("").unwrap_err().code, "locked");
        // Màn hình mở khoá nói rõ vì sao kho bị khoá; một lệnh khoá thừa (đóng cửa sổ, trang được
        // nạp lại) không xoá mất lời nhắn đó, còn mở khoá lại thì xoá.
        assert!(s.status().lock_note.is_some());
        s.lock();
        assert!(s.status().lock_note.is_some());
        s.unlock(&p, MP).unwrap();
        assert!(s.status().lock_note.is_none());
        // Người dùng tự khoá thì không cần lời nhắn.
        s.lock();
        assert!(s.vault.is_none() && s.status().lock_note.is_none());
    }

    /// Lỗi 0.1.2: máy B (chưa thấy thay đổi của máy A) chỉ cần bấm ★ hoặc lưu form là đè mất mật
    /// khẩu mới và mã 2FA mà máy A vừa đặt.
    #[test]
    fn editing_on_a_stale_device_does_not_revert_other_devices_changes() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        let (id, _) = s.save_entry(input("Bank", Some("old"))).unwrap();
        // Máy khác đổi mật khẩu + thêm 2FA và ghi vào file.
        let mut pc2 = other_device(&p);
        pc2.transact(|v| {
            v.update(&id, |e| {
                e.password = "new-from-pc2".into();
                e.totp = Some("JBSWY3DPEHPK3PXP".into());
            })
        })
        .unwrap();
        // Máy này (form mở từ trước, chưa đồng bộ) bấm ★ rồi sửa ghi chú.
        assert!(s.toggle_favorite(&id).unwrap());
        let mut upd = patch(&id);
        upd.notes = z("ghi chú mới");
        let (_, r) = s.save_entry(upd).unwrap();
        assert!(!r.changed, "lần ★ trước đó đã gộp thay đổi của máy kia rồi");
        assert_eq!(s.reveal_password(&id).unwrap(), "new-from-pc2");
        assert!(s.detail(&id).unwrap().has_totp && s.detail(&id).unwrap().favorite);
        pc2.sync().unwrap();
        let e = pc2.get(&id).unwrap();
        assert_eq!(
            (e.password.as_str(), e.notes.as_str()),
            ("new-from-pc2", "ghi chú mới")
        );
        assert!(e.favorite && e.totp.is_some());
    }

    #[test]
    fn change_master_password_requires_current_and_rotates_key() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        assert_eq!(
            s.change_master_password("sai", MP2).unwrap_err().code,
            "wrong_password"
        );
        assert_eq!(
            s.change_master_password(MP, "Matkhau@2024")
                .unwrap_err()
                .code,
            "weak_password"
        );
        let r = s.change_master_password(MP, MP2).unwrap();
        assert!(r.backups_reencrypted >= 1 && r.backups_skipped == 0);
        let o = OpenOptions {
            allow_weak_kdf: true,
        };
        assert!(Vault::open_with(&p, MP2.as_bytes(), o).is_ok());
        assert!(Vault::open_with(&p, MP.as_bytes(), o).is_err());
        for b in pwv_vault_core::fsutil::list_backups(&p) {
            assert!(Vault::open_with(&b.path, MP.as_bytes(), o).is_err());
        }
    }

    #[test]
    fn other_device_changing_the_password_locks_this_one_with_an_explanation() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let mut pc2 = other_device(&p);
        pc2.change_password(MP2.as_bytes(), KdfParams::INSECURE_TEST)
            .unwrap();
        let e = s.save_entry(input("B", Some("b"))).unwrap_err();
        assert_eq!(e.code, "password_changed");
        assert!(s.vault.is_none(), "kho bị khoá để nhập mật khẩu mới");
        assert!(s.status().lock_note.is_some());
        // Mở lại bằng mật khẩu mới: dùng tiếp bình thường, mục chưa ghi được không hề bị lưu.
        s.unlock(&p, MP2).unwrap();
        assert!(s.status().lock_note.is_none());
        assert_eq!(titles(&s), ["A"]);
        // Đồng bộ nền cũng khoá theo cách đó.
        let mut pc3 = Vault::open_with(
            &p,
            MP2.as_bytes(),
            OpenOptions {
                allow_weak_kdf: true,
            },
        )
        .unwrap();
        pc3.change_password(MP.as_bytes(), KdfParams::INSECURE_TEST)
            .unwrap();
        assert_eq!(s.sync().unwrap_err().code, "password_changed");
        assert!(s.vault.is_none());
    }

    #[test]
    fn sync_picks_up_other_device_and_conflict_copy_and_writes_back() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        // "Máy khác" thêm một mục.
        {
            let mut other = other_device(&p);
            other.add(Entry::new("Từ laptop"));
            other.save().unwrap();
        }
        // Dịch vụ đồng bộ tạo bản xung đột có thêm mục.
        let conflict = p.with_file_name("v-Binh-Laptop.pwv");
        std::fs::copy(&p, &conflict).unwrap();
        {
            let mut c = other_device(&conflict);
            c.add(Entry::new("Từ bản xung đột"));
            c.save().unwrap();
            let _ = std::fs::remove_dir_all(backup_dir(&conflict));
        }
        assert_eq!(s.status().conflict_copies, 1);
        let r = s.sync().unwrap();
        assert!(r.changed && r.wrote && r.problem.is_none());
        assert_eq!(r.conflicts_merged, 1);
        assert_eq!(titles(&s), ["A", "Từ bản xung đột", "Từ laptop"]);
        assert!(
            !conflict.exists(),
            "đã chuyển vào thư mục sao lưu SAU khi ghi"
        );
        assert_eq!(other_device(&p).entries().len(), 3);
        let r = s.sync().unwrap();
        assert!(!r.changed && !r.wrote);
    }

    /// Lỗi 0.1.2: file trên đĩa hỏng ⇒ lỗi "sai mật khẩu", mục mới vẫn hiện trong danh sách dù
    /// chưa được lưu, lỗi đồng bộ nền bị nuốt, và khi tự khoá thì mất hết.
    #[test]
    fn damaged_file_becomes_a_persistent_problem_and_nothing_is_lost_on_lock() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        s.save_entry(input("B", Some("b"))).unwrap();
        std::fs::write(&p, b"dong bo do").unwrap();

        let e = s.save_entry(input("C", Some("c"))).unwrap_err();
        assert_eq!(e.code, "file_damaged");
        assert_eq!(
            titles(&s),
            ["A", "B"],
            "mục chưa lưu được không hiện như đã lưu"
        );
        assert_eq!(s.status().disk_problem.unwrap().code, "file_damaged");
        let r = s.sync().unwrap();
        assert_eq!(r.problem.unwrap().code, "file_damaged");
        assert_eq!(std::fs::read(&p).unwrap(), b"dong bo do", "không tự ghi đè");

        // Tự khoá trong lúc file còn hỏng: bản tốt duy nhất (trong RAM) được ghi thành bản cứu hộ…
        let id = vid(&s);
        s.lock();
        assert_eq!(s.rescue_files(&id).len(), 1);
        // …mở khoá thì báo file hỏng; "khôi phục" dựng lại từ sao lưu + bản cứu hộ, không thiếu gì.
        assert_eq!(s.unlock(&p, MP).unwrap_err().code, "file_damaged");
        let r = s.recover(&p, MP, false).unwrap();
        assert_eq!(r.entries, 2);
        assert!(r.archived.is_some());
        assert_eq!(titles(&s), ["A", "B"]);
        assert_eq!(other_device(&p).entries().len(), 2);
        assert_eq!(s.rescue_files(&id).len(), 0);
        assert!(s.status().disk_problem.is_none());
    }

    #[test]
    fn user_confirmed_overwrite_of_a_damaged_file() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        std::fs::write(&p, b"").unwrap();
        assert_eq!(s.sync().unwrap().problem.unwrap().code, "file_damaged");
        let archived = s.force_write().unwrap().unwrap();
        assert!(Path::new(&archived).exists());
        assert!(s.status().disk_problem.is_none());
        s.save_entry(input("B", Some("b"))).unwrap();
        assert_eq!(other_device(&p).entries().len(), 2);
    }

    /// Lỗi 0.1.2: máy kia chuyển kho đi chỗ khác ⇒ máy này âm thầm tạo lại file ở chỗ cũ.
    #[test]
    fn missing_file_is_reported_not_recreated() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert_eq!(
            s.save_entry(input("B", Some("b"))).unwrap_err().code,
            "file_missing"
        );
        assert_eq!(s.sync().unwrap().problem.unwrap().code, "file_missing");
        assert!(!p.exists());
        let st = s.status();
        assert!(st.unlocked && st.vault_configured && !st.vault_exists);
        // Người dùng chọn "tạo lại ở đây".
        assert!(s.force_write().unwrap().is_none());
        assert_eq!(other_device(&p).entries().len(), 1);
    }

    #[test]
    fn rollback_to_an_older_file_is_flagged_at_unlock() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let old = std::fs::read(&p).unwrap();
        std::thread::sleep(Duration::from_millis(3));
        s.save_entry(input("B", Some("b"))).unwrap();
        s.lock();
        assert!(s.unlock(&p, MP).unwrap().rollback.is_none());
        s.lock();
        // Dịch vụ đồng bộ (hoặc ai đó) chép đè một bản cũ hơn.
        std::fs::write(&p, &old).unwrap();
        let info = s.unlock(&p, MP).unwrap();
        let rb = info
            .rollback
            .expect("phải cảnh báo file cũ hơn bản đã thấy");
        assert!(rb.file_modified_at < rb.seen_modified_at && !rb.older_password);
        // Bản lưu riêng trên máy này gộp lại B (và file kho được ghi lại).
        assert_eq!(info.local_restored.map(|l| l.added), Some(1));
        assert_eq!(titles(&s), ["A", "B"]);
        s.lock();
        assert!(s.unlock(&p, MP).unwrap().rollback.is_none(), "đã tự lành");
        // Máy này không có bản lưu riêng (ví dụ vừa cập nhật từ bản cũ): cảnh báo lặp lại ở mỗi lần
        // mở cho tới khi người dùng bấm "đã hiểu".
        let id = vid(&s);
        s.lock();
        std::fs::write(&p, &old).unwrap();
        std::fs::remove_file(local_file(&d, &id)).unwrap();
        let info = s.unlock(&p, MP).unwrap();
        assert!(info.rollback.is_some() && info.local_restored.is_none());
        assert_eq!(titles(&s), ["A"]);
        s.lock();
        assert!(s.unlock(&p, MP).unwrap().rollback.is_some());
        s.accept_rollback().unwrap();
        s.lock();
        assert!(s.unlock(&p, MP).unwrap().rollback.is_none());
    }

    #[test]
    fn backups_can_be_listed_compared_and_restored_from() {
        let (mut s, d) = session();
        open(&mut s, &d);
        let (id, _) = s.save_entry(input("Bank", Some("good-password"))).unwrap();
        let (other, _) = s.save_entry(input("Other", Some("o"))).unwrap();
        let mut upd = patch(&id);
        upd.password = z("mistake");
        upd.notes = z("oops");
        s.save_entry(upd).unwrap();
        s.delete_entry(&other).unwrap();

        let backups = s.list_backups().unwrap();
        assert!(backups.len() >= 3 && backups.iter().all(|b| b.kind == "auto"));
        // Bản có cả hai mục ở trạng thái tốt: bản sao lưu được tạo ngay trước lần sửa nhầm.
        // (danh sách xếp mới nhất trước ⇒ lấy bản CŨ nhất có đủ 2 mục)
        let good = backups
            .iter()
            .rev()
            .find(|b| b.entries == Some(2))
            .expect("phải có bản sao lưu chứa 2 mục");
        let diff = s.backup_diff(&good.name).unwrap();
        assert_eq!(diff.len(), 2);
        let bank = diff.iter().find(|e| e.id == id).unwrap();
        assert_eq!(bank.status, "changed");
        assert_eq!(bank.changed_fields, ["mật khẩu", "ghi chú"]);
        assert_eq!(
            diff.iter().find(|e| e.id == other).unwrap().status,
            "in_trash"
        );
        let json = serde_json::to_string(&diff).unwrap();
        assert!(!json.contains("good-password") && !json.contains("mistake"));

        let n = s
            .restore_from_backup(&good.name, &[id.clone(), other.clone(), "khong-co".into()])
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(s.reveal_password(&id).unwrap(), "good-password");
        assert_eq!(s.history(&id).unwrap()[0].password, "mistake");
        assert!(!s.detail(&id).unwrap().has_notes);
        assert_eq!(titles(&s), ["Bank", "Other"]);
        assert!(s.backup_diff(&good.name).unwrap().is_empty());
        // Tên file không được phép chứa đường dẫn.
        for bad in ["../v.pwv", "a/b", "..", ""] {
            assert!(s.backup_diff(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn move_vault_keeps_data_and_refuses_backup_folder() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        s.save_entry(input("B", Some("b"))).unwrap();
        assert!(s.move_vault(&backup_dir(&p).join("v.pwv"), false).is_err());
        assert_eq!(other_device(&p).entries().len(), 2, "kho cũ còn nguyên");
        let target = d.path().join("Dropbox").join("vault.pwv");
        let r = s.move_vault(&target, false).unwrap();
        assert!(r.old_removed && r.backups_moved && !r.rescued);
        assert_eq!(s.list("").unwrap().len(), 2);
        assert_eq!(s.config.vault.as_deref(), Some(target.as_path()));
        assert_eq!(other_device(&target).entries().len(), 2);
    }

    #[test]
    fn read_only_session_from_bytes_never_goes_backwards() {
        let (mut s, d) = session();
        let p = d.path().join("v.pwv");
        let mut pc = Vault::create(&p, MP.as_bytes(), s.create_opts).unwrap();
        pc.add(Entry::new("A"));
        pc.save().unwrap();
        let older = std::fs::read(&p).unwrap();
        s.unlock_bytes("content://x/v.pwv", &older, MP).unwrap();
        assert!(s.status().read_only);
        assert_eq!(s.list("").unwrap().len(), 1);
        // Ghi bị chặn ở chế độ chỉ đọc.
        assert_eq!(
            s.save_entry(input("B", Some("b"))).unwrap_err().code,
            "read_only"
        );
        assert!(s.sync().unwrap().problem.is_none());
        pc.add(Entry::new("C"));
        pc.save().unwrap();
        assert!(s.reload_bytes(&std::fs::read(&p).unwrap()).unwrap());
        assert_eq!(titles(&s), ["A", "C"]);
        // Chọn nhầm bản cũ: dữ liệu không lùi lại.
        assert!(!s.reload_bytes(&older).unwrap());
        assert_eq!(titles(&s), ["A", "C"]);
        // Bản lưu ngoại tuyến là kho đã mã hoá, mở lại được.
        let cache = s.export_bytes().unwrap();
        s.lock();
        s.unlock_bytes("cache", &cache, MP).unwrap();
        assert_eq!(titles(&s), ["A", "C"]);
        // Máy tính đổi mật khẩu ⇒ điện thoại bị khoá kèm giải thích.
        pc.change_password(MP2.as_bytes(), KdfParams::INSECURE_TEST)
            .unwrap();
        let e = s.reload_bytes(&std::fs::read(&p).unwrap()).unwrap_err();
        assert_eq!(e.code, "password_changed");
        assert!(s.vault.is_none() && s.lock_note.is_some());
    }

    #[test]
    fn generator_requests() {
        let g: GenRequest =
            serde_json::from_str(r#"{"mode":"password","length":32,"symbols":false}"#).unwrap();
        let out = generate(g).unwrap();
        assert_eq!(out.value.len(), 32);
        let g: GenRequest =
            serde_json::from_str(r#"{"mode":"passphrase","words":5,"separator":" "}"#).unwrap();
        assert_eq!(generate(g).unwrap().value.split(' ').count(), 5);
    }

    #[test]
    fn import_and_health() {
        let (mut s, d) = session();
        open(&mut s, &d);
        let csv = d.path().join("c.csv");
        std::fs::write(
            &csv,
            "name,url,username,password,note\n\
             A,https://a.vn,u,123456,\n\
             B,https://b.vn,u,123456,\n\
             ,,,,ghi chú 1\n\
             ,,,,ghi chú 2\n",
        )
        .unwrap();
        let r = s.import_csv(&csv).unwrap();
        assert_eq!((r.imported, r.duplicates, r.skipped), (4, 0, 0));
        assert!(csv.exists(), "không tự xoá CSV");
        // Nhập lại: toàn bộ là trùng hoàn toàn.
        let again = s.import_csv(&csv).unwrap();
        assert_eq!((again.imported, again.duplicates), (0, 4));
        s.delete_imported_csv().unwrap();
        assert!(!csv.exists());
        assert!(
            s.delete_imported_csv().is_err(),
            "chỉ xoá đúng file vừa nhập, một lần"
        );

        let h = s.health(None, None).unwrap();
        assert_eq!((h.reused, h.weak, h.score), (2, 2, 50));
        assert!(!h.breach_check_done);
        // Kết quả kiểm tra rò rỉ (đã lấy bên ngoài khoá phiên) được ghép vào theo id.
        let q = s.breach_queries().unwrap();
        assert_eq!(q.len(), 2);
        let found: HashMap<String, u64> = [(q[0].id.clone(), 42u64)].into();
        let h = s.health(Some(&found), None).unwrap();
        assert!(h.breach_check_done && h.breached == 1);
        let h = s.health(None, Some("mất mạng".into())).unwrap();
        assert!(!h.breach_check_done && h.breach_error.is_some());
    }

    #[test]
    fn settings_are_clamped() {
        let (mut s, _d) = session();
        s.set_settings(Settings {
            auto_lock_minutes: 100_000,
            clipboard_clear_secs: 0,
            check_updates: false,
        })
        .unwrap();
        let got = s.settings();
        assert_eq!(got.auto_lock_minutes, MAX_AUTO_LOCK_MINUTES);
        assert_eq!(got.clipboard_clear_secs, CLIPBOARD_CLEAR_SECS_MIN);
        assert!(!got.check_updates);
    }

    /// Bản cứu hộ không gộp được (ví dụ ghi bằng một mật khẩu chính khác) là bản DUY NHẤT còn giữ
    /// dữ liệu chưa lưu của nó: không được xoá cùng các bản đã gộp xong.
    #[test]
    fn rescue_copies_that_fail_to_merge_are_kept() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let rescue = d.path().join("rescue");
        std::fs::create_dir_all(&rescue).unwrap();
        let id = s.vault.as_ref().unwrap().vault_id().to_string();
        // Bản cứu hộ gộp được: kho hiện tại + một mục chưa kịp lưu.
        let mut good = other_device(&p);
        good.add(Entry::new("Chưa kịp lưu"));
        let good_file = rescue.join(format!("{id}-1.pwv"));
        std::fs::write(&good_file, good.export_bytes().unwrap()).unwrap();
        drop(good);
        // Bản cứu hộ cùng kho nhưng ghi bằng một mật khẩu chính khác (máy này không có khoá đó).
        let fork = d.path().join("fork").join("v.pwv");
        std::fs::create_dir_all(fork.parent().unwrap()).unwrap();
        std::fs::copy(&p, &fork).unwrap();
        let mut f = other_device(&fork);
        f.change_password(MP2.as_bytes(), KdfParams::INSECURE_TEST)
            .unwrap();
        let bad_file = rescue.join(format!("{id}-2.pwv"));
        std::fs::write(&bad_file, f.export_bytes().unwrap()).unwrap();
        s.lock();

        let info = s.unlock(&p, MP).unwrap();
        assert_eq!((info.rescued, info.rescue_kept), (1, 1));
        assert!(titles(&s).contains(&"Chưa kịp lưu".to_string()));
        assert!(!good_file.exists(), "bản đã gộp và ghi xong được xoá");
        assert!(bad_file.exists(), "bản không gộp được phải được giữ lại");
        // Lần mở khoá sau vẫn thử lại (và vẫn giữ).
        s.lock();
        let info = s.unlock(&p, MP).unwrap();
        assert_eq!((info.rescued, info.rescue_kept), (0, 1));
        assert!(bad_file.exists());
    }

    /// Sau khi đổi mật khẩu chính: một bản ghi bằng mật khẩu CŨ (bản cạnh kho, hoặc chính file kho)
    /// không được gộp mà được cất vào thư mục sao lưu và báo cho người dùng.
    #[test]
    fn copies_written_with_an_old_password_are_archived_and_reported() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        // Một máy chưa biết lần đổi mật khẩu: bản của nó (khoá cũ) có thêm một mục.
        let mut stale = other_device(&p);
        stale.add(Entry::new("Ghi bằng khoá cũ"));
        let old_bytes = stale.export_bytes().unwrap();
        drop(stale);
        let r = s.change_master_password(MP, MP2).unwrap();
        assert!(!r.unverified);

        // 1) Bản cạnh kho ghi bằng khoá cũ.
        let sibling = p.with_file_name("v (1).pwv");
        std::fs::write(&sibling, &old_bytes).unwrap();
        let r = s.sync().unwrap();
        assert_eq!(r.old_key_archived, 1);
        assert!(r.problem.is_none());
        // Đã cất xong ⇒ chỉ báo qua `old_key_archived`, không thêm dòng "chưa gộp được" trùng lặp.
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(
            !titles(&s).contains(&"Ghi bằng khoá cũ".to_string()),
            "không gộp"
        );
        assert!(!sibling.exists());
        let oldkey: Vec<BackupView> = s
            .list_backups()
            .unwrap()
            .into_iter()
            .filter(|b| b.kind == "oldkey")
            .collect();
        assert_eq!(oldkey.len(), 1);
        // Chủ kho vẫn xem được khác biệt của bản đó.
        let diff = s.backup_diff(&oldkey[0].name).unwrap();
        assert!(diff.iter().any(|e| e.title == "Ghi bằng khoá cũ"));

        // 2) Chính file kho bị thay bằng bản khoá cũ.
        std::fs::write(&p, &old_bytes).unwrap();
        let r = s.sync().unwrap();
        assert_eq!(r.old_key_archived, 1, "{r:?}");
        assert!(!titles(&s).contains(&"Ghi bằng khoá cũ".to_string()));
        assert!(Vault::open_with(
            &p,
            MP2.as_bytes(),
            OpenOptions {
                allow_weak_kdf: true
            }
        )
        .is_ok());
    }

    /// Bản sao lưu chỉ mở được bằng khoá của mật khẩu chính cũ được đánh dấu trong danh sách.
    #[test]
    fn backups_that_open_only_with_an_old_key_are_flagged() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let old_bytes = std::fs::read(&p).unwrap();
        s.change_master_password(MP, MP2).unwrap();
        s.save_entry(input("B", Some("b"))).unwrap();
        // Ai đó (hoặc một máy chưa biết lần đổi) đặt vào thư mục sao lưu một bản dùng khoá cũ.
        let planted = backup_dir(&p).join("v-1700000000000.pwv");
        std::fs::write(&planted, &old_bytes).unwrap();
        let list = s.list_backups().unwrap();
        let b = list
            .iter()
            .find(|b| b.name == "v-1700000000000.pwv")
            .unwrap();
        assert!(b.retired_key && b.kind == "auto" && b.entries == Some(1));
        // Các bản ghi SAU lần đổi mật khẩu là bản đáng tin (kể cả bản của chính lần ghi đổi mật
        // khẩu); mọi bản có từ TRƯỚC lần đổi (đã được mã hoá lại và đánh dấu) cũng mang nhãn này —
        // app không bao giờ tự dùng chúng.
        let others: Vec<_> = list
            .iter()
            .filter(|b| b.name != "v-1700000000000.pwv")
            .collect();
        assert!(others
            .iter()
            .filter(|b| b.entries == Some(2))
            .all(|b| !b.retired_key));
        assert!(others
            .iter()
            .any(|b| !b.retired_key && b.entries == Some(2)));
        assert!(others.iter().any(|b| b.retired_key && b.entries == Some(1)));
        assert!(others
            .iter()
            .any(|b| !b.retired_key && b.entries == Some(1)));
    }

    /// Khôi phục bằng mật khẩu chính CŨ bị từ chối (mã riêng), trừ khi chủ kho chọn rõ ràng;
    /// thư mục sao lưu không có bản nào dùng được cũng có mã riêng.
    #[test]
    fn recovery_reports_older_password_and_no_backup() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        // Giữ lại một bản sao lưu dùng mật khẩu cũ (lõi không bao giờ mã hoá lại bản như vậy nếu
        // nó được đặt vào SAU lần đổi).
        let before_change = std::fs::read(&p).unwrap();
        s.change_master_password(MP, MP2).unwrap();
        s.save_entry(input("B", Some("b"))).unwrap();
        std::fs::write(backup_dir(&p).join("v-1700000000000.pwv"), &before_change).unwrap();
        s.lock();
        std::fs::write(&p, b"hong").unwrap();
        let e = s.recover(&p, MP, false).unwrap_err();
        assert_eq!(e.code, "older_password", "{e:?}");
        assert!(s.vault.is_none());
        // Mật khẩu hiện tại: khôi phục bình thường, đủ cả hai mục.
        let r = s.recover(&p, MP2, false).unwrap();
        assert_eq!(r.entries, 2);
        s.lock();
        // Chủ kho chọn rõ ràng "vẫn khôi phục từ các bản cũ".
        std::fs::write(&p, b"hong").unwrap();
        let r = s.recover(&p, MP, true).unwrap();
        assert_eq!(r.entries, 1);

        // Thư mục sao lưu trống ⇒ mã riêng.
        let (mut s2, d2) = session();
        let p2 = d2.path().join("moi").join("v.pwv");
        s2.create_vault(&p2, MP).unwrap();
        s2.lock();
        let _ = std::fs::remove_dir_all(backup_dir(&p2));
        // (và máy này cũng không còn bản lưu riêng nào của kho)
        let _ = std::fs::remove_dir_all(d2.path().join("rescue"));
        std::fs::write(&p2, b"hong").unwrap();
        assert_eq!(s2.recover(&p2, MP, false).unwrap_err().code, "no_backup");
    }

    /// Thư mục sao lưu chỉ còn bản dùng mật khẩu CŨ (các bản mới hơn đã bị xoá / dọn): lõi không thấy
    /// gì mới hơn, nhưng máy này nhớ đã thấy một lần đổi mật khẩu mới hơn ⇒ vẫn báo `older_password`,
    /// không ghi gì; chủ kho chọn rõ ràng thì mới khôi phục.
    #[test]
    fn recovery_refuses_an_older_password_this_device_knows_is_old() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let before_change = std::fs::read(&p).unwrap();
        s.change_master_password(MP, MP2).unwrap();
        s.save_entry(input("B", Some("b"))).unwrap();
        s.lock();
        std::fs::remove_dir_all(backup_dir(&p)).unwrap();
        std::fs::create_dir_all(backup_dir(&p)).unwrap();
        std::fs::write(backup_dir(&p).join("v-1700000000000.pwv"), &before_change).unwrap();
        std::fs::write(&p, b"hong").unwrap();
        let e = s.recover(&p, MP, false).unwrap_err();
        assert_eq!(e.code, "older_password", "{e:?}");
        assert!(s.vault.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), b"hong", "không ghi gì");
        let r = s.recover(&p, MP, true).unwrap();
        assert_eq!(r.entries, 1);
        assert!(s.vault.is_some());
    }

    /// Đổi mật khẩu chính đồng bộ trước: file kho trên đĩa hỏng ⇒ báo lỗi và KHÔNG đổi gì.
    #[test]
    fn change_master_password_fails_cleanly_when_the_file_is_damaged() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        std::fs::write(&p, b"hong").unwrap();
        let e = s.change_master_password(MP, MP2).unwrap_err();
        assert_eq!(e.code, "file_damaged");
        assert!(s.vault.as_ref().unwrap().verify_password(MP.as_bytes()));
        assert_eq!(s.status().disk_problem.unwrap().code, "file_damaged");
    }

    /// Ghi cấu hình = đọc lại config.json, áp đúng một thay đổi, ghi lại: thay đổi do CLI làm trong
    /// lúc app đang mở không bị ghi đè.
    #[test]
    fn config_writes_start_from_the_file_on_disk() {
        let mem = Config {
            vault: Some(PathBuf::from("/cu/vault.pwv")),
            auto_lock_minutes: 5,
            ..Default::default()
        };
        let mut disk = Config {
            vault: Some(PathBuf::from("/moi/vault.pwv")),
            clipboard_clear_secs: 60,
            ..Default::default()
        };
        disk.note_seen("kho", 10, 20, 7);
        let bytes = serde_json::to_vec(&disk).unwrap();
        let mut c = config_base(Some(&bytes), &mem);
        c.auto_lock_minutes = 15;
        assert_eq!(c.vault.as_deref(), Some(Path::new("/moi/vault.pwv")));
        assert_eq!((c.auto_lock_minutes, c.clipboard_clear_secs), (15, 60));
        assert_eq!(c.seen_key_tag("kho"), 7);
        // File hỏng hoặc không có: làm tiếp từ bản trong RAM (không ghi đè bằng cấu hình mặc định).
        assert_eq!(config_base(Some(b"{hong"), &mem), mem);
        assert_eq!(config_base(None, &mem), mem);
        // Giá trị ngoài khoảng trong file bị ép về khoảng hợp lệ.
        let wild = br#"{"auto_lock_minutes": 999999, "clipboard_clear_secs": 1}"#;
        let c = config_base(Some(wild), &mem);
        assert_eq!(c.auto_lock_minutes, MAX_AUTO_LOCK_MINUTES);
        assert_eq!(c.clipboard_clear_secs, CLIPBOARD_CLEAR_SECS_MIN);
    }

    /// Như trên nhưng với config.json thật (thư mục tạm). `Config::set_dir` chỉ có tác dụng một lần
    /// cho cả tiến trình ⇒ chỉ test này dùng nó, các test khác đều `persist_config = false`.
    #[test]
    fn running_app_does_not_overwrite_config_changes_made_by_the_cli() {
        let dir = tempfile::tempdir().unwrap().keep();
        Config::set_dir(dir.clone());
        assert_eq!(Config::file(), Some(dir.join("config.json")));
        let (mut s, d) = session();
        s.persist_config = true;
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        assert_eq!(Config::load().vault.as_deref(), Some(p.as_path()));
        // CLI (tiến trình khác) đổi cài đặt và ghi config.json trong lúc app đang mở.
        let mut cli = Config::load();
        cli.clipboard_clear_secs = 120;
        cli.check_updates = false;
        cli.save().unwrap();
        // App đổi một cài đặt khác, rồi ghi mốc "đã thấy" sau một lần sửa.
        s.set_settings(Settings {
            auto_lock_minutes: 30,
            clipboard_clear_secs: 120,
            check_updates: false,
        })
        .unwrap();
        let mut cli = Config::load();
        cli.auto_lock_minutes = 2; // CLI đổi tiếp
        cli.save().unwrap();
        std::thread::sleep(Duration::from_millis(3));
        s.save_entry(input("B", Some("b"))).unwrap();
        let on_disk = Config::load();
        assert_eq!(on_disk.auto_lock_minutes, 2, "thay đổi của CLI còn nguyên");
        assert_eq!(on_disk.clipboard_clear_secs, 120);
        assert!(!on_disk.check_updates);
        let id = s.vault.as_ref().unwrap().vault_id().to_string();
        assert_eq!(
            on_disk.seen.get(&id).map(|m| m.modified_at),
            Some(s.vault.as_ref().unwrap().modified_at()),
            "mốc đã thấy được ghi"
        );
        assert_eq!(s.config, on_disk, "bản trong RAM = bản vừa ghi");
        // Lần đồng bộ không có gì mới thì không ghi config.json.
        let mut cli = Config::load();
        cli.auto_lock_minutes = 3;
        cli.save().unwrap();
        s.sync().unwrap();
        assert_eq!(Config::load().auto_lock_minutes, 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn warns_about_traces_of_an_existing_vault() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        s.save_entry(input("B", Some("b"))).unwrap();
        // Máy thứ hai: file kho chưa đồng bộ về nhưng thư mục sao lưu / file khác đã có.
        let fresh = d.path().join("trong").join("vault.pwv");
        assert!(Session::existing_vault_traces(&fresh).is_empty());
        let traces = Session::existing_vault_traces(&p.with_file_name("vault.pwv"));
        assert_eq!(traces, ["v.pwv"]);
        std::fs::remove_file(&p).unwrap();
        assert_eq!(Session::existing_vault_traces(&p), ["v.pwv.backups"]);
    }

    // ------------------------------------------------------------------ fix2: bản nháp (P1)

    fn vid(s: &Session) -> String {
        s.vault.as_ref().unwrap().vault_id().to_string()
    }

    fn stash_file(d: &tempfile::TempDir, id: &str) -> PathBuf {
        d.path().join("rescue").join(format!("stash-{id}.bin"))
    }

    fn local_file(d: &tempfile::TempDir, id: &str) -> PathBuf {
        d.path().join("rescue").join(format!("last-{id}.pwv"))
    }

    /// Một lần chạy app mới trên cùng máy (cùng thư mục riêng, cùng cấu hình).
    fn restart(s: &Session) -> (Session, tempfile::TempDir) {
        let (mut s2, d2) = session();
        s2.rescue_dir = s.rescue_dir.clone();
        s2.config = s.config.clone();
        (s2, d2)
    }

    #[test]
    fn draft_survives_lock_and_restart_and_is_never_on_disk_in_clear() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        assert!(s.unlock(&p, MP).is_ok());
        s.set_draft(z("{\"pw\":\"mat-khau-vua-tao-XYZ\"}")).unwrap();
        let id = vid(&s);
        let on_disk = std::fs::read(stash_file(&d, &id)).unwrap();
        assert!(!String::from_utf8_lossy(&on_disk).contains("mat-khau-vua-tao-XYZ"));
        s.lock();
        assert_eq!(s.draft().unwrap_err().code, "locked");
        let info = s.unlock(&p, MP).unwrap();
        assert_eq!(
            info.draft.as_deref(),
            Some("{\"pw\":\"mat-khau-vua-tao-XYZ\"}")
        );
        // App thoát / máy khởi động lại: đọc lại từ file trong thư mục riêng.
        s.lock();
        let (mut s2, _d2) = restart(&s);
        drop(s);
        let info = s2.unlock(&p, MP).unwrap();
        assert_eq!(
            info.draft.as_deref(),
            Some("{\"pw\":\"mat-khau-vua-tao-XYZ\"}")
        );
    }

    #[test]
    fn draft_is_cleared_by_a_successful_save_and_by_discard() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.set_draft(z("dang sua")).unwrap();
        // Lưu không thành công (tiêu đề trống) ⇒ bản nháp còn nguyên.
        assert!(s.save_entry(EntryInput::default()).is_err());
        assert_eq!(s.draft().unwrap().as_deref(), Some("dang sua"));
        s.save_entry(input("A", Some("a"))).unwrap();
        assert_eq!(s.draft().unwrap(), None);
        s.lock();
        assert_eq!(s.unlock(&p, MP).unwrap().draft, None);
        s.set_draft(z("lan hai")).unwrap();
        s.set_draft(None).unwrap();
        s.lock();
        assert_eq!(s.unlock(&p, MP).unwrap().draft, None);
    }

    #[test]
    fn a_draft_is_never_offered_to_another_vault() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.set_draft(z("cua kho A")).unwrap();
        let a = vid(&s);
        s.lock();
        let q = d.path().join("khac").join("b.pwv");
        s.create_vault(&q, MP).unwrap();
        let b = vid(&s);
        assert_eq!(s.draft().unwrap(), None, "bản nháp trong RAM là của kho A");
        // Chép file stash của A sang tên của B: không mở được (gắn với mã kho), và được để nguyên.
        s.lock();
        std::fs::copy(stash_file(&d, &a), stash_file(&d, &b)).unwrap();
        let planted = std::fs::read(stash_file(&d, &b)).unwrap();
        assert_eq!(s.unlock(&q, MP).unwrap().draft, None);
        assert_eq!(std::fs::read(stash_file(&d, &b)).unwrap(), planted);
        // Ghi lần đầu cho B: file không mở được được đổi tên để giữ lại, không bị ghi đè.
        s.set_draft(z("cua kho B")).unwrap();
        let kept: Vec<_> = std::fs::read_dir(d.path().join("rescue"))
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.to_string_lossy().contains(".unreadable-"))
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(std::fs::read(&kept[0]).unwrap(), planted);
        s.lock();
        assert_eq!(
            s.unlock(&p, MP).unwrap().draft.as_deref(),
            Some("cua kho A")
        );
    }

    #[test]
    fn oversize_drafts_are_not_kept() {
        let (mut s, d) = session();
        open(&mut s, &d);
        s.set_draft(z("cu")).unwrap();
        let big = "x".repeat(MAX_DRAFT_BYTES + 1);
        assert_eq!(s.set_draft(z(&big)).unwrap_err().code, "draft_too_large");
        assert_eq!(s.draft().unwrap(), None, "không giữ bản nháp cũ lỗi thời");
        s.set_draft(z(&"x".repeat(MAX_DRAFT_BYTES))).unwrap();
        assert!(s.draft().unwrap().is_some());
    }

    #[test]
    fn generated_passwords_are_capped_expire_and_never_listed_with_their_value() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        for i in 0..25 {
            s.record_generated(
                Zeroizing::new(format!("gen-{i:02}")),
                Some(format!("Mục {i}")),
            )
            .unwrap();
        }
        let list = s.list_generated().unwrap();
        assert_eq!(list.len(), MAX_GENERATED);
        assert!(!serde_json::to_string(&list).unwrap().contains("gen-"));
        let values: Vec<String> = list
            .iter()
            .map(|g| s.generated_value(&g.id).unwrap().to_string())
            .collect();
        assert!(values.contains(&"gen-24".to_string()) && !values.contains(&"gen-00".to_string()));
        // Ghi lại cùng một giá trị: không thành hai dòng.
        s.record_generated(Zeroizing::new("gen-24".into()), None)
            .unwrap();
        assert_eq!(s.list_generated().unwrap().len(), MAX_GENERATED);
        // Giữ qua lần khoá; xoá danh sách thì hết.
        s.lock();
        s.unlock(&p, MP).unwrap();
        assert_eq!(s.list_generated().unwrap().len(), MAX_GENERATED);
        s.clear_generated().unwrap();
        assert!(s.list_generated().unwrap().is_empty());
        // Quá 30 ngày ⇒ bị bỏ.
        let now = pwv_vault_core::model::now_ms();
        let mut data = StashData::default();
        for (i, age) in [1, GENERATED_MAX_AGE_MS - 1000, GENERATED_MAX_AGE_MS + 1000]
            .into_iter()
            .enumerate()
        {
            data.generated.push(GeneratedItem {
                id: format!("g{i}"),
                value: Zeroizing::new("v".into()),
                at: now - age,
                label: None,
            });
        }
        data.prune(now);
        let ids: Vec<&str> = data.generated.iter().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, ["g0", "g1"]);
    }

    #[test]
    fn a_stash_sealed_before_a_password_change_still_opens() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.set_draft(z("truoc khi doi")).unwrap();
        s.record_generated(Zeroizing::new("gen-1".into()), None)
            .unwrap();
        s.change_master_password(MP, MP2).unwrap();
        s.lock();
        let info = s.unlock(&p, MP2).unwrap();
        assert_eq!(info.draft.as_deref(), Some("truoc khi doi"));
        // Đổi ở máy khác (máy này đang khoá, sau một lần khởi động lại).
        s.lock();
        let mut pc2 = Vault::open_with(
            &p,
            MP2.as_bytes(),
            OpenOptions {
                allow_weak_kdf: true,
            },
        )
        .unwrap();
        pc2.change_password(MP.as_bytes(), KdfParams::INSECURE_TEST)
            .unwrap();
        let (mut s2, _d2) = restart(&s);
        let info = s2.unlock(&p, MP).unwrap();
        assert_eq!(info.draft.as_deref(), Some("truoc khi doi"));
        assert_eq!(s2.list_generated().unwrap().len(), 1);
    }

    #[test]
    fn read_only_sessions_have_no_stash() {
        let (mut s, d) = session();
        let p = d.path().join("v.pwv");
        Vault::create(&p, MP.as_bytes(), s.create_opts).unwrap();
        s.unlock_bytes("content://x", &std::fs::read(&p).unwrap(), MP)
            .unwrap();
        assert_eq!(s.set_draft(z("x")).unwrap_err().code, "read_only");
        assert!(!d.path().join("rescue").exists());
    }

    // ------------------------------------------------------------------ fix2: tự khoá khi phiên bận (P2)

    /// Một luồng giữ khoá phiên (thao tác đĩa treo): yêu cầu khoá được ghi mà không cần khoá phiên,
    /// và lệnh đầu tiên lấy được khoá phiên sau đó (ví dụ `status` của trang vừa nạp lại) chỉ thấy
    /// kho ĐÃ khoá.
    #[test]
    fn a_lock_requested_while_the_session_is_busy_is_applied_before_any_command() {
        let (mut s, d) = session();
        open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let shared = Arc::new(Shared::new(s));
        let busy = shared.lock();
        assert!(shared.try_lock().is_none());
        assert!(shared.request_lock(LOCK_IDLE));
        assert!(!shared.request_lock(LOCK_SUSPEND), "chỉ một yêu cầu");
        assert!(shared.lock_pending());
        let sh = shared.clone();
        let cmd = std::thread::spawn(move || sh.lock().status());
        std::thread::sleep(Duration::from_millis(50));
        drop(busy);
        let st = cmd.join().unwrap();
        assert!(!st.unlocked);
        assert_eq!(
            st.lock_note.as_deref(),
            Some("Kho đã tự khoá do không sử dụng.")
        );
        assert!(!shared.lock_pending());
        // touch không cần khoá phiên.
        shared.activity.backdate(Duration::from_secs(600));
        shared.activity.touch();
        assert!(shared.activity.idle() < Duration::from_secs(5));
    }

    // ------------------------------------------------------------------ fix2: lưu sang chỗ khác (P3)

    #[test]
    fn rescue_copy_never_touches_the_old_place_and_move_errors_are_not_disk_problems() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        // Đích không ghi được (thư mục cha là một file) ⇒ lỗi của việc chuyển, không phải của kho.
        let bad = p.join("x.pwv");
        let e = s.move_vault(&bad, true).unwrap_err();
        assert_eq!(e.code, "move_failed", "{e:?}");
        assert!(s.status().disk_problem.is_none());
        let e = s.move_vault(&p.with_file_name("v.pwv.backups").join("x.pwv"), false);
        assert!(e.is_err() && s.status().disk_problem.is_none());
        let before = std::fs::read(&p).unwrap();
        let target = d.path().join("cuu").join("v.pwv");
        let r = s.move_vault(&target, true).unwrap();
        assert!(r.rescued && !r.old_removed && !r.backups_moved);
        assert_eq!(r.old_path, p.display().to_string());
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert_eq!(s.config.vault.as_deref(), Some(target.as_path()));
        s.save_entry(input("B", Some("b"))).unwrap();
        assert_eq!(
            std::fs::read(&p).unwrap(),
            before,
            "lần lưu sau cũng không đụng chỗ cũ"
        );
    }

    // ------------------------------------------------------------------ fix2: bản lưu riêng (P4)

    /// (1) Máy khác (chưa đồng bộ xong) ghi đè file kho bằng một bản thiếu mục X nhưng MỚI hơn ⇒ khi
    /// mở khoá, X quay lại từ bản lưu riêng, được báo, và file kho được ghi lại.
    #[test]
    fn a_lost_update_is_healed_from_the_local_copy() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let mut stale = other_device(&p);
        std::thread::sleep(Duration::from_millis(3));
        let (x, _) = s.save_entry(input("X", Some("x"))).unwrap();
        s.lock();
        std::thread::sleep(Duration::from_millis(3));
        stale.add(Entry::new("Y từ máy kia"));
        std::fs::write(&p, stale.export_bytes().unwrap()).unwrap();
        let info = s.unlock(&p, MP).unwrap();
        assert!(
            info.rollback.is_none(),
            "file mới hơn ⇒ không có cảnh báo cũ hơn"
        );
        let lr = info.local_restored.expect("phải báo đã gộp lại");
        assert_eq!(lr.added, 1);
        assert_eq!(titles(&s), ["A", "X", "Y từ máy kia"]);
        assert!(
            other_device(&p).get(&x).is_some(),
            "file kho đã được ghi lại"
        );
        // Lần sau không còn gì để gộp.
        s.lock();
        assert!(s.unlock(&p, MP).unwrap().local_restored.is_none());
    }

    /// (2) Mục bị xoá vĩnh viễn ở máy khác không sống lại từ bản lưu riêng.
    #[test]
    fn an_entry_purged_elsewhere_stays_purged() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        let (x, _) = s.save_entry(input("X", Some("x"))).unwrap();
        s.save_entry(input("A", Some("a"))).unwrap();
        s.lock();
        let mut pc2 = other_device(&p);
        pc2.transact(|v| {
            v.delete(&x)?;
            v.purge(&x)
        })
        .unwrap();
        let info = s.unlock(&p, MP).unwrap();
        assert!(info.local_restored.is_none());
        assert_eq!(titles(&s), ["A"]);
        assert!(s.list_trash().unwrap().is_empty());
    }

    /// (3) Bản lưu riêng ghi bằng khoá cũ vẫn gộp được sau khi mật khẩu được đổi ở máy khác.
    #[test]
    fn a_local_copy_under_a_retired_key_merges_after_a_password_change_elsewhere() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let before_x = std::fs::read(&p).unwrap();
        s.save_entry(input("X", Some("x"))).unwrap();
        s.lock();
        // Máy kia chỉ có bản trước X, rồi đổi mật khẩu.
        std::fs::write(&p, &before_x).unwrap();
        let mut pc2 = other_device(&p);
        pc2.change_password(MP2.as_bytes(), KdfParams::INSECURE_TEST)
            .unwrap();
        drop(pc2);
        let info = s.unlock(&p, MP2).unwrap();
        assert_eq!(info.local_restored.map(|l| l.added), Some(1));
        assert_eq!(titles(&s), ["A", "X"]);
    }

    /// (4) Bản lưu riêng không gộp được được giữ lại thành bản cứu hộ, không bị ghi đè.
    #[test]
    fn an_unmergeable_local_copy_is_kept_as_a_rescue_copy() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let id = vid(&s);
        s.lock();
        let fork = d.path().join("fork").join("v.pwv");
        std::fs::create_dir_all(fork.parent().unwrap()).unwrap();
        std::fs::copy(&p, &fork).unwrap();
        let mut f = other_device(&fork);
        f.change_password(MP2.as_bytes(), KdfParams::INSECURE_TEST)
            .unwrap();
        let foreign = f.export_bytes().unwrap();
        std::fs::write(local_file(&d, &id), &foreign).unwrap();
        let info = s.unlock(&p, MP).unwrap();
        assert!(info.local_restored.is_none());
        assert_eq!(info.rescue_kept, 1, "được đếm như một bản cứu hộ");
        let kept = s.rescue_files(&id);
        assert_eq!(kept.len(), 1);
        assert_eq!(std::fs::read(&kept[0]).unwrap(), foreign);
        // Bản lưu riêng mới là của kho đang mở.
        assert_ne!(std::fs::read(local_file(&d, &id)).unwrap(), foreign);
    }

    /// (5) Tạo lại file kho từ bản lưu riêng: không bao giờ ghi đè.
    #[test]
    fn restoring_the_local_copy_never_overwrites() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        s.lock();
        assert!(s.status().local_copy_at.is_some());
        std::fs::remove_file(&p).unwrap();
        s.restore_local_copy().unwrap();
        s.unlock(&p, MP).unwrap();
        assert_eq!(titles(&s), ["A"]);
        assert!(s.restore_local_copy().is_err(), "đang mở khoá");
        s.lock();
        let now = std::fs::read(&p).unwrap();
        assert!(s.restore_local_copy().is_err());
        assert_eq!(std::fs::read(&p).unwrap(), now);
    }

    /// (6) Không còn bản sao lưu nào: dựng lại từ bản lưu riêng trên máy này.
    #[test]
    fn recovery_uses_the_local_copy_when_backups_are_gone() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        s.save_entry(input("B", Some("b"))).unwrap();
        s.lock();
        std::fs::remove_dir_all(backup_dir(&p)).unwrap();
        std::fs::write(&p, b"hong").unwrap();
        assert_eq!(
            s.recover(&p, "sai-mat-khau-hoan-toan", false)
                .unwrap_err()
                .code,
            "wrong_password"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"hong",
            "sai mật khẩu ⇒ không ghi gì"
        );
        let r = s.recover(&p, MP, false).unwrap();
        assert!(r.from_local_copy);
        assert_eq!(r.entries, 2);
        let archived = r.archived.expect("file hỏng được cất");
        assert_eq!(std::fs::read(&archived).unwrap(), b"hong");
        assert_eq!(other_device(&p).entries().len(), 2);
    }

    // ------------------------------------------------------------------ fix2: không đi lùi (P5)

    #[test]
    fn recovery_refuses_to_go_back_in_time_unless_asked() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        std::thread::sleep(Duration::from_millis(3));
        s.save_entry(input("B", Some("b"))).unwrap();
        let id = vid(&s);
        for b in s.list_backups().unwrap() {
            if b.entries == Some(2) {
                std::fs::remove_file(backup_dir(&p).join(&b.name)).unwrap();
            }
        }
        s.lock();
        // Máy này không còn bản lưu riêng (ví dụ vừa cập nhật từ bản cũ); bản sao lưu còn lại thiếu B.
        std::fs::remove_file(local_file(&d, &id)).unwrap();
        std::fs::write(&p, b"hong").unwrap();
        let e = s.recover(&p, MP, false).unwrap_err();
        assert_eq!(e.code, "older_than_seen", "{e:?}");
        let det = e.detail.unwrap();
        assert!(det.file_modified_at < det.seen_modified_at);
        assert!(s.vault.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), b"hong", "không ghi gì");
        let r = s
            .recover_with(
                &p,
                MP,
                RecoverOpts {
                    allow_stale: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(r.entries, 1);
        // Mốc "đã thấy" mới = bản vừa khôi phục: lần mở sau không cảnh báo nữa.
        s.lock();
        assert!(s.unlock(&p, MP).unwrap().rollback.is_none());
    }

    #[test]
    fn recovery_with_the_local_copy_merged_is_not_stale() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        std::thread::sleep(Duration::from_millis(3));
        s.save_entry(input("B", Some("b"))).unwrap();
        s.lock();
        std::fs::write(&p, b"hong").unwrap();
        let r = s.recover(&p, MP, false).unwrap();
        assert!(!r.from_local_copy);
        assert_eq!(r.entries, 2, "bản sao lưu thiếu B, bản lưu riêng bù lại");
    }

    // ------------------------------------------------------------------ fix2: đổi khoá (P7)

    #[test]
    fn rekey_scan_is_remembered_and_the_same_password_is_accepted() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let id = vid(&s);
        let tag = s.vault.as_ref().unwrap().key_tag();
        assert!(!s.config.wrap_scan_clean(&id, tag));
        assert!(!s.check_rekey().unwrap());
        assert!(
            s.config.wrap_scan_clean(&id, tag),
            "lần quét sạch được ghi nhớ"
        );
        assert!(!s.status().rekey_advised);
        // Nhập lại đúng mật khẩu đang dùng: được chấp nhận, và khoá được thay.
        let r = s.change_master_password(MP, MP).unwrap();
        assert!(r.backups_failed.is_empty());
        assert_ne!(s.vault.as_ref().unwrap().key_tag(), tag);
        s.lock();
        s.unlock(&p, MP).unwrap();
        assert!(!s.check_rekey().unwrap());
    }

    // ------------------------------------------------------------------ fix2: chọn file kho (P8)

    #[test]
    fn picking_a_conflict_copy_is_detected() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        s.save_entry(input("A", Some("a"))).unwrap();
        let dir = p.parent().unwrap();
        let copy = dir.join("v (conflicted copy 2026-11-20).pwv");
        std::fs::copy(&p, &copy).unwrap();
        let h = Session::conflict_hint(&copy).unwrap();
        assert_eq!(h.original_name, "v.pwv");
        assert_eq!(h.picked_name, "v (conflicted copy 2026-11-20).pwv");
        assert!(Session::conflict_hint(&p).is_none(), "chọn đúng file gốc");
        // Cùng tiền tố nhưng là kho khác ⇒ không phải bản xung đột.
        let other = dir.join("v-rieng.pwv");
        Vault::create(&other, MP.as_bytes(), s.create_opts).unwrap();
        assert!(Session::conflict_hint(&other).is_none());
        assert!(Session::conflict_hint(&dir.join("khong-co.pwv")).is_none());
    }

    // ------------------------------------------------------------------ fix2: sao chép theo chỉ số (P9)

    #[test]
    fn index_based_copies_refuse_an_entry_that_changed_since_it_was_shown() {
        let (mut s, d) = session();
        let p = open(&mut s, &d);
        let (id, _) = s.save_entry(input("A", Some("a"))).unwrap();
        let shown = s.detail(&id).unwrap().updated_at;
        assert_eq!(
            *s.field_value_checked(&id, "url:0", Some(shown)).unwrap(),
            "https://a.vn"
        );
        std::thread::sleep(Duration::from_millis(3));
        let mut pc2 = other_device(&p);
        pc2.transact(|v| v.update(&id, |e| e.urls = vec!["https://khac.vn".into()]))
            .unwrap();
        s.sync().unwrap();
        let e = s
            .field_value_checked(&id, "url:0", Some(shown))
            .unwrap_err();
        assert_eq!(e.code, "entry_changed");
        let now = s.detail(&id).unwrap().updated_at;
        assert_eq!(
            *s.field_value_checked(&id, "url:0", Some(now)).unwrap(),
            "https://khac.vn"
        );
    }
}
