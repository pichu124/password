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
}

impl AppError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
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

/// Số lần ĐỒNG BỘ NỀN liên tiếp phải ghi lại file trước khi app ngừng tự ghi. Thuật toán gộp bảo
/// đảm hai máy hội tụ sau tối đa 2 lần ghi; con số này chỉ là cầu chì phòng lỗi chưa biết.
const MAX_CONSECUTIVE_WRITEBACKS: u32 = 6;
/// File CSV lớn hơn mức này bị từ chối (chống file rác làm treo app).
const MAX_CSV_BYTES: u64 = 20 * 1024 * 1024;

pub struct Session {
    pub vault: Option<Vault>,
    pub config: Config,
    pub last_activity: Instant,
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
}

impl Default for Session {
    fn default() -> Self {
        Self {
            vault: None,
            config: Config::load(),
            last_activity: Instant::now(),
            create_opts: CreateOptions::default(),
            persist_config: true,
            disk_problem: None,
            lock_note: None,
            rescue_dir: None,
            writebacks: 0,
            last_import: None,
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
                Err(e) => out.errors.push(format!("{name}: {e}")),
            }
        }
        out
    }
}

/// File kho vừa mở cũ hơn bản mà máy này từng thấy.
#[derive(Debug, Serialize)]
pub struct RollbackView {
    pub seen_modified_at: i64,
    pub file_modified_at: i64,
    pub older_password: bool,
}

#[derive(Debug, Serialize, Default)]
pub struct UnlockInfo {
    pub rollback: Option<RollbackView>,
    /// Số bản cứu hộ (ghi khi app phải khoá mà chưa lưu được) vừa được gộp lại vào kho.
    pub rescued: usize,
    pub sync: SyncResult,
}

#[derive(Debug, Serialize)]
pub struct RecoverInfo {
    pub entries: usize,
    pub files_used: usize,
    pub newest_backup_at: i64,
    /// Nơi file hỏng được cất.
    pub archived: Option<String>,
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
    pub new_path: String,
    pub backups_moved: bool,
    pub old_removed: bool,
    pub conflicts_merged: usize,
    pub rescued: bool,
}

#[derive(Debug, Serialize)]
pub struct PasswordChangeView {
    pub backups_reencrypted: usize,
    pub backups_skipped: usize,
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
    /// "auto" | "merged" | "damaged"
    pub kind: &'static str,
    pub timestamp: i64,
    /// Số mục đang dùng trong bản sao lưu (None = không đọc được).
    pub entries: Option<usize>,
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
        self.last_activity = Instant::now();
    }

    fn open_opts(&self) -> OpenOptions {
        OpenOptions {
            allow_weak_kdf: self.create_opts.allow_weak_kdf,
        }
    }

    fn save_config(&self) -> AppResult<()> {
        if self.persist_config {
            self.config.save().map_err(err)?;
        }
        Ok(())
    }

    /// Trả về true nếu vừa tự khoá.
    pub fn auto_lock_if_idle(&mut self) -> bool {
        let mins = self.config.auto_lock_minutes;
        if mins == 0 || self.vault.is_none() {
            return false;
        }
        if self.last_activity.elapsed() >= Duration::from_secs(u64::from(mins) * 60) {
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
        let Some(v) = self.vault.as_ref() else {
            return;
        };
        if v.is_read_only() {
            return;
        }
        let (id, m, k) = (
            v.vault_id().to_string(),
            v.modified_at(),
            v.key_changed_at(),
        );
        if self.config.note_seen(&id, m, k) {
            let _ = self.save_config();
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
        self.config.set_vault_path(v.path());
        self.save_config()?;
        self.vault = Some(v);
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
        if self.config.vault.as_deref() != Some(v.path()) {
            self.config.set_vault_path(v.path());
            self.save_config()?;
        }
        let rollback = self
            .config
            .rollback_of(v.vault_id(), v.modified_at(), v.key_changed_at())
            .map(|r| RollbackView {
                seen_modified_at: r.seen_modified_at,
                file_modified_at: r.file_modified_at,
                older_password: r.older_password,
            });
        self.vault = Some(v);
        self.lock_note = None;
        self.disk_problem = None;
        self.writebacks = 0;
        self.touch();
        let rescued = self.merge_rescue_copies();
        // Ghi lại ngay những gì vừa gộp (bản cứu hộ, bản xung đột). Vấn đề với file trên đĩa không
        // chặn việc mở kho (nằm trong `sync.problem`); chỉ "mật khẩu đã đổi ở máy khác" mới trả lỗi.
        let sync = self.sync()?;
        if sync.problem.is_none() {
            self.delete_rescue_copies();
        }
        Ok(UnlockInfo {
            rollback,
            rescued,
            sync,
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
    pub fn recover(&mut self, path: &Path, password: &str) -> AppResult<RecoverInfo> {
        let (v, files_used, newest_backup_at) =
            Vault::recover_from_backups(path, password.as_bytes(), self.open_opts())?;
        self.vault = Some(v);
        self.lock_note = None;
        self.disk_problem = None;
        self.merge_rescue_copies();
        let archived = match self.vault_mut()?.force_write() {
            Ok(a) => a,
            Err(e) => {
                self.vault = None;
                return Err(e.into());
            }
        };
        self.delete_rescue_copies();
        let v = self.vault()?;
        let (path, id) = (v.path().to_path_buf(), v.vault_id().to_string());
        let (modified, key_changed) = (v.modified_at(), v.key_changed_at());
        self.config.set_vault_path(&path);
        // Người dùng chủ động dựng lại kho ⇒ lấy trạng thái này làm mốc "đã thấy" mới.
        self.config.set_seen(&id, modified, key_changed);
        self.save_config()?;
        self.after_success();
        self.touch();
        Ok(RecoverInfo {
            entries: self.vault()?.entries().len(),
            files_used,
            newest_backup_at,
            archived: archived.map(|p| p.display().to_string()),
        })
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
        self.vault = None;
        self.disk_problem = None;
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

    fn merge_rescue_copies(&mut self) -> usize {
        let Some(id) = self.vault.as_ref().map(|v| v.vault_id().to_string()) else {
            return 0;
        };
        let files = self.rescue_files(&id);
        let Some(v) = self.vault.as_mut() else {
            return 0;
        };
        files.iter().filter(|f| v.merge_file(f).is_ok()).count()
    }

    /// Xoá các bản cứu hộ đã được gộp và GHI thành công vào kho.
    fn delete_rescue_copies(&self) {
        let Some(v) = self.vault.as_ref() else {
            return;
        };
        if v.has_unsaved_changes() {
            return;
        }
        for f in self.rescue_files(v.vault_id()) {
            let _ = std::fs::remove_file(f);
        }
    }

    /// Người dùng đã đọc cảnh báo "file kho cũ hơn bản từng thấy" và chấp nhận dùng bản hiện tại.
    pub fn accept_rollback(&mut self) -> AppResult<()> {
        let v = self.vault()?;
        let (id, m, k) = (
            v.vault_id().to_string(),
            v.modified_at(),
            v.key_changed_at(),
        );
        self.config.set_seen(&id, m, k);
        self.save_config()
    }

    /// Ghi nhớ vị trí kho mới mà không khoá kho đang mở (chọn lại file trên điện thoại).
    pub fn set_vault_location_keep_open(&mut self, location: &str) -> AppResult<()> {
        self.config.set_vault_path(Path::new(location));
        self.save_config()
    }

    pub fn set_vault_path(&mut self, path: &Path) -> AppResult<()> {
        self.lock();
        // Lời nhắn "vì sao kho bị khoá" là của kho cũ, không còn đúng với kho vừa chọn.
        self.lock_note = None;
        self.config.set_vault_path(path);
        self.save_config()
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
    pub fn field_value(&mut self, id: &str, field: &str) -> AppResult<Zeroizing<String>> {
        self.touch();
        let e = self.entry(id)?;
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
        self.mutate(|v| match existing {
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
        })
    }

    /// Xoá = chuyển vào thùng rác.
    pub fn delete_entry(&mut self, id: &str) -> AppResult<SyncResult> {
        Ok(self.mutate(|v| v.delete(id))?.1)
    }

    pub fn toggle_favorite(&mut self, id: &str) -> AppResult<bool> {
        let (fav, _) = self.mutate(|v| {
            let now = !v
                .get(id)
                .ok_or_else(|| VaultError::EntryNotFound(id.to_string()))?
                .favorite;
            v.update(id, |e| e.favorite = now)?;
            Ok(now)
        })?;
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
        self.mutate(|v| v.restore(id))?;
        Ok(())
    }

    /// Xoá vĩnh viễn một mục trong thùng rác (trên mọi thiết bị).
    pub fn purge_entry(&mut self, id: &str) -> AppResult<()> {
        self.mutate(|v| {
            if v.get_trashed(id).is_none() {
                return Err(VaultError::EntryNotFound(id.to_string()));
            }
            v.purge(id)
        })?;
        Ok(())
    }

    pub fn empty_trash(&mut self) -> AppResult<usize> {
        Ok(self.mutate(|v| Ok(v.empty_trash()))?.0)
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
        let r = v.change_password(new.as_bytes(), kdf);
        match r {
            Ok(report) => {
                self.after_success();
                Ok(PasswordChangeView {
                    backups_reencrypted: report.backups_reencrypted,
                    backups_skipped: report.backups_skipped,
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
        let (view, _) = self.mutate(|v| {
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
                v.add(e);
            }
            Ok(view)
        })?;
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
            .map(|b| BackupView {
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
                entries: v.read_backup(&b.path).ok().map(|d| d.entries.len()),
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
        let (n, _) = self.mutate(|v| {
            Ok(ids
                .iter()
                .filter_map(|id| old.get(id))
                .filter(|e| v.reinstate(e))
                .count())
        })?;
        Ok(n)
    }

    // ------------------------------------------------------------------ chuyển kho / cài đặt

    /// Chuyển kho đang mở sang vị trí mới và ghi nhớ vị trí đó.
    pub fn move_vault(&mut self, new_path: &Path) -> AppResult<MoveView> {
        self.touch();
        let r = self.vault_mut()?.move_to(new_path);
        let r = match r {
            Ok(r) => r,
            Err(e) => return Err(self.vault_error(e)),
        };
        let new_path = self.vault()?.path().to_path_buf();
        self.config.set_vault_path(&new_path);
        self.save_config()?;
        self.after_success();
        Ok(MoveView {
            new_path: new_path.display().to_string(),
            backups_moved: r.backups_moved,
            old_removed: r.old_removed,
            conflicts_merged: r.conflicts_merged,
            rescued: r.rescued,
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
        self.config.auto_lock_minutes = s.auto_lock_minutes.min(MAX_AUTO_LOCK_MINUTES);
        self.config.clipboard_clear_secs = s
            .clipboard_clear_secs
            .clamp(CLIPBOARD_CLEAR_SECS_MIN, CLIPBOARD_CLEAR_SECS_MAX);
        self.config.check_updates = s.check_updates;
        self.save_config()
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
            last_activity: Instant::now(),
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
        assert_eq!(s.empty_trash().unwrap(), 1);
        assert_eq!(s.status().trash_count, 0);
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
        s.last_activity = Instant::now() - Duration::from_secs(61);
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
        s.lock();
        assert_eq!(
            std::fs::read_dir(d.path().join("rescue")).unwrap().count(),
            1
        );
        // …mở khoá thì báo file hỏng; "khôi phục" dựng lại từ sao lưu + bản cứu hộ, không thiếu gì.
        assert_eq!(s.unlock(&p, MP).unwrap_err().code, "file_damaged");
        let r = s.recover(&p, MP).unwrap();
        assert_eq!(r.entries, 2);
        assert!(r.archived.is_some());
        assert_eq!(titles(&s), ["A", "B"]);
        assert_eq!(other_device(&p).entries().len(), 2);
        assert_eq!(
            std::fs::read_dir(d.path().join("rescue")).unwrap().count(),
            0
        );
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
        assert_eq!(titles(&s), ["A"]);
        // Cảnh báo lặp lại ở mỗi lần mở cho tới khi người dùng bấm "đã hiểu".
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
        assert!(s.move_vault(&backup_dir(&p).join("v.pwv")).is_err());
        assert_eq!(other_device(&p).entries().len(), 2, "kho cũ còn nguyên");
        let target = d.path().join("Dropbox").join("vault.pwv");
        let r = s.move_vault(&target).unwrap();
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
}
