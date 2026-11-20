//! Lớp Tauri: chuyển lời gọi từ giao diện vào `Session`.
//!
//! Các lệnh có đọc/ghi đĩa đều chạy NGOÀI luồng giao diện (`command(async)`), để một thư mục đồng
//! bộ chậm không làm đơ cửa sổ. Việc gọi mạng (kiểm tra rò rỉ, kiểm tra bản mới) được làm khi KHÔNG
//! giữ khoá phiên, để mạng treo không chặn việc tự khoá.

mod session;
mod update;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use pwv_vault_core::config::CLIPBOARD_CLEAR_SECS_MAX;
use session::*;
use tauri::{Emitter, Manager, State};
use zeroize::Zeroizing;

type AppState = Mutex<Session>;

/// Lấy khoá phiên. Nếu một lệnh trước đó panic khi đang giữ khoá (mutex "nhiễm độc"), vẫn lấy được
/// — nhờ vậy các đường KHOÁ KHO không bao giờ bị vô hiệu.
fn lock_state(state: &AppState) -> MutexGuard<'_, Session> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn with<T>(state: &State<AppState>, f: impl FnOnce(&mut Session) -> AppResult<T>) -> AppResult<T> {
    f(&mut lock_state(state))
}

/// Chạy việc nặng (Argon2 256 MiB, đọc file qua mạng) ở luồng nền.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> AppResult<T> + Send + 'static,
) -> AppResult<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| AppError::new("error", e.to_string()))?
}

// ----------------------------------------------------------------------------- lệnh

#[tauri::command(async)]
fn status(state: State<AppState>) -> AppResult<Status> {
    with(&state, |s| Ok(s.status()))
}

/// Gợi ý vị trí đặt kho (dò thư mục Drive/Dropbox/OneDrive) — chỉ gọi ở màn hình tạo/chuyển kho.
#[tauri::command(async)]
fn suggest_path() -> String {
    pwv_vault_core::config::suggest_vault_location()
        .display()
        .to_string()
}

/// Dấu vết của một kho đã có ở thư mục định tạo kho mới (xem `Session::existing_vault_traces`).
#[tauri::command(async)]
fn vault_traces(path: String) -> Vec<String> {
    Session::existing_vault_traces(&PathBuf::from(path))
}

#[tauri::command]
fn touch(state: State<AppState>) -> AppResult<()> {
    with(&state, |s| {
        s.touch();
        Ok(())
    })
}

/// Giao diện vừa được nạp (lần đầu, hoặc WebView bị hệ điều hành tạo lại).
///
/// Trên điện thoại, một trang mới mà phiên vẫn đang mở khoá nghĩa là Android đã dựng lại WebView
/// (đổi cỡ chữ, thu hồi bộ nhớ…) — mọi bộ đếm "khoá khi ở nền" trong trang cũ đã mất, nên khoá lại
/// cho chắc. Trên máy tính thì app chủ động nạp lại trang sau khi mở khoá (để xoá master password
/// khỏi bộ nhớ của WebView), nên không khoá.
#[tauri::command]
fn page_loaded(state: State<AppState>) -> AppResult<()> {
    if cfg!(mobile) {
        with(&state, |s| {
            if s.vault.is_some() {
                s.lock_because("Kho đã khoá lại vì màn hình app vừa được hệ điều hành nạp lại.");
            }
            Ok(())
        })?;
    }
    let _ = state;
    Ok(())
}

/// Argon2id 256 MiB mất ~1 giây ⇒ chạy ở luồng nền để giao diện không bị treo.
#[tauri::command]
async fn create_vault(app: tauri::AppHandle, path: String, password: String) -> AppResult<()> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let state = app.state::<AppState>();
        let mut s = lock_state(&state);
        s.create_vault(&PathBuf::from(path), &password)
    })
    .await
}

#[tauri::command]
async fn unlock(app: tauri::AppHandle, path: String, password: String) -> AppResult<UnlockInfo> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let state = app.state::<AppState>();
        let mut s = lock_state(&state);
        s.unlock(&PathBuf::from(path), &password)
    })
    .await
}

/// File kho hỏng: dựng lại từ thư mục sao lưu.
#[tauri::command]
async fn recover_vault(
    app: tauri::AppHandle,
    path: String,
    password: String,
) -> AppResult<RecoverInfo> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let state = app.state::<AppState>();
        let mut s = lock_state(&state);
        s.recover(&PathBuf::from(path), &password)
    })
    .await
}

/// Người dùng bấm "đã hiểu" ở cảnh báo file kho cũ hơn bản từng thấy.
#[tauri::command(async)]
fn accept_rollback(state: State<AppState>) -> AppResult<()> {
    with(&state, |s| s.accept_rollback())
}

#[tauri::command(async)]
fn lock(state: State<AppState>) -> AppResult<()> {
    // Không xoá clipboard ở đây: "chép mật khẩu → khoá app → dán" là thao tác bình thường; bộ hẹn
    // giờ vẫn xoá sau N giây vì tiến trình còn chạy.
    with(&state, |s| {
        s.lock();
        Ok(())
    })
}

#[tauri::command(async)]
fn set_vault_path(state: State<AppState>, path: String) -> AppResult<()> {
    with(&state, |s| s.set_vault_path(&PathBuf::from(path)))
}

#[tauri::command]
fn list_entries(state: State<AppState>, query: String) -> AppResult<Vec<EntrySummary>> {
    with(&state, |s| s.list(&query))
}

#[tauri::command]
fn get_entry(state: State<AppState>, id: String) -> AppResult<EntryDetail> {
    with(&state, |s| s.detail(&id))
}

#[tauri::command]
fn reveal_password(state: State<AppState>, id: String) -> AppResult<String> {
    with(&state, |s| s.reveal_password(&id))
}

#[tauri::command]
fn reveal_notes(state: State<AppState>, id: String) -> AppResult<String> {
    with(&state, |s| s.reveal_notes(&id))
}

#[tauri::command]
fn reveal_totp_secret(state: State<AppState>, id: String) -> AppResult<String> {
    with(&state, |s| s.reveal_totp_secret(&id))
}

#[tauri::command]
fn password_history(state: State<AppState>, id: String) -> AppResult<Vec<HistoryView>> {
    with(&state, |s| s.history(&id))
}

#[tauri::command]
fn totp_code(state: State<AppState>, id: String) -> AppResult<TotpCode> {
    with(&state, |s| s.totp(&id))
}

/// Sao chép trực tiếp từ Rust vào clipboard: bí mật không đi qua JavaScript.
/// `field`: password | username | totp | url | notes | history:<n>.
#[tauri::command(async)]
fn copy_field(
    app: tauri::AppHandle,
    state: State<AppState>,
    id: String,
    field: String,
) -> AppResult<u32> {
    let (value, secs) = with(&state, |s| {
        Ok((s.field_value(&id, &field)?, s.config.clipboard_clear_secs))
    })?;
    copy_with_auto_clear(&app, value, secs)?;
    Ok(secs)
}

/// Sao chép một đoạn văn bản do giao diện đưa xuống (mật khẩu vừa tạo, hoặc phần người dùng bôi đen
/// rồi bấm Ctrl+C) qua CÙNG đường bảo vệ: không vào lịch sử clipboard, tự xoá sau N giây.
#[tauri::command(async)]
fn copy_text(app: tauri::AppHandle, state: State<AppState>, text: String) -> AppResult<u32> {
    let text = Zeroizing::new(text);
    if text.is_empty() {
        return Err("Không có gì để sao chép".into());
    }
    let secs = with(&state, |s| {
        s.touch();
        Ok(s.config.clipboard_clear_secs)
    })?;
    copy_with_auto_clear(&app, text, secs)?;
    Ok(secs)
}

#[tauri::command(async)]
fn save_entry(state: State<AppState>, entry: EntryInput) -> AppResult<(String, SyncResult)> {
    with(&state, |s| s.save_entry(entry))
}

#[tauri::command(async)]
fn delete_entry(state: State<AppState>, id: String) -> AppResult<SyncResult> {
    with(&state, |s| s.delete_entry(&id))
}

#[tauri::command(async)]
fn toggle_favorite(state: State<AppState>, id: String) -> AppResult<bool> {
    with(&state, |s| s.toggle_favorite(&id))
}

#[tauri::command]
fn list_trash(state: State<AppState>) -> AppResult<Vec<TrashItem>> {
    with(&state, |s| s.list_trash())
}

#[tauri::command(async)]
fn restore_entry(state: State<AppState>, id: String) -> AppResult<()> {
    with(&state, |s| s.restore_entry(&id))
}

#[tauri::command(async)]
fn purge_entry(state: State<AppState>, id: String) -> AppResult<()> {
    with(&state, |s| s.purge_entry(&id))
}

#[tauri::command(async)]
fn empty_trash(state: State<AppState>) -> AppResult<usize> {
    with(&state, |s| s.empty_trash())
}

#[tauri::command(async)]
fn sync_now(state: State<AppState>) -> AppResult<SyncResult> {
    with(&state, |s| s.sync())
}

/// Người dùng xác nhận ghi bản đang mở đè lên file hỏng / tạo lại file đã biến mất.
#[tauri::command(async)]
fn force_write(state: State<AppState>) -> AppResult<Option<String>> {
    with(&state, |s| s.force_write())
}

#[tauri::command]
fn generate(request: GenRequest) -> AppResult<Generated> {
    session::generate(request)
}

/// Độ mạnh của mật khẩu MỘT TÀI KHOẢN đang gõ trong form (không dùng cho master password).
#[tauri::command]
fn strength(password: String) -> pwv_generator::Strength {
    let password = Zeroizing::new(password);
    pwv_generator::estimate_strength(&password, &[])
}

/// Chấm master password theo chính sách. Giao diện chỉ gọi khi người dùng rời ô nhập / bấm nút,
/// không gọi theo từng phím (mỗi lần gọi để lại một bản sao của mật khẩu trong bộ đệm IPC).
#[tauri::command]
fn master_check(password: String) -> pwv_generator::MasterCheck {
    let password = Zeroizing::new(password);
    pwv_generator::check_master_password(&password)
}

#[tauri::command]
async fn change_master_password(
    app: tauri::AppHandle,
    current: String,
    new: String,
) -> AppResult<PasswordChangeView> {
    let (current, new) = (Zeroizing::new(current), Zeroizing::new(new));
    blocking(move || {
        let state = app.state::<AppState>();
        let mut s = lock_state(&state);
        s.change_master_password(&current, &new)
    })
    .await
}

/// Báo cáo sức khoẻ mật khẩu. Kiểm tra rò rỉ (cần mạng) chạy ở luồng nền và KHÔNG giữ khoá phiên
/// trong lúc gọi mạng.
#[tauri::command]
async fn health_report(app: tauri::AppHandle, online: bool) -> AppResult<HealthView> {
    blocking(move || {
        let state = app.state::<AppState>();
        if !online {
            return lock_state(&state).health(None, None);
        }
        let queries = lock_state(&state).breach_queries()?;
        let outcome = pwv_health::run_breach_queries(&queries, pwv_health::hibp_fetch);
        drop(queries);
        let s = lock_state(&state);
        match outcome {
            Ok(found) => s.health(Some(&found), None),
            Err(e) => s.health(None, Some(e.to_string())),
        }
    })
    .await
}

#[tauri::command(async)]
fn import_csv(state: State<AppState>, path: String) -> AppResult<ImportView> {
    with(&state, |s| s.import_csv(&PathBuf::from(path)))
}

/// Xoá file CSV vừa nhập (đúng file đó, do Rust ghi nhớ — giao diện không truyền đường dẫn).
#[tauri::command(async)]
fn delete_imported_csv(state: State<AppState>) -> AppResult<()> {
    with(&state, |s| s.delete_imported_csv())
}

#[tauri::command(async)]
fn move_vault(state: State<AppState>, path: String) -> AppResult<MoveView> {
    with(&state, |s| s.move_vault(&PathBuf::from(path)))
}

#[tauri::command(async)]
fn list_backups(state: State<AppState>) -> AppResult<Vec<BackupView>> {
    with(&state, |s| s.list_backups())
}

#[tauri::command(async)]
fn backup_diff(state: State<AppState>, name: String) -> AppResult<Vec<BackupEntryView>> {
    with(&state, |s| s.backup_diff(&name))
}

#[tauri::command(async)]
fn restore_from_backup(state: State<AppState>, name: String, ids: Vec<String>) -> AppResult<usize> {
    with(&state, |s| s.restore_from_backup(&name, &ids))
}

#[tauri::command]
fn app_version() -> &'static str {
    update::CURRENT_VERSION
}

/// Kiểm tra bản mới (cần mạng ⇒ chạy nền). Trả về None nếu chưa có bản phát hành nào.
#[tauri::command]
async fn check_update() -> AppResult<Option<update::UpdateInfo>> {
    blocking(|| update::check().map_err(AppError::from)).await
}

/// Mở trang tải của một phiên bản trong trình duyệt. Địa chỉ được DỰNG từ số phiên bản (đã kiểm
/// tra chỉ gồm chữ số và dấu chấm) — không bao giờ mở một địa chỉ do giao diện hay mạng đưa xuống.
#[tauri::command]
fn open_release_page(app: tauri::AppHandle, version: String) -> AppResult<()> {
    use tauri_plugin_opener::OpenerExt;
    let url = update::release_page_url(&version).ok_or("Số phiên bản không hợp lệ")?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| AppError::new("error", e.to_string()))
}

#[tauri::command]
fn get_settings(state: State<AppState>) -> AppResult<Settings> {
    with(&state, |s| Ok(s.settings()))
}

#[tauri::command(async)]
fn set_settings(state: State<AppState>, settings: Settings) -> AppResult<()> {
    with(&state, |s| s.set_settings(settings))
}

#[tauri::command]
fn backups_dir(state: State<AppState>) -> AppResult<Option<String>> {
    with(&state, |s| {
        Ok(s.backups_dir().map(|p| p.display().to_string()))
    })
}

// ----------------------------------------------------------------------------- chế độ chỉ đọc (điện thoại)

#[derive(serde::Serialize)]
struct ReadOnlyOpen {
    /// Đang dùng bản đã lưu trên máy (không đọc được file mới, hoặc file mới bị hỏng).
    from_cache: bool,
    note: Option<String>,
}

/// Đọc file kho: đường dẫn thường hoặc URI `content://` (Drive/Dropbox/OneDrive trên Android).
/// Lỗi ở đây mang mã `read_failed` để giao diện biết cần gợi ý "chọn lại file".
fn read_location(app: &tauri::AppHandle, location: &str) -> AppResult<Vec<u8>> {
    use tauri_plugin_fs::FsExt;
    let fp: tauri_plugin_fs::FilePath = location
        .parse()
        .map_err(|_| AppError::new("read_failed", "Đường dẫn kho không hợp lệ"))?;
    app.fs()
        .read(fp)
        .map_err(|e| AppError::new("read_failed", format!("Không đọc được file kho: {e}")))
}

/// FNV-1a 64 bit — chỉ để đặt tên file bản lưu theo vị trí kho (không dùng cho mục đích bảo mật).
fn location_tag(location: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in location.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Bản sao kho (vẫn đã mã hoá) trong bộ nhớ riêng của app — để mở được khi offline hoặc khi Android
/// thu hồi quyền đọc file. Mỗi vị trí kho có một bản lưu riêng: chọn kho khác thì không bao giờ mở
/// nhầm bản lưu của kho cũ.
fn cache_path(app: &tauri::AppHandle, location: &str) -> Option<PathBuf> {
    app.path()
        .app_data_dir()
        .ok()
        .map(|d| d.join(format!("vault-cache-{}.pwv", location_tag(location))))
}

/// Ghi bản lưu ngoại tuyến (nguyên tử: bị tắt giữa chừng thì bản cũ vẫn nguyên) và dọn bản lưu của
/// các vị trí khác.
fn write_cache(app: &tauri::AppHandle, location: &str, bytes: &[u8]) {
    let Some(p) = cache_path(app, location) else {
        return;
    };
    let Some(dir) = p.parent() else {
        return;
    };
    let _ = std::fs::create_dir_all(dir);
    if pwv_vault_core::fsutil::atomic_write(&p, bytes).is_err() {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for other in rd.filter_map(|e| e.ok().map(|e| e.path())) {
            let name = other
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if other != p && name.starts_with("vault-cache") && name.ends_with(".pwv") {
                let _ = std::fs::remove_file(other);
            }
        }
    }
}

fn vault_location(app: &tauri::AppHandle) -> AppResult<String> {
    let state = app.state::<AppState>();
    let s = lock_state(&state);
    Ok(s.config
        .vault
        .clone()
        .ok_or("Chưa chọn file kho")?
        .to_string_lossy()
        .to_string())
}

/// Lưu kho đang mở (đã gộp mọi thứ từng thấy) làm bản xem ngoại tuyến.
fn refresh_cache(app: &tauri::AppHandle, location: &str) {
    let state = app.state::<AppState>();
    let bytes = lock_state(&state).export_bytes();
    if let Ok(bytes) = bytes {
        write_cache(app, location, &bytes);
    }
}

#[tauri::command]
async fn open_readonly(app: tauri::AppHandle, password: String) -> AppResult<ReadOnlyOpen> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let location = vault_location(&app)?;
        let fresh = read_location(&app, &location);
        let cached = cache_path(&app, &location).and_then(|p| std::fs::read(p).ok());
        let state = app.state::<AppState>();
        let mut s = lock_state(&state);
        let outcome = match (&fresh, &cached) {
            (Ok(bytes), _) => match s.unlock_bytes(&location, bytes, &password) {
                Ok(()) => {
                    // Gộp thêm bản đã lưu: dữ liệu trên điện thoại không bao giờ đi lùi, kể cả khi
                    // dịch vụ đồng bộ trả về một bản cũ. (Nếu bản đã lưu dùng master password MỚI
                    // hơn file vừa đọc thì phiên bị khoá kèm lời giải thích — xem bên dưới.)
                    if let Some(c) = &cached {
                        if let Err(e) = s.reload_bytes(c) {
                            if e.code == "password_changed" {
                                return Err(AppError::new(
                                    "password_changed",
                                    "File kho vừa đọc CŨ HƠN bản đã lưu trên máy (dùng mật khẩu chính \
                                     cũ). Hãy nhập mật khẩu chính MỚI, hoặc chọn lại đúng file kho.",
                                ));
                            }
                        }
                    }
                    Ok(ReadOnlyOpen {
                        from_cache: false,
                        note: None,
                    })
                }
                // Sai mật khẩu thì KHÔNG lùi về bản đã lưu: nếu vừa đổi master password trên máy
                // tính, bản lưu cũ vẫn mở được bằng mật khẩu cũ và sẽ hiện dữ liệu lỗi thời.
                Err(e) if e.code == "wrong_password" => Err(e),
                // File mới đọc được nhưng hỏng (tải dở): dùng bản đã lưu nếu có.
                Err(e) => match &cached {
                    Some(c) if s.unlock_bytes(&location, c, &password).is_ok() => {
                        Ok(ReadOnlyOpen {
                            from_cache: true,
                            note: Some(format!(
                                "File kho vừa tải về không mở được ({e}) nên đang dùng bản đã lưu \
                                 trên máy."
                            )),
                        })
                    }
                    _ => Err(e),
                },
            },
            (Err(read_err), Some(c)) => match s.unlock_bytes(&location, c, &password) {
                Ok(()) => Ok(ReadOnlyOpen {
                    from_cache: true,
                    note: Some(read_err.message.clone()),
                }),
                Err(e) => Err(AppError::new(
                    &e.code,
                    format!(
                        "{read_err}. Bản đã lưu trên máy cũng không mở được: {e}. Nếu bạn vừa đổi \
                         mật khẩu chính trên máy tính thì bản lưu trên điện thoại vẫn dùng mật khẩu \
                         CŨ — hãy bấm “Chọn file kho khác” để chọn lại file."
                    ),
                )),
            },
            (Err(read_err), None) => Err(AppError::new(
                "read_failed",
                format!("{read_err}. Hãy chọn lại file kho."),
            )),
        };
        drop(s);
        if outcome.is_ok() {
            refresh_cache(&app, &location);
        }
        outcome
    })
    .await
}

/// Đọc lại file kho từ Drive/Dropbox/OneDrive. Trả về true nếu có dữ liệu mới.
#[tauri::command]
async fn reload_readonly(app: tauri::AppHandle) -> AppResult<bool> {
    blocking(move || {
        let location = vault_location(&app)?;
        let bytes = read_location(&app, &location)?;
        let state = app.state::<AppState>();
        let changed = lock_state(&state).reload_bytes(&bytes)?;
        refresh_cache(&app, &location);
        Ok(changed)
    })
    .await
}

/// Chọn lại file (cấp lại quyền đọc trên Android) rồi nạp — không cần nhập lại mật khẩu nếu vẫn
/// là cùng một kho. Dữ liệu được GỘP nên chọn nhầm một bản cũ cũng không làm mất gì.
#[tauri::command]
async fn repick_readonly(app: tauri::AppHandle, location: String) -> AppResult<bool> {
    blocking(move || {
        let bytes = read_location(&app, &location)?;
        let state = app.state::<AppState>();
        let mut s = lock_state(&state);
        let changed = s.reload_bytes(&bytes)?;
        s.set_vault_location_keep_open(&location)?;
        drop(s);
        refresh_cache(&app, &location);
        Ok(changed)
    })
    .await
}

// ----------------------------------------------------------------------------- clipboard

/// Bí mật gần nhất đã đưa vào clipboard và chưa xoá. Giữ lại để xoá được ngay khi app THOÁT hoặc
/// KHOÁ (bản 0.1.2 chỉ có một luồng hẹn giờ — đóng app trong vòng 20 giây là mật khẩu nằm lại trên
/// clipboard vô thời hạn).
#[derive(Default)]
struct ClipboardGuard {
    pending: Mutex<Option<(u64, Zeroizing<String>)>>,
    next_id: AtomicU64,
    /// Cửa sổ đã đóng và app đang ẩn chờ xoá clipboard rồi mới thoát.
    exit_when_cleared: AtomicBool,
}

impl ClipboardGuard {
    fn has_pending(&self) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    fn remember(&self, value: Zeroizing<String>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        *self.pending.lock().unwrap_or_else(|p| p.into_inner()) = Some((id, value));
        id
    }

    /// Lấy bí mật đang chờ xoá. `only`: chỉ lấy nếu đó vẫn là lần sao chép ấy (để bộ hẹn giờ cũ
    /// không xoá sớm một lần sao chép mới hơn).
    fn take(&self, only: Option<u64>) -> Option<Zeroizing<String>> {
        let mut p = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        match (&*p, only) {
            (Some((id, _)), Some(want)) if *id != want => None,
            _ => p.take().map(|(_, v)| v),
        }
    }
}

fn copy_with_auto_clear(
    app: &tauri::AppHandle,
    value: Zeroizing<String>,
    secs: u32,
) -> AppResult<()> {
    set_clipboard(app, &value)?;
    let id = app.state::<ClipboardGuard>().remember(value);
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(u64::from(secs)));
        clear_clipboard_if_ours(&app, Some(id));
    });
    Ok(())
}

/// Xoá clipboard nếu nó vẫn đang giữ bí mật do app đưa vào.
fn clear_clipboard_if_ours(app: &tauri::AppHandle, only: Option<u64>) {
    if let Some(value) = app.state::<ClipboardGuard>().take(only) {
        clear_clipboard(app, &value);
    }
}

#[cfg(desktop)]
fn set_clipboard(_app: &tauri::AppHandle, value: &str) -> AppResult<()> {
    let mut cb = arboard::Clipboard::new()
        .map_err(|e| AppError::new("error", format!("Không mở được clipboard: {e}")))?;
    set_clipboard_text(&mut cb, value).map_err(|e| AppError::new("error", e))
}

#[cfg(all(desktop, windows))]
fn set_clipboard_text(cb: &mut arboard::Clipboard, value: &str) -> Result<(), String> {
    use arboard::SetExtWindows;
    // Không vào lịch sử clipboard (Win+V), không đồng bộ lên cloud clipboard, và đánh dấu để các
    // trình quản lý clipboard của bên thứ ba bỏ qua.
    cb.set()
        .exclude_from_history()
        .exclude_from_cloud()
        .exclude_from_monitoring()
        .text(value)
        .map_err(|e| e.to_string())
}

#[cfg(all(desktop, not(windows)))]
fn set_clipboard_text(cb: &mut arboard::Clipboard, value: &str) -> Result<(), String> {
    cb.set_text(value).map_err(|e| e.to_string())
}

#[cfg(desktop)]
fn clear_clipboard(_app: &tauri::AppHandle, ours: &str) {
    // Clipboard có thể đang bị ứng dụng khác giữ trong tích tắc ⇒ thử lại vài lần.
    for _ in 0..5 {
        let Ok(mut cb) = arboard::Clipboard::new() else {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };
        match cb.get_text() {
            // Chỉ xoá nếu clipboard vẫn còn đúng giá trị của ta (người dùng có thể đã chép thứ khác).
            Ok(t) if t == ours => {
                let _ = cb.clear();
                return;
            }
            Ok(_) => return,
            // Clipboard đang chứa thứ không phải văn bản (ảnh chụp màn hình…) ⇒ không phải của ta.
            Err(arboard::Error::ContentNotAvailable) => return,
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

#[cfg(mobile)]
fn set_clipboard(app: &tauri::AppHandle, value: &str) -> AppResult<()> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    // write_secret đánh dấu nội dung là NHẠY CẢM: Android 13+ không hiện nó trong khung xem trước
    // clipboard, bàn phím không đưa vào lịch sử.
    app.clipboard()
        .write_secret(value.to_string())
        .map_err(|e| AppError::new("error", format!("Không chép được vào clipboard: {e}")))
}

#[cfg(mobile)]
fn clear_clipboard(app: &tauri::AppHandle, ours: &str) {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    // Android 10+ không cho app ở nền ĐỌC clipboard (đọc lỗi ⇒ coi như vẫn là của ta), nhưng vẫn
    // cho ghi — nên xoá bằng cách ghi đè chuỗi rỗng.
    let still_ours = app
        .clipboard()
        .read_text()
        .map(|t| t == ours)
        .unwrap_or(true);
    if still_ours {
        let _ = app.clipboard().write_secret(String::new());
    }
}

// ----------------------------------------------------------------------------- khởi động

/// Khoảng nghỉ giữa hai lần kiểm tra tự khoá.
const LOCK_TICK: Duration = Duration::from_secs(5);
/// Nếu đồng hồ nhảy quá mức này giữa hai lần kiểm tra thì máy vừa ngủ/ngủ đông (hoặc app bị hệ
/// điều hành "đóng băng" ở nền) ⇒ khoá ngay khi thức dậy, không chờ hết thời gian chờ.
const SUSPEND_GAP: Duration = Duration::from_secs(40);

fn lock_and_notify(app: &tauri::AppHandle, reason: &str, note: Option<&str>) {
    let state = app.state::<AppState>();
    let was_unlocked = {
        let mut s = lock_state(&state);
        let unlocked = s.vault.is_some();
        match note {
            Some(n) if unlocked => s.lock_because(n),
            _ => s.lock(),
        }
        unlocked
    };
    if was_unlocked {
        clear_clipboard_if_ours(app, None);
        let _ = app.emit("vault-locked", reason);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    // Chỉ cho chạy 1 cửa sổ app: tránh 2 tiến trình cùng ghi một file kho.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        // Mở lại app trong lúc nó đang ẩn chờ xoá clipboard: hiện lại cửa sổ và huỷ việc tự thoát.
        app.state::<ClipboardGuard>()
            .exit_when_cleared
            .store(false, Ordering::SeqCst);
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
    }));
    let app = builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .manage::<AppState>(Mutex::new(Session::default()))
        .manage(ClipboardGuard::default())
        .setup(|app| {
            // Điện thoại không có %APPDATA%: lưu cấu hình trong thư mục riêng của app.
            #[cfg(mobile)]
            {
                if let Ok(dir) = app.path().app_config_dir() {
                    pwv_vault_core::Config::set_dir(dir);
                    lock_state(&app.state::<AppState>()).config = pwv_vault_core::Config::load();
                }
            }
            // Nơi ghi bản cứu hộ khi phải khoá mà chưa lưu được ra thư mục đồng bộ.
            if let Ok(dir) = app.path().app_local_data_dir() {
                lock_state(&app.state::<AppState>()).rescue_dir = Some(dir.join("rescue"));
            }
            // Luồng tự khoá: chạy độc lập với giao diện, nên vẫn khoá kể cả khi JS bị treo.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut last = SystemTime::now();
                loop {
                    std::thread::sleep(LOCK_TICK);
                    let now = SystemTime::now();
                    let gap = now.duration_since(last).unwrap_or(Duration::ZERO);
                    last = now;
                    if gap > SUSPEND_GAP {
                        lock_and_notify(
                            &handle,
                            "suspend",
                            Some("Kho đã tự khoá vì máy vừa ngủ hoặc app bị tạm dừng."),
                        );
                        continue;
                    }
                    let state = handle.state::<AppState>();
                    let locked = lock_state(&state).auto_lock_if_idle();
                    if locked {
                        let _ = handle.emit("vault-locked", "idle");
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Đóng cửa sổ ⇒ xoá khoá khỏi RAM ngay.
                lock_state(&window.state::<AppState>()).lock();
                let app = window.app_handle().clone();
                let guard = app.state::<ClipboardGuard>();
                if cfg!(desktop) && guard.has_pending() {
                    // Vừa chép một mật khẩu: nếu thoát ngay thì bộ hẹn giờ xoá clipboard chết theo
                    // tiến trình và mật khẩu nằm lại vô thời hạn (lỗi của bản 0.1.2). Vì vậy chỉ ẨN
                    // cửa sổ — người dùng vẫn kịp dán — rồi thoát hẳn ngay khi clipboard đã được xoá.
                    api.prevent_close();
                    let _ = window.hide();
                    guard.exit_when_cleared.store(true, Ordering::SeqCst);
                    std::thread::spawn(move || {
                        let guard = app.state::<ClipboardGuard>();
                        let deadline = Instant::now()
                            + Duration::from_secs(u64::from(CLIPBOARD_CLEAR_SECS_MAX) + 5);
                        while guard.has_pending() && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(250));
                        }
                        // Người dùng đã mở lại app trong lúc chờ ⇒ không thoát nữa.
                        if guard.exit_when_cleared.swap(false, Ordering::SeqCst) {
                            clear_clipboard_if_ours(&app, None);
                            app.exit(0);
                        }
                    });
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            suggest_path,
            vault_traces,
            touch,
            page_loaded,
            create_vault,
            unlock,
            recover_vault,
            accept_rollback,
            lock,
            set_vault_path,
            list_entries,
            get_entry,
            reveal_password,
            reveal_notes,
            reveal_totp_secret,
            password_history,
            totp_code,
            copy_field,
            copy_text,
            save_entry,
            delete_entry,
            toggle_favorite,
            list_trash,
            restore_entry,
            purge_entry,
            empty_trash,
            sync_now,
            force_write,
            generate,
            strength,
            master_check,
            change_master_password,
            health_report,
            import_csv,
            delete_imported_csv,
            move_vault,
            list_backups,
            backup_diff,
            restore_from_backup,
            app_version,
            open_readonly,
            reload_readonly,
            repick_readonly,
            check_update,
            open_release_page,
            get_settings,
            set_settings,
            backups_dir,
        ])
        .build(tauri::generate_context!())
        .expect("không khởi động được ứng dụng");

    app.run(|handle, event| {
        // Mọi đường thoát (đóng cửa sổ, thoát từ hệ điều hành) đều khoá kho và dọn clipboard.
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            lock_state(&handle.state::<AppState>()).lock();
            clear_clipboard_if_ours(handle, None);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_guard_only_lets_the_newest_timer_clear() {
        let g = ClipboardGuard::default();
        assert!(g.take(None).is_none());
        let first = g.remember(Zeroizing::new("mật khẩu 1".into()));
        let second = g.remember(Zeroizing::new("mật khẩu 2".into()));
        assert_ne!(first, second);
        // Bộ hẹn giờ của lần sao chép đầu hết giờ: không được đụng vào lần sao chép thứ hai.
        assert!(g.take(Some(first)).is_none());
        assert_eq!(*g.take(Some(second)).unwrap(), "mật khẩu 2");
        assert!(g.take(Some(second)).is_none(), "chỉ xoá một lần");
        // Thoát app / khoá: lấy bất kể là lần nào.
        g.remember(Zeroizing::new("mật khẩu 3".into()));
        assert_eq!(*g.take(None).unwrap(), "mật khẩu 3");
    }

    #[test]
    fn cache_file_name_depends_on_the_vault_location() {
        let a = location_tag("content://com.google.android.apps.docs.storage/document/acc=1;doc=1");
        let b = location_tag("content://com.dropbox.android.document/document/2");
        assert_ne!(a, b);
        assert_eq!(a.len(), 16);
        assert_eq!(
            a,
            location_tag("content://com.google.android.apps.docs.storage/document/acc=1;doc=1")
        );
    }
}
