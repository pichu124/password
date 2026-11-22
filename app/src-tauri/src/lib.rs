//! Lớp Tauri: chuyển lời gọi từ giao diện vào `Session`.
//!
//! Điều được bảo đảm:
//! - MỌI lệnh lấy khoá phiên đều chạy NGOÀI luồng giao diện (`command(async)` hoặc `async fn`):
//!   một thư mục đồng bộ chậm / treo chỉ làm lệnh đó chờ, cửa sổ không bị đơ. `touch` (gửi khi rê
//!   chuột) không lấy khoá phiên: đồng hồ hoạt động nằm ngoài nó (`session::Activity`).
//! - Đóng cửa sổ không khoá / ghi trên luồng giao diện: việc đó chạy ở luồng nền rồi app mới thoát.
//! - Tự khoá (hết giờ, máy vừa ngủ) KHÔNG chờ khoá phiên: nếu một luồng khác đang giữ nó, luồng tự
//!   khoá ghi một yêu cầu khoá (`session::Shared::request_lock`), báo trang vứt bí mật NGAY, và khoá
//!   giải mã được xoá khỏi RAM ngay khi khoá phiên rảnh. Mọi lệnh lấy khoá phiên sau đó đều thực hiện
//!   yêu cầu khoá trước, nên không lệnh nào mang được màn hình đang mở khoá trở lại.
//! - Việc gọi mạng (kiểm tra rò rỉ, kiểm tra bản mới) được làm khi KHÔNG giữ khoá phiên.
//! - Không bảo đảm: một thao tác đĩa treo vĩnh viễn giữ khoá phiên thì khoá giải mã cũng nằm trong RAM
//!   tới lúc đó (màn hình thì đã sạch); app bị "End task" thì không có gì chạy được nữa.

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

type AppState = Shared;

/// Lấy khoá phiên (xem [`Shared::lock`]: vẫn lấy được khi mutex "nhiễm độc", và thực hiện yêu cầu
/// khoá đang chờ trước) — nhờ vậy các đường KHOÁ KHO không bao giờ bị vô hiệu.
fn lock_state(state: &AppState) -> MutexGuard<'_, Session> {
    state.lock()
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

/// Không lấy khoá phiên: chỉ ghi đồng hồ hoạt động (nằm ngoài khoá phiên).
#[tauri::command]
fn touch(state: State<AppState>) {
    state.activity.touch();
}

/// Giao diện vừa được nạp (lần đầu, hoặc WebView bị hệ điều hành tạo lại).
///
/// Trên điện thoại, một trang mới mà phiên vẫn đang mở khoá nghĩa là Android đã dựng lại WebView
/// (đổi cỡ chữ, thu hồi bộ nhớ…) — mọi bộ đếm "khoá khi ở nền" trong trang cũ đã mất, nên khoá lại
/// cho chắc. Trên máy tính thì app chủ động nạp lại trang sau khi mở khoá (để xoá master password
/// khỏi bộ nhớ của WebView), nên không khoá.
#[tauri::command(async)]
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

/// File kho hỏng: dựng lại từ thư mục sao lưu. Các lựa chọn rõ ràng của chủ kho (JS: camelCase):
/// `allow_older` — khôi phục từ các bản sao lưu tạo trước lần đổi mật khẩu chính gần nhất;
/// `allow_stale` — chấp nhận bản dựng lại cũ hơn dữ liệu máy này từng thấy; `replace_newer` — file
/// kho báo "định dạng mới hơn" vẫn được cất đi và thay.
#[tauri::command]
async fn recover_vault(
    app: tauri::AppHandle,
    path: String,
    password: String,
    allow_older: bool,
    allow_stale: Option<bool>,
    replace_newer: Option<bool>,
) -> AppResult<RecoverInfo> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let state = app.state::<AppState>();
        let mut s = lock_state(&state);
        s.recover_with(
            &PathBuf::from(path),
            &password,
            RecoverOpts {
                allow_older,
                allow_stale: allow_stale.unwrap_or(false),
                replace_newer: replace_newer.unwrap_or(false),
            },
        )
    })
    .await
}

/// Người dùng bấm "đã hiểu" ở cảnh báo file kho cũ hơn bản từng thấy.
#[tauri::command(async)]
fn accept_rollback(state: State<AppState>) -> AppResult<()> {
    with(&state, |s| s.accept_rollback())
}

/// Khoá bằng tay: KHÔNG chờ khoá phiên (một thao tác đĩa chậm có thể đang giữ nó). Ghi yêu cầu khoá
/// rồi trả về ngay — trang nạp lại và vứt bí mật; khoá giải mã bị xoá ngay khi khoá phiên rảnh, và
/// mọi lệnh đến sau (kể cả `status` của trang mới) đều thấy kho đã khoá.
///
/// `has_draft` + `draft` (JS: `{ hasDraft, draft, draftSeq }`, khi đang có form): bản nháp form đang
/// giữ NGAY LÚC NÀY (`draft: null` = form sạch). Nó vào hộp thư TRƯỚC khi yêu cầu khoá được ghi, nên
/// được ghi vào stash trước khi kho khoá.
#[tauri::command(async)]
fn lock(
    app: tauri::AppHandle,
    has_draft: Option<bool>,
    draft: Option<String>,
    draft_seq: Option<u64>,
) -> AppResult<()> {
    // Không xoá clipboard ở đây: "chép mật khẩu → khoá app → dán" là thao tác bình thường; bộ hẹn
    // giờ vẫn xoá sau N giây vì tiến trình còn chạy.
    let state = app.state::<AppState>();
    if has_draft == Some(true) {
        state.queue_stash(StashOp::Draft {
            draft: draft.map(Zeroizing::new),
            seq: draft_seq,
        });
    }
    state.request_lock(LOCK_MANUAL);
    std::thread::spawn(move || drop(lock_state(&app.state::<AppState>())));
    Ok(())
}

#[tauri::command(async)]
fn set_vault_path(state: State<AppState>, path: String) -> AppResult<()> {
    with(&state, |s| s.set_vault_path(&PathBuf::from(path)))
}

#[tauri::command(async)]
fn list_entries(state: State<AppState>, query: String) -> AppResult<Vec<EntrySummary>> {
    with(&state, |s| s.list(&query))
}

#[tauri::command(async)]
fn get_entry(state: State<AppState>, id: String) -> AppResult<EntryDetail> {
    with(&state, |s| s.detail(&id))
}

#[tauri::command(async)]
fn reveal_password(state: State<AppState>, id: String) -> AppResult<String> {
    with(&state, |s| s.reveal_password(&id))
}

#[tauri::command(async)]
fn reveal_notes(state: State<AppState>, id: String) -> AppResult<String> {
    with(&state, |s| s.reveal_notes(&id))
}

#[tauri::command(async)]
fn reveal_totp_secret(state: State<AppState>, id: String) -> AppResult<String> {
    with(&state, |s| s.reveal_totp_secret(&id))
}

#[tauri::command(async)]
fn password_history(state: State<AppState>, id: String) -> AppResult<Vec<HistoryView>> {
    with(&state, |s| s.history(&id))
}

#[tauri::command(async)]
fn totp_code(state: State<AppState>, id: String) -> AppResult<TotpCode> {
    with(&state, |s| s.totp(&id))
}

/// Sao chép trực tiếp từ Rust vào clipboard: bí mật không đi qua JavaScript.
/// `field`: password | username | totp | url | notes | url:<n> | history:<n>. `updated_at` (JS
/// `updatedAt`): thời điểm sửa của mục đang hiện; `shown`: dòng đang hiện (địa chỉ của `url:<n>`,
/// `replaced_at` của `history:<n>`) — mục đã đổi ⇒ lỗi `entry_changed`.
#[tauri::command(async)]
fn copy_field(
    app: tauri::AppHandle,
    state: State<AppState>,
    id: String,
    field: String,
    updated_at: Option<i64>,
    shown: Option<String>,
) -> AppResult<u32> {
    let (value, secs) = with(&state, |s| {
        Ok((
            s.field_value_checked(&id, &field, updated_at, shown.as_deref())?,
            s.config.clipboard_clear_secs,
        ))
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

#[tauri::command(async)]
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

/// `ids`: các mục người dùng đã thấy trong thùng rác lúc bấm xác nhận — chỉ những mục đó bị xoá.
#[tauri::command(async)]
fn empty_trash(state: State<AppState>, ids: Vec<String>) -> AppResult<EmptyTrashView> {
    with(&state, |s| s.empty_trash(&ids))
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

/// `copy_only` (JS `copyOnly`): chỉ ghi một bản sao sang chỗ mới, không đụng gì ở chỗ cũ.
#[tauri::command(async)]
fn move_vault(
    state: State<AppState>,
    path: String,
    copy_only: Option<bool>,
) -> AppResult<MoveView> {
    with(&state, |s| {
        s.move_vault(&PathBuf::from(path), copy_only.unwrap_or(false))
    })
}

// ----------------------------------------------------------------------------- bản nháp & mật khẩu vừa tạo

/// Đặt (chuỗi) hoặc xoá (`null`) bản nháp của form đang sửa.
/// Đi qua hộp thư (xem [`Shared::stash_op`]): một lần khoá được yêu cầu trong lúc lệnh này còn chờ khoá
/// phiên không làm mất nó. `draft_seq` (JS `draftSeq`): số thứ tự tăng dần — bản đến muộn mà cũ hơn bị bỏ.
#[tauri::command(async)]
fn set_draft(
    state: State<AppState>,
    draft: Option<String>,
    draft_seq: Option<u64>,
) -> AppResult<()> {
    state.stash_op(StashOp::Draft {
        draft: draft.map(Zeroizing::new),
        seq: draft_seq,
    })
}

#[tauri::command(async)]
fn get_draft(state: State<AppState>) -> AppResult<Option<String>> {
    with(&state, |s| s.draft())
}

#[tauri::command(async)]
fn record_generated(state: State<AppState>, value: String, label: Option<String>) -> AppResult<()> {
    state.stash_op(StashOp::Generated {
        value: Zeroizing::new(value),
        label,
    })
}

#[tauri::command(async)]
fn list_generated(state: State<AppState>) -> AppResult<Vec<GeneratedView>> {
    with(&state, |s| s.list_generated())
}

#[tauri::command(async)]
fn reveal_generated(state: State<AppState>, id: String) -> AppResult<String> {
    with(&state, |s| Ok(s.generated_value(&id)?.to_string()))
}

#[tauri::command(async)]
fn copy_generated(app: tauri::AppHandle, state: State<AppState>, id: String) -> AppResult<u32> {
    let (value, secs) = with(&state, |s| {
        Ok((s.generated_value(&id)?, s.config.clipboard_clear_secs))
    })?;
    copy_with_auto_clear(&app, value, secs)?;
    Ok(secs)
}

#[tauri::command(async)]
fn clear_generated(state: State<AppState>) -> AppResult<()> {
    with(&state, |s| s.clear_generated())
}

/// Quét (một lần cho mỗi khoá) xem kho có cần đổi mật khẩu chính để thay khoá không (0.1.x).
#[tauri::command(async)]
fn check_rekey(state: State<AppState>) -> AppResult<bool> {
    with(&state, |s| s.check_rekey())
}

/// Ghi bản lưu riêng trên máy này ra vị trí file kho đã cấu hình (không bao giờ ghi đè).
#[tauri::command(async)]
fn restore_local_copy(state: State<AppState>) -> AppResult<()> {
    with(&state, |s| s.restore_local_copy())
}

/// "Lưu sang chỗ khác": tạo sẵn thư mục con gợi ý bên trong thư mục của file kho.
#[tauri::command(async)]
fn prepare_copy_folder(state: State<AppState>, day: String) -> AppResult<String> {
    with(&state, |s| s.prepare_copy_folder(&day))
}

/// Xoá thư mục con vừa tạo cho "Lưu sang chỗ khác" nếu nó vẫn trống.
#[tauri::command(async)]
fn discard_copy_folder(state: State<AppState>) {
    lock_state(&state).discard_copy_folder();
}

/// File vừa chọn có phải bản xung đột của một file kho khác cùng thư mục không.
#[tauri::command(async)]
fn check_vault_choice(path: String) -> Option<ConflictHint> {
    Session::conflict_hint(&PathBuf::from(path))
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

#[tauri::command(async)]
fn get_settings(state: State<AppState>) -> AppResult<Settings> {
    with(&state, |s| Ok(s.settings()))
}

#[tauri::command(async)]
fn set_settings(state: State<AppState>, settings: Settings) -> AppResult<()> {
    with(&state, |s| s.set_settings(settings))
}

#[tauri::command(async)]
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
    app.fs().read(fp).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("Permission Denial") || msg.contains("SecurityException") {
            // Quyền đọc tạm thời của bộ chọn file cũ (trước 0.2.1) đã hết khi app bị đóng.
            AppError::new(
                "read_failed",
                "Android không còn cho app đọc file kho (quyền đọc đã hết hạn). Vào Cài đặt → chọn \
                 lại file kho: từ bản này quyền đọc được giữ lâu dài, chỉ cần làm một lần.",
            )
        } else {
            AppError::new("read_failed", format!("Không đọc được file kho: {msg}"))
        }
    })
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
                        if let Err(e) = s.merge_cached_bytes(c) {
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

/// Kết quả bộ chọn file kho của Android (`VaultPickerPlugin.kt`).
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct PickedVault {
    /// `None` = người dùng huỷ.
    #[serde(default)]
    uri: Option<String>,
    /// Android cho giữ quyền đọc lâu dài (còn sau khi app bị đóng).
    #[serde(default)]
    persisted: bool,
}

#[cfg(target_os = "android")]
struct VaultPicker(tauri::plugin::PluginHandle<tauri::Wry>);

/// Plugin nhỏ nạp bộ chọn file kho viết bằng Kotlin. Nạp không được (gói Android khác tên) thì app
/// vẫn chạy: giao diện lùi về bộ chọn file của plugin dialog.
#[cfg(target_os = "android")]
fn vault_picker_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::<tauri::Wry, ()>::new("vaultpicker")
        .setup(|app, api| {
            match api.register_android_plugin("vn.pwv.vault", "VaultPickerPlugin") {
                Ok(h) => {
                    app.manage(VaultPicker(h));
                }
                Err(e) => eprintln!("không nạp được bộ chọn file kho: {e}"),
            }
            Ok(())
        })
        .build()
}

/// Android: chọn file kho bằng ACTION_OPEN_DOCUMENT và giữ quyền đọc lâu dài (xem
/// `android-overrides/VaultPickerPlugin.kt`). Nơi khác: lỗi (giao diện dùng bộ chọn thường).
#[tauri::command]
async fn pick_vault_file(app: tauri::AppHandle, mode: Option<String>) -> AppResult<PickedVault> {
    #[cfg(target_os = "android")]
    {
        let mode = match mode.as_deref() {
            Some("apps") => "apps",
            _ => "documents",
        };
        blocking(move || {
            let picker = app
                .try_state::<VaultPicker>()
                .ok_or_else(|| AppError::new("error", "Bộ chọn file kho chưa sẵn sàng"))?;
            picker
                .0
                .run_mobile_plugin::<PickedVault>("pickVault", serde_json::json!({ "mode": mode }))
                .map_err(|e| AppError::new("error", format!("Không mở được bộ chọn file: {e}")))
        })
        .await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, mode);
        Err(AppError::new("error", "Chỉ dùng trên Android"))
    }
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

    /// Đưa `value` vào clipboard (`set`) và ghi nhớ nó dưới CÙNG một khoá: không lần xoá nào chen
    /// vào giữa được (nếu không, một bộ hẹn giờ cũ có thể "ghi nhớ" sai giá trị đang nằm trên clipboard).
    fn set_and_remember(
        &self,
        value: Zeroizing<String>,
        set: impl FnOnce(&str) -> AppResult<()>,
    ) -> AppResult<u64> {
        let mut p = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        set(&value)?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        *p = Some((id, value));
        Ok(id)
    }

    /// Xoá bí mật đang chờ (`clear` nhận giá trị để chỉ xoá nếu clipboard vẫn giữ đúng nó). `only`:
    /// chỉ khi đó vẫn là lần sao chép ấy (để bộ hẹn giờ cũ không xoá sớm một lần sao chép mới hơn).
    /// Việc xoá diễn ra khi VẪN giữ khoá: `has_pending` chỉ trả false khi đã xoá xong, nên lần thoát
    /// đang chờ không thể kết thúc tiến trình giữa chừng.
    fn clear_with(&self, only: Option<u64>, clear: impl FnOnce(&str)) -> bool {
        let mut p = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        match (&*p, only) {
            (None, _) => return false,
            (Some((id, _)), Some(want)) if *id != want => return false,
            (Some((_, v)), _) => clear(v),
        }
        *p = None;
        true
    }
}

fn copy_with_auto_clear(
    app: &tauri::AppHandle,
    value: Zeroizing<String>,
    secs: u32,
) -> AppResult<()> {
    let id = app
        .state::<ClipboardGuard>()
        .set_and_remember(value, |v| set_clipboard(app, v))?;
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(u64::from(secs)));
        clear_clipboard_if_ours(&app, Some(id));
    });
    Ok(())
}

/// Xoá clipboard nếu nó vẫn đang giữ bí mật do app đưa vào.
fn clear_clipboard_if_ours(app: &tauri::AppHandle, only: Option<u64>) {
    app.state::<ClipboardGuard>()
        .clear_with(only, |value| clear_clipboard(app, value));
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

/// Panic hook (chỉ máy tính): bản phát hành dùng `panic = "abort"`, nên một panic bất kỳ giết tiến
/// trình NGAY — bộ hẹn giờ xoá clipboard chết theo và mật khẩu vừa chép nằm lại trên clipboard vô
/// thời hạn. Hook này cố xoá clipboard (chỉ khi nó vẫn giữ đúng bí mật app đã chép) rồi mới để hook
/// mặc định chạy tiếp (in thông báo lỗi; sau đó tiến trình kết thúc như cũ).
///
/// Nguyên tắc trong hook: không bao giờ chờ và không được panic lần nữa — dùng `try_lock` (luồng
/// đang panic có thể chính là luồng đang giữ khoá), thử clipboard đúng một lần, bỏ qua mọi lỗi.
/// (Bản debug dùng `panic = "unwind"`: panic trong một lệnh không giết app nhưng hook vẫn xoá
/// clipboard sớm — vô hại.)
///
/// KHÔNG bảo vệ được: tiến trình chết mà không qua panic của Rust (lỗi truy cập bộ nhớ trong thư
/// viện C / WebView, bị "End task" hoặc bị hệ điều hành diệt, hết RAM), mất điện / máy treo cứng.
/// Khi đó clipboard có thể còn giữ mật khẩu cho tới khi người dùng chép thứ khác.
#[cfg(desktop)]
fn install_panic_hook(app: tauri::AppHandle) {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(guard) = app.try_state::<ClipboardGuard>() {
            let pending = match guard.pending.try_lock() {
                Ok(mut p) => p.take(),
                Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner().take(),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some((_, value)) = pending {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    if cb.get_text().is_ok_and(|t| t == *value) {
                        let _ = cb.clear();
                    }
                }
            }
        }
        default_hook(info);
    }));
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    // Chỉ cho chạy 1 cửa sổ app: tránh 2 tiến trình cùng ghi một file kho.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        // Mở lại app trong lúc nó đang ẩn chờ xoá clipboard: hiện lại cửa sổ và huỷ việc tự thoát.
        let was_closing = app
            .state::<ClipboardGuard>()
            .exit_when_cleared
            .swap(false, Ordering::SeqCst);
        if let Some(w) = app.get_webview_window("main") {
            // Cửa sổ đang ẩn vì vừa đóng: chắc chắn trang không còn hiện gì của lần mở khoá cũ.
            if was_closing {
                let _ = w.eval("window.location.reload()");
            }
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
    }));
    #[cfg(target_os = "android")]
    let builder = builder.plugin(vault_picker_plugin());
    let app = builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .manage::<AppState>(Shared::new(Session::default()))
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
            // Panic ⇒ cố xoá mật khẩu vừa chép khỏi clipboard trước khi tiến trình chết.
            #[cfg(desktop)]
            install_panic_hook(app.handle().clone());
            // Nơi ghi bản cứu hộ khi phải khoá mà chưa lưu được ra thư mục đồng bộ.
            if let Ok(dir) = app.path().app_local_data_dir() {
                lock_state(&app.state::<AppState>()).rescue_dir = Some(dir.join("rescue"));
            }
            // Luồng tự khoá: chạy độc lập với giao diện, nên vẫn khoá kể cả khi JS bị treo; và không
            // bao giờ chờ khoá phiên (xem đầu file).
            let handle = app.handle().clone();
            std::thread::spawn(move || auto_lock_loop(&handle));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Không khoá / ghi trên luồng giao diện: yêu cầu khoá (mọi lệnh đến sau đều thấy kho
                // đã khoá), báo trang vứt bí mật, ẩn cửa sổ; luồng nền khoá + ghi rồi mới thoát.
                api.prevent_close();
                let app = window.app_handle().clone();
                app.state::<AppState>().request_lock(LOCK_CLOSE);
                let _ = app.emit("vault-locked", "close");
                let _ = window.hide();
                app.state::<ClipboardGuard>()
                    .exit_when_cleared
                    .store(true, Ordering::SeqCst);
                std::thread::spawn(move || {
                    drop(lock_state(&app.state::<AppState>()));
                    let guard = app.state::<ClipboardGuard>();
                    if cfg!(desktop) {
                        // Vừa chép một mật khẩu: nếu thoát ngay thì bộ hẹn giờ xoá clipboard chết theo
                        // tiến trình (lỗi của bản 0.1.2). Cửa sổ đã ẩn — người dùng vẫn kịp dán — và app
                        // thoát hẳn ngay khi clipboard đã được xoá xong.
                        let deadline = Instant::now()
                            + Duration::from_secs(u64::from(CLIPBOARD_CLEAR_SECS_MAX) + 5);
                        while guard.has_pending() && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(250));
                        }
                    }
                    // Người dùng đã mở lại app trong lúc chờ ⇒ không thoát nữa.
                    if guard.exit_when_cleared.swap(false, Ordering::SeqCst) {
                        clear_clipboard_if_ours(&app, None);
                        app.exit(0);
                    }
                });
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
            set_draft,
            get_draft,
            record_generated,
            list_generated,
            reveal_generated,
            copy_generated,
            clear_generated,
            check_rekey,
            restore_local_copy,
            check_vault_choice,
            prepare_copy_folder,
            discard_copy_folder,
            pick_vault_file,
        ])
        .build(tauri::generate_context!())
        .expect("không khởi động được ứng dụng");

    app.run(|handle, event| {
        // Mọi đường thoát (đóng cửa sổ, thoát từ hệ điều hành) đều khoá kho và dọn clipboard.
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            // Luồng chính: không chờ một thao tác đĩa đang treo.
            let state = handle.state::<AppState>();
            match state.try_lock() {
                Some(mut s) => s.lock(),
                None => {
                    state.request_lock(LOCK_CLOSE);
                }
            }
            clear_clipboard_if_ours(handle, None);
        }
    });
}

/// Mỗi `LOCK_TICK`: tự khoá khi hết giờ hoặc khi máy vừa ngủ. Lấy khoá phiên bằng `try_lock`; nếu
/// một luồng khác đang giữ (thao tác đĩa chậm), quyết định bằng đồng hồ hoạt động + trạng thái đã
/// biết ở lần trước, rồi yêu cầu khoá mà không chờ.
fn auto_lock_loop(handle: &tauri::AppHandle) {
    let mut last = SystemTime::now();
    // (đang mở khoá, số phút tự khoá) — đọc ở lần lấy được khoá phiên gần nhất.
    let mut known = (false, 0u32);
    loop {
        std::thread::sleep(LOCK_TICK);
        let now = SystemTime::now();
        let gap = now.duration_since(last).unwrap_or(Duration::ZERO);
        last = now;
        let suspend = gap > SUSPEND_GAP;
        // Máy vừa ngủ: luôn xoá clipboard nếu nó còn giữ bí mật của app, dù kho đang khoá hay mở.
        if suspend {
            clear_clipboard_if_ours(handle, None);
        }
        let state = handle.state::<AppState>();
        if let Some(mut s) = state.try_lock() {
            known = (s.vault.is_some(), s.config.auto_lock_minutes);
            // Quyết định trước, báo trang vứt bí mật NGAY, rồi mới khoá: việc khoá có thể phải ghi ra
            // thư mục đồng bộ đang chậm. Trang vừa nạp lại hỏi `status` thì phải chờ khoá phiên — tới
            // lúc đó kho đã khoá xong. Hộp thư bản nháp được xử lý ngay trước khi khoá.
            state.drain(&mut s);
            s.auto_lock_step(suspend, |reason, _| {
                let _ = handle.emit("vault-locked", reason);
            });
            continue;
        }
        if should_lock_while_busy(known, suspend, state.activity.idle()) {
            let reason = if suspend { LOCK_SUSPEND } else { LOCK_IDLE };
            if state.request_lock(reason) {
                // Màn hình sạch NGAY; khoá giải mã bị xoá ngay khi khoá phiên rảnh.
                let _ = handle.emit("vault-locked", if suspend { "suspend" } else { "idle" });
                let h = handle.clone();
                std::thread::spawn(move || drop(lock_state(&h.state::<AppState>())));
                known.0 = false;
            }
        }
    }
}

/// Khoá phiên đang bị giữ: có phải khoá không? `known` = (đang mở khoá, số phút tự khoá) — đọc ở lần
/// lấy được khoá phiên gần nhất nên có thể đã cũ (ví dụ máy ngủ đúng lúc lệnh mở khoá đang chạy). Máy
/// vừa ngủ ⇒ luôn yêu cầu khoá (kho đã khoá sẵn thì yêu cầu đó không làm gì); hết giờ ⇒ chỉ khi biết
/// kho đang mở.
fn should_lock_while_busy(known: (bool, u32), suspend: bool, idle: Duration) -> bool {
    let (unlocked, mins) = known;
    suspend || (unlocked && mins > 0 && idle >= Duration::from_secs(u64::from(mins) * 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_guard_only_lets_the_newest_timer_clear() {
        let g = ClipboardGuard::default();
        let ok = |_: &str| Ok(());
        assert!(!g.clear_with(None, |_| panic!("không có gì để xoá")));
        let first = g
            .set_and_remember(Zeroizing::new("mật khẩu 1".into()), ok)
            .unwrap();
        let second = g
            .set_and_remember(Zeroizing::new("mật khẩu 2".into()), ok)
            .unwrap();
        assert_ne!(first, second);
        // Bộ hẹn giờ của lần sao chép đầu hết giờ: không được đụng vào lần sao chép thứ hai.
        assert!(!g.clear_with(Some(first), |_| panic!("không được xoá")));
        let mut cleared = String::new();
        assert!(g.clear_with(Some(second), |v| cleared = v.to_string()));
        assert_eq!(cleared, "mật khẩu 2");
        assert!(!g.clear_with(Some(second), |_| panic!("chỉ xoá một lần")));
        // Thoát app / khoá: xoá bất kể là lần nào.
        g.set_and_remember(Zeroizing::new("mật khẩu 3".into()), ok)
            .unwrap();
        assert!(g.clear_with(None, |v| assert_eq!(v, "mật khẩu 3")));
        // Không đặt được clipboard ⇒ không ghi nhớ gì.
        assert!(g
            .set_and_remember(Zeroizing::new("x".into()), |_| Err("lỗi".into()))
            .is_err());
        assert!(!g.has_pending());
    }

    /// Đang có lần xoá clipboard dở dang (giữ khoá của bộ bảo vệ) ⇒ `has_pending` chờ nó xong, nên
    /// vòng chờ trước khi thoát không thể kết thúc tiến trình giữa chừng.
    #[test]
    fn pending_clear_is_visible_until_it_finishes() {
        let g = std::sync::Arc::new(ClipboardGuard::default());
        g.set_and_remember(Zeroizing::new("bí mật".into()), |_| Ok(()))
            .unwrap();
        let g2 = g.clone();
        let t = std::thread::spawn(move || {
            g2.clear_with(None, |_| std::thread::sleep(Duration::from_millis(200)))
        });
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        assert!(!g.has_pending());
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "phải chờ lần xoá xong"
        );
        assert!(t.join().unwrap());
    }

    #[test]
    fn busy_session_still_locks_on_time() {
        let five = Duration::from_secs(5 * 60);
        assert!(should_lock_while_busy((true, 5), false, five));
        assert!(!should_lock_while_busy(
            (true, 5),
            false,
            five - Duration::from_secs(1)
        ));
        assert!(
            should_lock_while_busy((true, 5), true, Duration::ZERO),
            "máy vừa ngủ"
        );
        assert!(
            !should_lock_while_busy((true, 0), false, five * 100),
            "tự khoá tắt"
        );
        assert!(
            should_lock_while_busy((false, 5), true, five),
            "máy vừa ngủ: luôn yêu cầu khoá, dù lần đọc trước thấy kho đang khoá (có thể đã cũ)"
        );
        assert!(
            !should_lock_while_busy((false, 5), false, five * 100),
            "hết giờ nhưng kho đang khoá"
        );
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
