//! Lớp Tauri: chuyển lời gọi từ giao diện vào `Session`.

mod session;
mod update;

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use session::*;
use tauri::{Emitter, Manager, State};
use zeroize::Zeroizing;

type AppState = Mutex<Session>;

fn with<T>(state: &State<AppState>, f: impl FnOnce(&mut Session) -> AppResult<T>) -> AppResult<T> {
    let mut s = state.lock().map_err(|_| "Lỗi nội bộ (mutex)".to_string())?;
    f(&mut s)
}

// ----------------------------------------------------------------------------- lệnh

#[tauri::command]
fn status(state: State<AppState>) -> AppResult<Status> {
    with(&state, |s| Ok(s.status()))
}

#[tauri::command]
fn touch(state: State<AppState>) -> AppResult<()> {
    with(&state, |s| {
        s.touch();
        Ok(())
    })
}

/// Argon2id 256 MiB mất ~1 giây ⇒ chạy ở luồng nền để giao diện không bị treo.
#[tauri::command]
async fn create_vault(app: tauri::AppHandle, path: String, password: String) -> AppResult<()> {
    let password = Zeroizing::new(password);
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let mut s = state.lock().map_err(|_| "mutex".to_string())?;
        s.create_vault(&PathBuf::from(path), &password)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn unlock(app: tauri::AppHandle, path: String, password: String) -> AppResult<()> {
    let password = Zeroizing::new(password);
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let mut s = state.lock().map_err(|_| "mutex".to_string())?;
        s.unlock(&PathBuf::from(path), &password)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn lock(state: State<AppState>) -> AppResult<()> {
    with(&state, |s| {
        s.lock();
        Ok(())
    })
}

#[tauri::command]
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
fn password_history(state: State<AppState>, id: String) -> AppResult<Vec<HistoryView>> {
    with(&state, |s| s.history(&id))
}

#[tauri::command]
fn totp_code(state: State<AppState>, id: String) -> AppResult<TotpCode> {
    with(&state, |s| s.totp(&id))
}

/// Sao chép trực tiếp từ Rust vào clipboard: mật khẩu không đi qua JavaScript.
#[tauri::command]
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

/// Sao chép một giá trị vừa tạo (bộ tạo mật khẩu).
#[tauri::command]
fn copy_text(app: tauri::AppHandle, state: State<AppState>, text: String) -> AppResult<u32> {
    let secs = with(&state, |s| Ok(s.config.clipboard_clear_secs))?;
    copy_with_auto_clear(&app, Zeroizing::new(text), secs)?;
    Ok(secs)
}

#[tauri::command]
fn save_entry(state: State<AppState>, entry: EntryInput) -> AppResult<(String, SyncResult)> {
    with(&state, |s| s.save_entry(entry))
}

#[tauri::command]
fn delete_entry(state: State<AppState>, id: String) -> AppResult<SyncResult> {
    with(&state, |s| s.delete_entry(&id))
}

#[tauri::command]
fn toggle_favorite(state: State<AppState>, id: String) -> AppResult<()> {
    with(&state, |s| s.toggle_favorite(&id))
}

#[tauri::command]
fn sync_now(state: State<AppState>) -> AppResult<SyncResult> {
    with(&state, |s| s.sync())
}

#[tauri::command]
fn generate(request: GenRequest) -> AppResult<Generated> {
    session::generate(request)
}

#[tauri::command]
fn strength(password: String) -> pwv_generator::Strength {
    let password = Zeroizing::new(password);
    pwv_generator::estimate_strength(&password, &[])
}

#[tauri::command]
async fn change_master_password(
    app: tauri::AppHandle,
    current: String,
    new: String,
) -> AppResult<()> {
    let (current, new) = (Zeroizing::new(current), Zeroizing::new(new));
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let mut s = state.lock().map_err(|_| "mutex".to_string())?;
        s.change_master_password(&current, &new)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Kiểm tra rò rỉ cần mạng ⇒ chạy nền.
#[tauri::command]
async fn health_report(app: tauri::AppHandle, online: bool) -> AppResult<HealthView> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let s = state.lock().map_err(|_| "mutex".to_string())?;
        s.health(online)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn import_csv(state: State<AppState>, path: String, delete_after: bool) -> AppResult<ImportView> {
    with(&state, |s| s.import_csv(&PathBuf::from(path), delete_after))
}

#[tauri::command]
fn move_vault(state: State<AppState>, path: String) -> AppResult<MoveView> {
    with(&state, |s| s.move_vault(&PathBuf::from(path)))
}

#[tauri::command]
fn app_version() -> &'static str {
    update::CURRENT_VERSION
}

/// Kiểm tra bản mới (cần mạng ⇒ chạy nền). Trả về None nếu chưa có bản phát hành nào.
#[tauri::command]
async fn check_update() -> AppResult<Option<update::UpdateInfo>> {
    tauri::async_runtime::spawn_blocking(update::check)
        .await
        .map_err(|e| e.to_string())?
}

/// Mở trang tải bản mới trong trình duyệt. Chỉ cho phép link release của repo pwv.
#[tauri::command]
fn open_release_page(app: tauri::AppHandle, url: String) -> AppResult<()> {
    use tauri_plugin_opener::OpenerExt;
    if !url.starts_with(update::RELEASES_PAGE_PREFIX) {
        return Err("Link không hợp lệ".into());
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_settings(state: State<AppState>) -> AppResult<Settings> {
    with(&state, |s| Ok(s.settings()))
}

#[tauri::command]
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
    /// Không đọc được file mới (quyền truy cập đã hết hạn hoặc mất mạng) ⇒ đang dùng bản lưu trên máy.
    from_cache: bool,
    note: Option<String>,
}

/// Đọc file kho: đường dẫn thường hoặc URI `content://` (Drive/Dropbox/OneDrive trên Android).
fn read_location(app: &tauri::AppHandle, location: &str) -> Result<Vec<u8>, String> {
    use tauri_plugin_fs::FsExt;
    let fp: tauri_plugin_fs::FilePath = location
        .parse()
        .map_err(|_| "Đường dẫn kho không hợp lệ".to_string())?;
    app.fs()
        .read(fp)
        .map_err(|e| format!("Không đọc được file kho: {e}"))
}

/// Bản sao file kho (vẫn đã mã hoá) trong bộ nhớ riêng của app — để mở được khi offline
/// hoặc khi Android thu hồi quyền đọc file sau khi tắt app.
fn cache_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path()
        .app_data_dir()
        .ok()
        .map(|d| d.join("vault-cache.pwv"))
}

fn write_cache(app: &tauri::AppHandle, bytes: &[u8]) {
    if let Some(p) = cache_path(app) {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(p, bytes);
    }
}

fn vault_location(app: &tauri::AppHandle) -> AppResult<String> {
    let state = app.state::<AppState>();
    let s = state.lock().map_err(|_| "mutex".to_string())?;
    Ok(s.config
        .vault
        .clone()
        .ok_or("Chưa chọn file kho")?
        .to_string_lossy()
        .to_string())
}

#[tauri::command]
async fn open_readonly(app: tauri::AppHandle, password: String) -> AppResult<ReadOnlyOpen> {
    let password = Zeroizing::new(password);
    tauri::async_runtime::spawn_blocking(move || {
        let location = vault_location(&app)?;
        let (bytes, from_cache, note) = match read_location(&app, &location) {
            Ok(b) => (b, false, None),
            Err(e) => match cache_path(&app).and_then(|p| std::fs::read(p).ok()) {
                Some(b) => (b, true, Some(e)),
                None => return Err(format!("{e}. Hãy chọn lại file kho.")),
            },
        };
        let state = app.state::<AppState>();
        let mut s = state.lock().map_err(|_| "mutex".to_string())?;
        s.unlock_bytes(&location, &bytes, &password)?;
        drop(s);
        if !from_cache {
            write_cache(&app, &bytes);
        }
        Ok(ReadOnlyOpen { from_cache, note })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Đọc lại file kho từ Drive/Dropbox/OneDrive. Trả về true nếu có dữ liệu mới.
#[tauri::command]
async fn reload_readonly(app: tauri::AppHandle) -> AppResult<bool> {
    tauri::async_runtime::spawn_blocking(move || {
        let location = vault_location(&app)?;
        let bytes = read_location(&app, &location)
            .map_err(|e| format!("{e}. Hãy bấm “Chọn lại file” để cấp quyền đọc lần nữa."))?;
        let state = app.state::<AppState>();
        let changed = state
            .lock()
            .map_err(|_| "mutex".to_string())?
            .reload_bytes(&bytes)?;
        write_cache(&app, &bytes);
        Ok(changed)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Chọn lại file (cấp lại quyền đọc trên Android) rồi tải bản mới — không cần nhập lại mật khẩu
/// nếu vẫn là cùng một kho.
#[tauri::command]
async fn repick_readonly(app: tauri::AppHandle, location: String) -> AppResult<bool> {
    tauri::async_runtime::spawn_blocking(move || {
        let bytes = read_location(&app, &location)?;
        let state = app.state::<AppState>();
        let mut s = state.lock().map_err(|_| "mutex".to_string())?;
        let changed = s.reload_bytes(&bytes)?;
        s.set_vault_location_keep_open(&location)?;
        drop(s);
        write_cache(&app, &bytes);
        Ok(changed)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ----------------------------------------------------------------------------- clipboard

#[cfg(mobile)]
fn copy_with_auto_clear(
    app: &tauri::AppHandle,
    value: Zeroizing<String>,
    secs: u32,
) -> AppResult<()> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard()
        .write_text(value.to_string())
        .map_err(|e| format!("Không chép được vào clipboard: {e}"))?;
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(u64::from(secs)));
        let still_ours = app
            .clipboard()
            .read_text()
            .map(|t| *t == **value)
            .unwrap_or(true);
        if still_ours {
            let _ = app.clipboard().write_text(String::new());
        }
    });
    Ok(())
}

#[cfg(desktop)]
fn copy_with_auto_clear(
    _app: &tauri::AppHandle,
    value: Zeroizing<String>,
    secs: u32,
) -> AppResult<()> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("Không mở được clipboard: {e}"))?;
    set_clipboard(&mut cb, &value)?;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(u64::from(secs)));
        // Chỉ xoá nếu clipboard vẫn còn đúng giá trị của ta.
        if cb.get_text().map(|t| *t == **value).unwrap_or(true) {
            let _ = cb.clear();
        }
    });
    Ok(())
}

#[cfg(all(desktop, windows))]
fn set_clipboard(cb: &mut arboard::Clipboard, value: &str) -> AppResult<()> {
    use arboard::SetExtWindows;
    // Không vào lịch sử clipboard (Win+V), không đồng bộ lên cloud clipboard.
    cb.set()
        .exclude_from_history()
        .exclude_from_cloud()
        .text(value)
        .map_err(|e| e.to_string())
}

#[cfg(all(desktop, not(windows)))]
fn set_clipboard(cb: &mut arboard::Clipboard, value: &str) -> AppResult<()> {
    cb.set_text(value).map_err(|e| e.to_string())
}

// ----------------------------------------------------------------------------- khởi động

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    // Chỉ cho chạy 1 cửa sổ app: tránh 2 tiến trình cùng ghi một file kho.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
    }));
    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .manage::<AppState>(Mutex::new(Session::default()))
        .setup(|app| {
            // Điện thoại không có %APPDATA%: lưu cấu hình trong thư mục riêng của app.
            #[cfg(mobile)]
            {
                if let Ok(dir) = app.path().app_config_dir() {
                    pwv_vault_core::Config::set_dir(dir);
                    if let Ok(mut s) = app.state::<AppState>().lock() {
                        s.config = pwv_vault_core::Config::load();
                    }
                }
            }
            // Luồng tự khoá: chạy độc lập với giao diện, nên vẫn khoá kể cả khi JS bị treo.
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                let state = handle.state::<AppState>();
                let locked = match state.lock() {
                    Ok(mut s) => s.auto_lock_if_idle(),
                    Err(_) => false,
                };
                if locked {
                    let _ = handle.emit("vault-locked", "idle");
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Đóng cửa sổ ⇒ xoá khoá khỏi RAM ngay.
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                if let Ok(mut s) = window.state::<AppState>().lock() {
                    s.lock();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            touch,
            create_vault,
            unlock,
            lock,
            set_vault_path,
            list_entries,
            get_entry,
            reveal_password,
            password_history,
            totp_code,
            copy_field,
            copy_text,
            save_entry,
            delete_entry,
            toggle_favorite,
            sync_now,
            generate,
            strength,
            change_master_password,
            health_report,
            import_csv,
            move_vault,
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
        .run(tauri::generate_context!())
        .expect("không khởi động được ứng dụng");
}
