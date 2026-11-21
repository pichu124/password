// Cầu nối tới backend Rust. Chế độ `vite --mode mock` dùng dữ liệu giả để xem giao diện
// trong trình duyệt; bản build thật không chứa phần mock.
import type {
  AppError,
  BackupEntryView,
  BackupView,
  ConflictHint,
  CopyField,
  EmptyTrashView,
  EntryDetail,
  EntryInput,
  EntrySummary,
  GenRequest,
  Generated,
  GeneratedItem,
  HealthView,
  HistoryView,
  ImportView,
  MasterCheck,
  MoveView,
  PasswordChangeView,
  ReadOnlyOpen,
  RecoverInfo,
  Settings,
  Status,
  Strength,
  SyncResult,
  TotpCode,
  TrashItem,
  UnlockInfo,
  UpdateInfo,
} from "./types";

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export const IS_MOCK = import.meta.env.MODE === "mock";

let invokePromise: Promise<Invoke> | null = null;
function getInvoke(): Promise<Invoke> {
  if (!invokePromise) {
    invokePromise = IS_MOCK
      ? import("./mock").then((m) => m.mockInvoke as Invoke)
      : import("@tauri-apps/api/core").then((m) => m.invoke as Invoke);
  }
  return invokePromise;
}

// ------------------------------------------------------------------ xử lý lỗi chung

/** Mã lỗi nghĩa là phiên đã mất (kho đã bị khoá ở backend). */
const SESSION_LOST = new Set(["locked", "password_changed"]);
/** Mã lỗi nghĩa là file kho trên đĩa đang có vấn đề (backend ghi nhận vào `disk_problem`). */
const DISK_PROBLEM = new Set(["file_damaged", "file_missing", "different_vault", "unsupported_version"]);
/** Các lệnh tự xử lý lỗi của mình (màn hình khoá / mở khoá) — không kích hoạt xử lý chung. */
const OWN_HANDLING = new Set(["status", "page_loaded", "lock", "unlock", "recover_vault", "create_vault", "open_readonly", "set_vault_path", "vault_traces", "suggest_path", "restore_local_copy", "check_vault_choice", "prepare_copy_folder", "discard_copy_folder", "pick_vault_file", "set_draft", "record_generated", "check_rekey"]);

let sessionLostHandler: ((e: AppError) => void) | null = null;
let diskProblemHandler: ((e: AppError) => void) | null = null;
let writeResultHandler: ((r: SyncResult) => void) | null = null;

/** Đăng ký việc cần làm khi BẤT KỲ lệnh nào báo kho đã khoá / mật khẩu đã đổi ở máy khác. */
export function onSessionLost(h: ((e: AppError) => void) | null) {
  sessionLostHandler = h;
}
/** Đăng ký việc cần làm khi một lệnh báo file kho trên đĩa có vấn đề. */
export function onDiskProblem(h: ((e: AppError) => void) | null) {
  diskProblemHandler = h;
}
/**
 * Đăng ký việc cần làm với kết quả ghi của "lưu mục" / "xoá mục" (bản ghi bằng mật khẩu cũ vừa được
 * cất, ghi chưa kiểm tra lại được…). Các lệnh ghi khác không trả kết quả này: backend giữ lại và trả
 * về ở lần đồng bộ tới.
 */
export function onWriteResult(h: ((r: SyncResult) => void) | null) {
  writeResultHandler = h;
}
function reportWrite<T>(r: T, sync: SyncResult): T {
  writeResultHandler?.(sync);
  return r;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const invoke = await getInvoke();
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    const code = errorCode(e);
    if (!OWN_HANDLING.has(cmd)) {
      if (SESSION_LOST.has(code)) sessionLostHandler?.(asAppError(e));
      else if (DISK_PROBLEM.has(code)) diskProblemHandler?.(asAppError(e));
    }
    throw e;
  }
}

export const api = {
  status: () => call<Status>("status"),
  suggestPath: () => call<string>("suggest_path"),
  vaultTraces: (path: string) => call<string[]>("vault_traces", { path }),
  touch: () => call<void>("touch"),
  pageLoaded: () => call<void>("page_loaded"),
  createVault: (path: string, password: string) => call<void>("create_vault", { path, password }),
  unlock: (path: string, password: string) => call<UnlockInfo>("unlock", { path, password }),
  /**
   * Các lựa chọn rõ ràng của chủ kho: `allowOlder` — khôi phục từ các bản sao lưu tạo trước lần đổi mật khẩu chính gần nhất;
   * `allowStale` — chấp nhận bản dựng lại cũ hơn dữ liệu máy này từng thấy; `replaceNewer` — file kho báo "định dạng mới hơn"
   * vẫn được cất đi và thay bằng bản dựng lại.
   */
  recoverVault: (path: string, password: string, opts: { allowOlder?: boolean; allowStale?: boolean; replaceNewer?: boolean } = {}) =>
    call<RecoverInfo>("recover_vault", { path, password, allowOlder: !!opts.allowOlder, allowStale: !!opts.allowStale, replaceNewer: !!opts.replaceNewer }),
  /** Kho đang khoá, file kho không còn: ghi bản lưu riêng trên máy này ra đúng vị trí đó (không bao giờ ghi đè). */
  restoreLocalCopy: () => call<void>("restore_local_copy"),
  /** File vừa chọn có phải bản xung đột của một file kho khác cùng thư mục không. */
  checkVaultChoice: (path: string) => call<ConflictHint | null>("check_vault_choice", { path }),
  prepareCopyFolder: (day: string) => call<string>("prepare_copy_folder", { day }),
  discardCopyFolder: () => call<void>("discard_copy_folder"),
  acceptRollback: () => call<void>("accept_rollback"),
  /** `form`: bản nháp form đang giữ NGAY LÚC NÀY (`draft: null` = form sạch) — được ghi vào stash trước khi kho khoá. */
  lock: (form?: { draft: string | null }) =>
    call<void>("lock", form ? { hasDraft: true, draft: form.draft, draftSeq: nextDraftSeq() } : {}),
  setVaultPath: (path: string) => call<void>("set_vault_path", { path }),
  list: (query: string) => call<EntrySummary[]>("list_entries", { query }),
  get: (id: string) => call<EntryDetail>("get_entry", { id }),
  reveal: (id: string) => call<string>("reveal_password", { id }),
  revealNotes: (id: string) => call<string>("reveal_notes", { id }),
  revealTotpSecret: (id: string) => call<string>("reveal_totp_secret", { id }),
  history: (id: string) => call<HistoryView[]>("password_history", { id }),
  totp: (id: string) => call<TotpCode>("totp_code", { id }),
  /**
   * `updatedAt`: thời điểm sửa của mục đang hiện; `shown`: dòng đang hiện (địa chỉ của `url:<i>`, `replaced_at` của
   * `history:<i>`). Mục / dòng đã đổi ⇒ lỗi `entry_changed`.
   */
  copyField: (id: string, field: CopyField, updatedAt?: number, shown?: string) =>
    call<number>("copy_field", { id, field, updatedAt: updatedAt ?? null, shown: shown ?? null }),
  copyText: (text: string) => call<number>("copy_text", { text }),
  save: (entry: EntryInput) => call<[string, SyncResult]>("save_entry", { entry }).then((r) => reportWrite(r, r[1])),
  /** Chuyển vào thùng rác. */
  remove: (id: string) => call<SyncResult>("delete_entry", { id }).then((r) => reportWrite(r, r)),
  toggleFavorite: (id: string) => call<boolean>("toggle_favorite", { id }),
  listTrash: () => call<TrashItem[]>("list_trash"),
  restoreEntry: (id: string) => call<void>("restore_entry", { id }),
  purgeEntry: (id: string) => call<void>("purge_entry", { id }),
  /** Xoá vĩnh viễn ĐÚNG các mục `ids` (những mục người dùng đã thấy khi xác nhận). */
  emptyTrash: (ids: string[]) => call<EmptyTrashView>("empty_trash", { ids }),
  sync: () => call<SyncResult>("sync_now"),
  forceWrite: () => call<string | null>("force_write"),
  generate: (request: GenRequest) => call<Generated>("generate", { request }),
  /** Độ mạnh mật khẩu của MỘT TÀI KHOẢN (không dùng cho master password). */
  strength: (password: string) => call<Strength>("strength", { password }),
  /** Chấm master password — chỉ gọi khi rời ô nhập hoặc bấm nút, không gọi theo từng phím. */
  masterCheck: (password: string) => call<MasterCheck>("master_check", { password }),
  changeMaster: (current: string, next: string) =>
    call<PasswordChangeView>("change_master_password", { current, new: next }),
  health: (online: boolean) => call<HealthView>("health_report", { online }),
  importCsv: (path: string) => call<ImportView>("import_csv", { path }),
  deleteImportedCsv: () => call<void>("delete_imported_csv"),
  /** `copyOnly`: chỉ ghi một BẢN SAO sang chỗ mới, không đụng gì ở chỗ cũ (cứu dữ liệu khi file kho có vấn đề). */
  moveVault: (path: string, copyOnly = false) => call<MoveView>("move_vault", { path, copyOnly }),
  // Bản nháp & mật khẩu vừa tạo (giữ trong backend, đã mã hoá bằng khoá kho; giữ qua lần khoá)
  /** `seq`: số thứ tự lấy LÚC chụp bản nháp (xem nextDraftSeq) — bản đến muộn mà cũ hơn bị backend bỏ. */
  setDraft: (draft: string | null, seq: number = nextDraftSeq()) => call<void>("set_draft", { draft, draftSeq: seq }),
  getDraft: () => call<string | null>("get_draft"),
  recordGenerated: (value: string, label: string | null = null) => call<void>("record_generated", { value, label }),
  listGenerated: () => call<GeneratedItem[]>("list_generated"),
  revealGenerated: (id: string) => call<string>("reveal_generated", { id }),
  copyGenerated: (id: string) => call<number>("copy_generated", { id }),
  clearGenerated: () => call<void>("clear_generated"),
  /** Kho từng đổi mật khẩu chính bằng bản 0.1.x (khoá chưa được thay)? Quét một lần cho mỗi khoá. */
  checkRekey: () => call<boolean>("check_rekey"),
  listBackups: () => call<BackupView[]>("list_backups"),
  backupDiff: (name: string) => call<BackupEntryView[]>("backup_diff", { name }),
  restoreFromBackup: (name: string, ids: string[]) => call<number>("restore_from_backup", { name, ids }),
  getSettings: () => call<Settings>("get_settings"),
  setSettings: (settings: Settings) => call<void>("set_settings", { settings }),
  backupsDir: () => call<string | null>("backups_dir"),
  appVersion: () => call<string>("app_version"),
  // Điện thoại (chỉ đọc)
  openReadonly: (password: string) => call<ReadOnlyOpen>("open_readonly", { password }),
  reloadReadonly: () => call<boolean>("reload_readonly"),
  repickReadonly: (location: string) => call<boolean>("repick_readonly", { location }),
  /** Android: bộ chọn file kho giữ quyền đọc lâu dài. */
  pickVaultFile: () => call<{ uri?: string | null; persisted: boolean }>("pick_vault_file"),
  checkUpdate: () => call<UpdateInfo | null>("check_update"),
  /** Mở trang tải của một phiên bản (truyền số phiên bản, ví dụ `update.latest`, không phải địa chỉ). */
  openReleasePage: (version: string) => call<void>("open_release_page", { version }),
};

/** Lắng nghe sự kiện từ backend (ví dụ "vault-locked" với payload "idle" | "suspend"). */
export async function onEvent(name: string, cb: (payload: unknown) => void): Promise<() => void> {
  if (IS_MOCK) {
    const { mockListen } = await import("./mock");
    return mockListen(name, cb);
  }
  const { listen } = await import("@tauri-apps/api/event");
  return listen(name, (e) => cb(e.payload));
}

/** Hộp thoại chọn file. */
export async function pickFile(opts: {
  save?: boolean;
  title: string;
  defaultPath?: string;
  filters: { name: string; extensions: string[] }[];
}): Promise<string | null> {
  if (IS_MOCK) {
    const { mockPickFile } = await import("./mock");
    return mockPickFile(opts);
  }
  const dialog = await import("@tauri-apps/plugin-dialog");
  const r = opts.save
    ? await dialog.save({ title: opts.title, defaultPath: opts.defaultPath, filters: opts.filters })
    : await dialog.open({ title: opts.title, multiple: false, directory: false, filters: opts.filters });
  return typeof r === "string" ? r : null;
}

// ------------------------------------------------------------------ lỗi

function isAppError(e: unknown): e is AppError {
  return typeof e === "object" && e !== null && typeof (e as AppError).message === "string" && typeof (e as AppError).code === "string";
}

function asAppError(e: unknown): AppError {
  return isAppError(e) ? e : { code: "error", message: errorText(e) };
}

/** Lời nhắn hiển thị được cho người dùng, dù lỗi là chuỗi (backend cũ) hay `{ code, message }`. */
export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (isAppError(e)) return e.message;
  if (e instanceof Error) return e.message;
  if (typeof e === "object" && e !== null && typeof (e as { message?: unknown }).message === "string") return (e as { message: string }).message;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

/** Mã lỗi (`"error"` nếu lỗi không mang mã). */
export function errorCode(e: unknown): string {
  return isAppError(e) ? e.code : "error";
}

// ------------------------------------------------------------------ nạp lại trang

// Sau khi khoá, app nạp lại trang để WebView vứt bỏ toàn bộ bộ nhớ JavaScript (master password vừa
// gõ, mật khẩu vừa hiện…). Những thông tin KHÔNG bí mật cần hiện sau khi nạp lại (lý do khoá, cảnh
// báo sau khi mở khoá) được gửi qua sessionStorage của tab này rồi xoá ngay khi đọc.

const STASH_PREFIX = "pwv.after-reload.";

/** Ghi tạm một giá trị KHÔNG bí mật để đọc lại sau khi nạp lại trang. Trả về false nếu không ghi được. */
export function stashForReload(key: string, value: unknown): boolean {
  try {
    sessionStorage.setItem(STASH_PREFIX + key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

/** Đọc (và xoá) giá trị đã ghi tạm trước khi nạp lại trang. */
export function takeStashed<T>(key: string): T | null {
  try {
    const raw = sessionStorage.getItem(STASH_PREFIX + key);
    sessionStorage.removeItem(STASH_PREFIX + key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

// Đọc đúng MỘT lần khi nạp trang (main.tsx nạp cả App lẫn MobileApp; StrictMode chạy effect hai lần).
/** Lý do khoá do trang trước để lại. */
export const STASHED_LOCK_NOTE = takeStashed<string>("lock-note");
/** Kết quả mở khoá (không bí mật) do trang trước để lại. */
export const STASHED_UNLOCK_INFO = takeStashed<UnlockInfo>("unlock-info");

let reloading = false;
/** Đang nạp lại trang (để các thông báo lỗi không chen vào lúc đó). */
export const isReloading = () => reloading;

/** Nạp lại trang ngay (sau khi kho đã khoá). `note`: lý do hiện ở màn hình mở khoá. */
export function reloadPage(note?: string) {
  if (reloading) return;
  reloading = true;
  if (note) stashForReload("lock-note", note);
  window.location.reload();
}

let lastDraftSeq = 0;
/** Số thứ tự tăng dần cho các lần ghi bản nháp (cả qua các lần nạp lại trang: dựa trên đồng hồ). */
export function nextDraftSeq(): number {
  lastDraftSeq = Math.max(Date.now() * 1000, lastDraftSeq + 1);
  return lastDraftSeq;
}

let beforeLock: (() => { draft: string | null } | undefined) | null = null;
/**
 * Form đang sửa cho biết bản nháp nó giữ NGAY LÚC NÀY (undefined = không có gì để giữ, ví dụ form chưa tải xong). Khoá bằng
 * tay gửi bản đó kèm lệnh khoá — không chờ gì cả.
 */
export function onBeforeLock(h: (() => { draft: string | null } | undefined) | null) {
  beforeLock = h;
}

/** Khoá kho rồi nạp lại trang. */
export async function lockAndReload(note?: string) {
  if (reloading) return;
  let form: { draft: string | null } | undefined;
  try {
    form = beforeLock?.();
  } catch {
    form = undefined;
  }
  try {
    await api.lock(form);
  } catch {
    /* kho có thể đã khoá sẵn — vẫn nạp lại */
  }
  reloadPage(note);
}
