// Cầu nối tới backend Rust. Chế độ `vite --mode mock` dùng dữ liệu giả để xem giao diện
// trong trình duyệt; bản build thật không chứa phần mock.
import type {
  EntryDetail,
  EntryInput,
  EntrySummary,
  GenRequest,
  Generated,
  HealthView,
  HistoryView,
  ImportView,
  MoveView,
  Settings,
  Status,
  Strength,
  SyncResult,
  TotpCode,
  UpdateInfo,
} from "./types";

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

const IS_MOCK = import.meta.env.MODE === "mock";

let invokePromise: Promise<Invoke> | null = null;
function getInvoke(): Promise<Invoke> {
  if (!invokePromise) {
    invokePromise = IS_MOCK
      ? import("./mock").then((m) => m.mockInvoke as Invoke)
      : import("@tauri-apps/api/core").then((m) => m.invoke as Invoke);
  }
  return invokePromise;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const invoke = await getInvoke();
  return invoke<T>(cmd, args);
}

export const api = {
  status: () => call<Status>("status"),
  touch: () => call<void>("touch"),
  createVault: (path: string, password: string) => call<void>("create_vault", { path, password }),
  unlock: (path: string, password: string) => call<void>("unlock", { path, password }),
  lock: () => call<void>("lock"),
  setVaultPath: (path: string) => call<void>("set_vault_path", { path }),
  list: (query: string) => call<EntrySummary[]>("list_entries", { query }),
  get: (id: string) => call<EntryDetail>("get_entry", { id }),
  reveal: (id: string) => call<string>("reveal_password", { id }),
  history: (id: string) => call<HistoryView[]>("password_history", { id }),
  totp: (id: string) => call<TotpCode>("totp_code", { id }),
  copyField: (id: string, field: "password" | "username" | "totp" | "url") =>
    call<number>("copy_field", { id, field }),
  copyText: (text: string) => call<number>("copy_text", { text }),
  save: (entry: EntryInput) => call<[string, SyncResult]>("save_entry", { entry }),
  remove: (id: string) => call<SyncResult>("delete_entry", { id }),
  toggleFavorite: (id: string) => call<void>("toggle_favorite", { id }),
  sync: () => call<SyncResult>("sync_now"),
  generate: (request: GenRequest) => call<Generated>("generate", { request }),
  strength: (password: string) => call<Strength>("strength", { password }),
  changeMaster: (current: string, next: string) =>
    call<void>("change_master_password", { current, new: next }),
  health: (online: boolean) => call<HealthView>("health_report", { online }),
  importCsv: (path: string, deleteAfter: boolean) =>
    call<ImportView>("import_csv", { path, deleteAfter }),
  moveVault: (path: string) => call<MoveView>("move_vault", { path }),
  getSettings: () => call<Settings>("get_settings"),
  setSettings: (settings: Settings) => call<void>("set_settings", { settings }),
  backupsDir: () => call<string | null>("backups_dir"),
  appVersion: () => call<string>("app_version"),
  checkUpdate: () => call<UpdateInfo | null>("check_update"),
  openReleasePage: (url: string) => call<void>("open_release_page", { url }),
};

/** Lắng nghe sự kiện từ backend (ví dụ "vault-locked"). */
export async function onEvent(name: string, cb: () => void): Promise<() => void> {
  if (IS_MOCK) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen(name, cb);
}

/** Hộp thoại chọn file. */
export async function pickFile(opts: {
  save?: boolean;
  title: string;
  defaultPath?: string;
  filters: { name: string; extensions: string[] }[];
}): Promise<string | null> {
  if (IS_MOCK) return opts.save ? opts.defaultPath ?? "C:\\vault.pwv" : "C:\\Users\\toi\\Downloads\\chrome.csv";
  const dialog = await import("@tauri-apps/plugin-dialog");
  const r = opts.save
    ? await dialog.save({ title: opts.title, defaultPath: opts.defaultPath, filters: opts.filters })
    : await dialog.open({ title: opts.title, multiple: false, directory: false, filters: opts.filters });
  return typeof r === "string" ? r : null;
}

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}
