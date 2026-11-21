// Kiểu dữ liệu khớp với các DTO trong app/src-tauri/src/session.rs (và update.rs, crates/generator).

/** Lỗi từ backend: `code` để giao diện biết phải làm gì, `message` để hiện cho người dùng. */
export interface AppError {
  code: ErrorCode | string;
  message: string;
}

export type ErrorCode =
  | "error"
  | "locked"
  | "wrong_password"
  | "weak_password"
  | "password_changed"
  | "file_missing"
  | "file_damaged"
  | "unsupported_version"
  | "different_vault"
  | "read_only"
  | "not_found"
  | "read_failed"
  /** Khôi phục: mật khẩu vừa nhập chỉ mở được các bản sao lưu từ TRƯỚC lần đổi mật khẩu chính gần nhất. */
  | "older_password"
  /** Khôi phục: thư mục sao lưu không có bản nào dùng được. */
  | "no_backup";

export interface Strength {
  score: number;
  guesses_log10: number;
  label: string;
}

/** Kết quả chấm master password theo chính sách (crates/generator). */
export interface MasterCheck {
  ok: boolean;
  guesses_log10: number;
  message: string;
}

export interface Status {
  unlocked: boolean;
  read_only: boolean;
  vault_path: string | null;
  /** Đã từng chọn/tạo kho trên máy này (dù file hiện có thể không còn ở đó). */
  vault_configured: boolean;
  vault_exists: boolean;
  conflict_copies: number;
  memory_locked: boolean;
  entry_count: number;
  trash_count: number;
  /** Lần sửa nội dung gần nhất của kho đang mở (ms). */
  modified_at: number;
  disk_problem: AppError | null;
  lock_note: string | null;
  auto_lock_minutes: number;
}

export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  url: string | null;
  favorite: boolean;
  tags: string[];
  has_totp: boolean;
  updated_at: number;
}

export interface EntryDetail {
  id: string;
  title: string;
  username: string;
  urls: string[];
  tags: string[];
  favorite: boolean;
  has_password: boolean;
  /** Ghi chú chỉ được gửi khi người dùng bấm "hiện" (reveal_notes). */
  has_notes: boolean;
  has_totp: boolean;
  totp_label: string | null;
  /** Secret 2FA đã lưu không đọc được. */
  totp_error: string | null;
  history_count: number;
  strength: Strength;
  created_at: number;
  updated_at: number;
}

/**
 * Dữ liệu gửi khi lưu. Khi SỬA (có `id`), trường nào vắng mặt / `null` thì GIỮ NGUYÊN.
 * `totp`: vắng = giữ, `""` = xoá, còn lại = secret mới.
 */
export interface EntryInput {
  id?: string | null;
  title?: string | null;
  username?: string | null;
  password?: string | null;
  urls?: string[] | null;
  notes?: string | null;
  tags?: string[] | null;
  favorite?: boolean | null;
  totp?: string | null;
}

export type CopyField = "password" | "username" | "totp" | "url" | "notes" | `url:${number}` | `history:${number}`;

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
  require_each: boolean;
}

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  add_number: boolean;
}

export type GenRequest =
  | ({ mode: "password" } & PasswordOptions)
  | ({ mode: "passphrase" } & PassphraseOptions);

export interface Generated {
  value: string;
  entropy_bits: number;
  strength: Strength;
}

export interface TotpCode {
  code: string;
  remaining: number;
  period: number;
}

export interface HistoryView {
  password: string;
  replaced_at: number;
}

export interface SyncResult {
  changed: boolean;
  added: number;
  updated: number;
  deleted: number;
  conflicts_merged: number;
  /** Bản xung đột không gộp được — mỗi dòng ổn định (không đổi giữa các lần đồng bộ). */
  errors: string[];
  password_changed_elsewhere: boolean;
  /** App vừa ghi lại file kho. */
  wrote: boolean;
  backup_failed: boolean;
  /** Số bản của kho ghi bằng mật khẩu chính CŨ: không được gộp, đã cất vào thư mục sao lưu (loại "oldkey"). */
  old_key_archived: number;
  /** Đã ghi file kho nhưng chưa đọc lại kiểm tra được (lần đồng bộ sau kiểm tra lại). */
  unverified: boolean;
  /** File kho trên đĩa đang có vấn đề. */
  problem: AppError | null;
}

/** File kho vừa mở cũ hơn bản mà máy này từng thấy. */
export interface RollbackView {
  seen_modified_at: number;
  file_modified_at: number;
  older_password: boolean;
  /** Kho vừa mở KHÔNG nối tiếp từ kho máy này dùng lần trước (mật khẩu chính cũ, hoặc file bị thay). */
  unknown_key: boolean;
}

export interface UnlockInfo {
  rollback: RollbackView | null;
  /** Số bản cứu hộ vừa được gộp lại vào kho. */
  rescued: number;
  /** Số bản cứu hộ chưa gộp được — vẫn được giữ lại, lần mở khoá sau thử lại. */
  rescue_kept: number;
  sync: SyncResult;
}

export interface RecoverInfo {
  entries: number;
  files_used: number;
  newest_backup_at: number;
  /** Nơi file hỏng được cất. */
  archived: string | null;
  /** Số bản cứu hộ chưa gộp được (vẫn được giữ lại). */
  rescue_kept: number;
}

export interface HealthItem {
  id: string;
  title: string;
  username: string;
  severity: number;
  issues: string[];
}

export interface HealthView {
  score: number;
  checked: number;
  breached: number;
  reused: number;
  weak: number;
  old: number;
  breach_check_done: boolean;
  breach_error: string | null;
  items: HealthItem[];
}

export interface ImportView {
  imported: number;
  duplicates: number;
  skipped: number;
  /** Tiêu đề các mục đã nhập nhưng có vẻ trùng với mục khác. */
  similar: string[];
  /** Tiêu đề các mục có mã 2FA không đọc được (giá trị gốc nằm trong ghi chú). */
  bad_totp: string[];
  detected: string;
}

export interface MoveView {
  new_path: string;
  backups_moved: boolean;
  old_removed: boolean;
  conflicts_merged: number;
  /** Chỉ ghi một BẢN SAO sang chỗ mới; mọi thứ ở chỗ cũ được giữ nguyên. */
  rescued: boolean;
}

export interface PasswordChangeView {
  backups_reencrypted: number;
  /** Bản sao lưu để nguyên: không đọc được, hoặc chỉ mở được bằng một mật khẩu chính cũ hơn nữa. */
  backups_skipped: number;
  /** Mật khẩu ĐÃ đổi, nhưng chưa đọc lại kiểm tra được file vừa ghi. */
  unverified: boolean;
}

/** Kết quả "dọn sạch thùng rác". */
export interface EmptyTrashView {
  /** Số mục đã xoá vĩnh viễn (trong số các mục đã thấy khi xác nhận). */
  purged: number;
  /** Số mục còn lại trong thùng rác (ví dụ máy khác vừa chuyển thêm vào). */
  remaining: number;
}

export interface TrashItem {
  id: string;
  title: string;
  username: string;
  deleted_at: number;
}

export type BackupKind = "auto" | "merged" | "damaged" | "oldkey";

export interface BackupView {
  /** Tên file trong thư mục sao lưu (dùng làm khoá khi gọi lại). */
  name: string;
  kind: BackupKind;
  timestamp: number;
  /** Số mục trong bản sao lưu (null = không đọc được). */
  entries: number | null;
  /** Bản này chỉ mở được bằng một mật khẩu chính CŨ (có thể không phải do chủ kho ghi). */
  retired_key: boolean;
}

export type BackupEntryStatus = "changed" | "in_trash" | "missing";

export interface BackupEntryView {
  id: string;
  title: string;
  username: string;
  status: BackupEntryStatus;
  /** Tên các trường khác với bản hiện tại (không kèm giá trị). */
  changed_fields: string[];
  updated_at: number;
}

export interface Settings {
  auto_lock_minutes: number;
  clipboard_clear_secs: number;
  check_updates: boolean;
}

export interface UpdateInfo {
  current: string;
  latest: string;
  available: boolean;
  page_url: string;
  notes: string;
  published_at: string;
}

/** Kết quả mở kho chỉ đọc trên điện thoại. */
export interface ReadOnlyOpen {
  from_cache: boolean;
  note: string | null;
}
