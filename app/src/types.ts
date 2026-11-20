// Kiểu dữ liệu khớp với các DTO trong app/src-tauri/src/session.rs

export interface Strength {
  score: number;
  guesses_log10: number;
  label: string;
}

export interface Status {
  unlocked: boolean;
  vault_path: string | null;
  vault_exists: boolean;
  suggested_path: string;
  conflict_copies: number;
  memory_locked: boolean;
  entry_count: number;
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
  notes: string;
  tags: string[];
  favorite: boolean;
  has_password: boolean;
  has_totp: boolean;
  totp_label: string | null;
  history_count: number;
  strength: Strength;
  created_at: number;
  updated_at: number;
}

export interface EntryInput {
  id: string | null;
  title: string;
  username: string;
  password: string | null;
  urls: string[];
  notes: string;
  tags: string[];
  favorite: boolean;
  totp: string | null;
}

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
  errors: string[];
  password_changed_elsewhere: boolean;
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
  detected: string;
  csv_deleted: boolean;
}

export interface MoveView {
  new_path: string;
  backups_moved: boolean;
  old_removed: boolean;
  conflicts_merged: number;
}

export interface Settings {
  auto_lock_minutes: number;
  clipboard_clear_secs: number;
}
