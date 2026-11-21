// Backend giả — CHỈ dùng khi chạy `vite --mode mock` để xem giao diện trong trình duyệt.
//
// Các tình huống được bật bằng tham số trên địa chỉ (có thể ghép nhiều cái bằng &):
//   ?setup                  chưa có kho nào trên máy (màn hình chào mừng)
//   ?missing                đã cấu hình kho nhưng không thấy file (chưa đồng bộ xong / bị chuyển đi)
//   ?unlocked               mở sẵn kho (máy tính)
//   ?mobile                 giao diện điện thoại
//   ?note=…                 lý do khoá hiện ở màn hình mở khoá (status.lock_note)
//   ?damaged                mở khoá báo file hỏng (khôi phục được từ bản sao lưu)
//   ?oldformat              mở khoá báo định dạng mới hơn bản app
//   ?rollback | ?rollback=pw | ?rollback=key   sau khi mở khoá: file kho cũ hơn bản từng thấy (=pw: kèm mật khẩu
//                           cũ; =key: kho KHÔNG nối tiếp từ kho máy này dùng lần trước — RollbackView.unknown_key)
//   ?rescued                sau khi mở khoá: đã gộp lại thay đổi chưa lưu của phiên trước
//   ?rescuekept             sau khi mở khoá: 1 bản cứu hộ chưa gộp được, vẫn được giữ lại (UnlockInfo.rescue_kept)
//   ?oldkey                 lần đồng bộ đầu tiên (kể cả lúc mở khoá): đã cất 1 bản ghi bằng mật khẩu chính cũ
//                           (SyncResult.old_key_archived + một dòng trong errors); danh sách sao lưu có thêm bản "oldkey"
//   ?oldbackup              danh sách sao lưu có một bản tự động chỉ mở được bằng mật khẩu cũ (retired_key) và một bản "oldkey"
//   ?unverified             lần lưu / xoá mục đầu tiên: đã ghi nhưng chưa kiểm tra lại được (SyncResult.unverified);
//                           đổi mật khẩu chính cũng trả unverified = true
//   ?recover=older          khôi phục từ sao lưu: lỗi older_password, trừ khi gọi lại với allowOlder = true
//   ?recover=nobackup       khôi phục từ sao lưu: lỗi no_backup
//   ?recover=prechange      khôi phục từ sao lưu: lỗi old_backups_only, trừ khi gọi lại với allowOlder = true
//   ?imported               mật khẩu cũ thứ hai của Gmail mang thời điểm 1 ms (giá trị nhập từ CSV) ⇒ phải hiện "—"
//   ?trashrace              "dọn sạch thùng rác": trong lúc xác nhận, "máy khác" chuyển thêm một mục vào thùng rác
//                           (mục đó không bị xoá ⇒ remaining = 1)
//   ?problem=file_damaged|file_missing|different_vault|unsupported_version   vấn đề với file trên đĩa
//   ?syncerr                đồng bộ trả về lỗi bản xung đột (lặp lại mỗi lần)
//   ?backupfail             đồng bộ báo không tạo được bản sao lưu
//   ?autolock0              tự khoá đang tắt
//   ?traces                 thư mục định tạo kho mới đã có dấu vết kho cũ
//   ?breacherr              kiểm tra rò rỉ qua mạng thất bại
//   ?syncreject=locked|password_changed|error   đồng bộ nền bị từ chối
//   --- fix2 ---
//   ?draft | ?draft=edit | ?draft=changed | ?draft=gone   có sẵn một bản nháp (form đang sửa dở) trong "backend": mục mới /
//                           sửa Gmail / sửa Gmail nhưng mục đã đổi kể từ lúc bắt đầu sửa / sửa một mục không còn trong kho.
//                           Bản nháp + mật khẩu vừa tạo được giữ trong sessionStorage (giả lập backend giữ qua lần khoá)
//   ?generated              có sẵn vài "mật khẩu vừa tạo gần đây"
//   ?localrestored          sau khi mở khoá: đã gộp lại từ bản lưu riêng trên máy (UnlockInfo.local_restored)
//   ?oldversion             sau khi mở khoá: file vừa được máy chạy 0.1.x ghi lại (UnlockInfo.old_version_wrote)
//   ?rekey                  kho từng đổi mật khẩu chính bằng 0.1.x (check_rekey = true) cho tới khi đổi mật khẩu chính
//   ?localcopy              (kèm ?missing) máy này còn bản lưu riêng: NotFoundScreen hiện nút "Tạo lại file kho từ bản lưu riêng"
//   ?recover=stale          khôi phục: lỗi older_than_seen (kèm hai mốc), trừ khi gọi lại với allowStale = true
//   ?recover=local          khôi phục: không còn bản sao lưu ⇒ dựng lại từ bản lưu riêng (RecoverInfo.from_local_copy)
//   ?conflictpick           hộp chọn file trả về "vault (1).pwv" — check_vault_choice báo là bản xung đột của vault.pwv
//   ?movefail               chuyển / lưu sang chỗ khác: lỗi move_failed (không phải vấn đề của file kho)
//   ?pwfailed               đổi mật khẩu chính: 2 bản sao lưu chưa mã hoá lại được (backups_failed)
//   ?entrychanged           lần sao chép đầu tiên: mục vừa thay đổi (entry_changed) — giao diện tải lại mục
//   ?oldformat              (đã có) — khôi phục với replaceNewer = true thì được
//   ?samefolder             hộp "lưu file" trả về một file trong CHÍNH thư mục của file kho (lưu sang chỗ khác phải từ chối)
//   ?oldlocal               sau khi mở khoá / khôi phục: 1 bản lưu riêng ghi bằng mật khẩu cũ đã được cất (old_local_archived)
//   (đổi mật khẩu chính: nhập lại đúng mật khẩu đang dùng — kho giả dùng mật khẩu không đạt chính sách — ⇒ được, kèm policy_warning)
//   ?badheader              mở khoá luôn báo sai mật khẩu (header hỏng), nhưng khôi phục từ sao lưu bằng mật khẩu đúng thì được
//   Điện thoại: ?readfail (mở khoá: không đọc được file), ?cache (dùng bản đã lưu),
//               ?pwchanged (mật khẩu chính đã đổi trên máy tính),
//               ?reloadfail=read_failed|password_changed|error (nút ⟳)
// Mật khẩu chính của kho giả: demo-demo-demo-demo
//
// Gọi từ console: pwvMock.emit("vault-locked", "idle") — giả lập backend tự khoá.
import type { AppError, BackupEntryView, BackupView, EntryDetail, EntryInput, GenRequest, Settings, SyncResult } from "./types";

const MASTER = "demo-demo-demo-demo";
const params = new URLSearchParams(location.search);
const flag = (k: string) => params.has(k);
const IS_PHONE = flag("mobile") || /Android|iPhone|iPad/i.test(navigator.userAgent);

interface MockEntry {
  id: string;
  title: string;
  username: string;
  password: string;
  urls: string[];
  tags: string[];
  favorite: boolean;
  totp: string | null;
  notes: string;
  history: { password: string; replaced_at: number }[];
  created_at: number;
  updated_at: number;
  trashed_at: number | null;
}

const now = Date.now();
/** Mã mục đã dùng (xem mockId). */
const usedIds = new Set<string>();
const day = 86_400_000;
let unlocked = flag("unlocked") && !IS_PHONE;
let vaultConfigured = !flag("setup");
let vaultExists = !flag("setup") && !flag("missing");
let vaultPath = vaultConfigured ? "G:\\My Drive\\Passwords\\vault.pwv" : null;
let lockNote: string | null = params.get("note");
let diskProblem: AppError | null = problemFromParam(params.get("problem"));
let settings: Settings = { auto_lock_minutes: flag("autolock0") ? 0 : 5, clipboard_clear_secs: 20, check_updates: true };
let modifiedAt = now - 2 * 3_600_000;
let backupFailOnce = flag("backupfail");
let oldKeyOnce = flag("oldkey") && params.get("oldkey") !== "done";
let unverifiedOnce = flag("unverified");
let rekeyAdvised = flag("rekey");
let entryChangedOnce = flag("entrychanged");
const OLDKEY_ERROR = "vault (1).pwv: bản này được ghi bằng mật khẩu chính CŨ nên không được tự gộp — đã cất vào thư mục sao lưu để bạn xem lại";
/** Kết quả đồng bộ, kèm "bản ghi bằng mật khẩu cũ" ở lần đầu nếu có ?oldkey. */
function syncResult(): SyncResult {
  const r = noSync();
  r.problem = diskProblem;
  if (flag("syncerr")) r.errors = ["vault (conflicted copy 2026-11-19).pwv: sai mật khẩu chính hoặc file đã bị sửa đổi"];
  if (oldKeyOnce) {
    // Backend thật báo mỗi lần cất đúng một lần; ghi lên địa chỉ để lần nạp lại trang sau mở khoá không báo lại.
    oldKeyOnce = false;
    setUrlFlag("oldkey", true, "done");
    r.old_key_archived = 1;
    r.errors.push(OLDKEY_ERROR);
    r.wrote = true;
  }
  return r;
}
/** Kết quả ghi của lưu / xoá mục, kèm "chưa kiểm tra lại được" ở lần đầu nếu có ?unverified. */
function writeResult(): SyncResult {
  const r = noSync();
  if (unverifiedOnce) {
    unverifiedOnce = false;
    r.unverified = true;
  }
  return r;
}
let lastImport: string | null = null;

function problemFromParam(p: string | null): AppError | null {
  switch (p) {
    case "file_damaged":
      return { code: "file_damaged", message: "File kho trên đĩa bị hỏng hoặc chưa tải xong (không đọc được phần dữ liệu)" };
    case "file_missing":
      return { code: "file_missing", message: "Không tìm thấy file kho: G:\\My Drive\\Passwords\\vault.pwv" };
    case "different_vault":
      return { code: "different_vault", message: "File ở vị trí kho giờ là một kho KHÁC (khác mã kho) — app không ghi đè lên nó" };
    case "unsupported_version":
      return { code: "unsupported_version", message: "File kho được ghi bởi phiên bản app mới hơn (định dạng 3) — hãy cập nhật app" };
  }
  return null;
}

const entries: MockEntry[] = [
  mk("Vietcombank", "nguyenvana", "Qx7#mP2!vL9@wR4$", ["https://vcbdigibank.vietcombank.com.vn"], ["Ngân hàng"], true, null, 30),
  mk("Gmail", "toi@gmail.com", "Lettuce-Marbled1-Posting-Raffle", ["https://mail.google.com"], ["Email"], true, "otpauth://totp/Google:toi@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google", 10),
  mk("Facebook", "toi@gmail.com", "Abc@2020", ["https://facebook.com"], ["Mạng xã hội"], false, null, 500),
  mk("Shopee", "toi@gmail.com", "Abc@2020", ["https://shopee.vn"], ["Mua sắm"], false, null, 200),
  mk("Binance", "toi@gmail.com", "k9$Vb2#Lq8!mZ3@xT7", ["https://binance.com"], ["Crypto"], false, "JBSWY3DPEHPK3PXP", 5),
  mk("Zalo", "0901234567", "zalo-mat-khau-dai-123", ["https://chat.zalo.me"], [], false, "khong-phai-base32!", 60),
  mk("Wi-Fi nhà", "", "123456", [], [], false, null, 900),
];
const trashed = mk("Tiki (cũ)", "toi@gmail.com", "tiki-old-pass", ["https://tiki.vn"], ["Mua sắm"], false, null, 400);
trashed.trashed_at = now - 3 * day;
entries.push(trashed);
const trashed2 = mk("Lazada", "toi@yahoo.com", "lzd-2019", [], [], false, null, 800);
trashed2.trashed_at = now - 12 * day;
entries.push(trashed2);

/** Mã mục suy ra từ tiêu đề (ổn định qua các lần nạp lại trang, để bản nháp của một mục có sẵn khôi phục đúng vào mục đó). */
function mockId(title: string): string {
  const base = "m-" + (title.normalize("NFD").replace(/[^\w]+/g, "-").toLowerCase() || "muc");
  let id = base;
  for (let n = 2; usedIds.has(id); n++) id = `${base}-${n}`;
  usedIds.add(id);
  return id;
}

function mk(title: string, username: string, password: string, urls: string[], tags: string[], favorite: boolean, totp: string | null, ageDays: number): MockEntry {
  return {
    id: mockId(title), title, username, password, urls, tags, favorite, totp,
    notes: title === "Vietcombank" ? "Số tài khoản: 0123456789\nCâu hỏi bảo mật: tên trường cấp 1 → Lê Lợi" : title === "Zalo" ? "otpauth gốc: khong-phai-base32!" : "",
    history: title === "Gmail" ? [{ password: "old-gmail-pass", replaced_at: now - 40 * day }, { password: "older-gmail-2019", replaced_at: flag("imported") ? 1 : now - 400 * day }] : [],
    created_at: now - ageDays * day, updated_at: now - ageDays * day, trashed_at: null,
  };
}

const live = () => entries.filter((e) => e.trashed_at === null);

// ------------------------------------------------------------------ bản nháp & mật khẩu vừa tạo (giả lập backend)

interface MockStash {
  draft: string | null;
  /** Số thứ tự của bản nháp mới nhất đã ghi. */
  seq?: number;
  generated: { id: string; value: string; at: number; label: string | null }[];
}
const STASH_KEY = "pwv.mock.stash";
function loadStash(): MockStash {
  try {
    return JSON.parse(sessionStorage.getItem(STASH_KEY) ?? "") as MockStash;
  } catch {
    return { draft: null, generated: [] };
  }
}
/** Như backend: lưu mục thành công ⇒ bản nháp bị xoá trong CÙNG lệnh. */
function clearMockDraft() {
  const st = loadStash();
  st.draft = null;
  saveStash(st);
}
function saveStash(st: MockStash) {
  st.generated = st.generated.filter((g) => g.at > Date.now() - 30 * day).sort((a, b) => b.at - a.at).slice(0, 20);
  sessionStorage.setItem(STASH_KEY, JSON.stringify(st));
}
{
  const d = params.get("draft");
  if (d !== null) {
    const g = entries.find((e) => e.title === "Gmail")!;
    const base = { title: g.title, username: g.username, urls: g.urls.join("\n"), tags: g.tags.join(", "), notes: g.notes, favorite: g.favorite };
    const draft =
      d === ""
        ? { v: 1, id: null, updated_at: null, base: { title: "", username: "", urls: "", tags: "", notes: "", favorite: false }, cur: { title: "Techcombank", username: "0912345678", urls: "https://techcombank.com", tags: "Ngân hàng", notes: "", favorite: false }, password: "Moi-Tao-Khi-Dang-Sua-42!", passwordTouched: true, removePassword: false, totp: "", totpAction: "keep" }
        : { v: 1, id: d === "gone" ? "khong-con-nua" : g.id, updated_at: d === "changed" ? g.updated_at - 60_000 : g.updated_at, base, cur: { ...base, notes: base.notes + "đổi mật khẩu 21/11" }, password: "Vua-Tao-Cho-Gmail-9x#Q", passwordTouched: true, removePassword: false, totp: "", totpAction: "keep" };
    const st = loadStash();
    st.draft = JSON.stringify(draft);
    saveStash(st);
    setUrlFlag("draft", false);
  }
  if (flag("generated")) {
    const st = loadStash();
    st.generated = [
      { id: "g1", value: "Vua-Tao-Cho-Gmail-9x#Q", at: now - 5 * 60_000, label: "Gmail" },
      { id: "g2", value: "k9$Vb2#Lq8!mZ3@xT7pp", at: now - 2 * 3_600_000, label: null },
      { id: "g3", value: "orbit-canyon-tulip-harbor-pencil-7", at: now - 3 * day, label: "Vietcombank" },
    ];
    saveStash(st);
    setUrlFlag("generated", false);
  }
}

function strength(pw: string) {
  const score = pw.length === 0 ? 0 : pw.length < 8 ? 0 : pw.length < 10 ? 2 : pw.length < 14 ? 3 : 4;
  return { score, guesses_log10: pw.length * 1.5, label: ["Rất yếu", "Yếu", "Trung bình", "Mạnh", "Rất mạnh"][score] };
}

function masterCheck(pw: string) {
  const chars = [...pw].length;
  const guesses = new Set(pw).size * 1.6;
  const ok = chars >= 12 && guesses >= 14;
  const message = chars < 12
    ? `Quá ngắn: cần ít nhất 12 ký tự (hiện ${chars}).`
    : !ok
      ? "Quá dễ đoán (tên, ngày sinh, số điện thoại, từ quen thuộc… ghép lại rất dễ bị dò). Hãy dùng một cụm 5–6 từ ngẫu nhiên, KHÔNG liên quan đến nhau (bộ tạo mật khẩu của pwv tạo được cụm như vậy)."
      : "Đạt";
  return { ok, guesses_log10: guesses, message };
}

function totpOk(t: string) {
  return t.startsWith("otpauth://") || /^[A-Z2-7\s]+=*$/i.test(t);
}

function detail(e: MockEntry): EntryDetail {
  const bad = e.totp !== null && !totpOk(e.totp);
  return {
    id: e.id, title: e.title, username: e.username, urls: e.urls, tags: e.tags,
    favorite: e.favorite, has_password: !!e.password, has_notes: !!e.notes, has_totp: !!e.totp,
    totp_label: e.totp && !bad ? (e.totp.includes("Google") ? "Google (toi@gmail.com)" : "Mã 2FA") : null,
    totp_error: bad ? "Secret 2FA đã lưu không đọc được (khoá bí mật không phải Base32) — hãy sửa mục này và nhập lại." : null,
    history_count: e.history.length,
    strength: strength(e.password), created_at: e.created_at, updated_at: e.updated_at,
  };
}

const err = (code: string, message: string): AppError => ({ code, message });
const LOCKED = err("locked", "Kho đang khoá");

function find(id: string) {
  const e = live().find((x) => x.id === id);
  if (!e) throw err("not_found", "Không tìm thấy mục này (có thể đã bị xoá)");
  return e;
}
function needUnlocked() {
  if (!unlocked) throw LOCKED;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const noSync = (): SyncResult => ({ changed: false, added: 0, updated: 0, deleted: 0, conflicts_merged: 0, errors: [], password_changed_elsewhere: false, wrote: false, backup_failed: false, old_key_archived: 0, unverified: false, problem: null });

/** Ghi nhớ trạng thái mở/khoá lên địa chỉ để giữ được qua lần nạp lại trang. */
function setUrlFlag(k: string, on: boolean, value = "") {
  const p = new URLSearchParams(location.search);
  if (on) p.set(k, value);
  else p.delete(k);
  const q = p.toString().replace(/=(&|$)/g, "$1");
  history.replaceState(history.state, "", `${location.pathname}${q ? `?${q}` : ""}`);
}

function mutated() {
  modifiedAt = Date.now();
  if (diskProblem) throw diskProblem;
}

function lockMock(note: string | null = null) {
  unlocked = false;
  lockNote = note;
  setUrlFlag("unlocked", false);
  if (note) setUrlFlag("note", true, note);
  else setUrlFlag("note", false);
}

const backups: BackupView[] = [
  { name: "vault-20261120-0915.pwv", kind: "auto", timestamp: now - 3 * 3_600_000, entries: 7, retired_key: false },
  { name: "vault-20261118-2100.pwv", kind: "auto", timestamp: now - 2 * day, entries: 8, retired_key: false },
  { name: "vault (conflicted copy).merged-20261110.pwv", kind: "merged", timestamp: now - 10 * day, entries: 9, retired_key: false },
  { name: "vault.damaged-20261101.pwv", kind: "damaged", timestamp: now - 19 * day, entries: null, retired_key: false },
];
// Bản "oldkey-…" do app cất: giữ nguyên văn, vẫn chỉ mở được bằng khoá cũ ⇒ retired_key = true.
if (flag("oldkey") || flag("oldbackup"))
  backups.unshift({ name: `oldkey-${now - 60_000}-vault (1).pwv`, kind: "oldkey", timestamp: now - 60_000, entries: 7, retired_key: true });
// Bản tự động chỉ mở được bằng khoá của mật khẩu chính cũ (ví dụ ai đó đặt vào thư mục sao lưu).
if (flag("oldbackup")) backups.splice(2, 0, { name: "vault-20261119-0700.pwv", kind: "auto", timestamp: now - 1.5 * day, entries: 7, retired_key: true });

function diff(name: string): BackupEntryView[] {
  if (name.includes("damaged")) throw err("file_damaged", "Bản sao lưu này bị hỏng, không đọc được");
  const l = live();
  const out: BackupEntryView[] = [
    { id: l[0].id, title: l[0].title, username: l[0].username, status: "changed", changed_fields: ["mật khẩu", "ghi chú"], updated_at: now - 40 * day },
    { id: trashed.id, title: trashed.title, username: trashed.username, status: "in_trash", changed_fields: [], updated_at: now - 400 * day },
  ];
  if (!name.includes("1120")) out.push({ id: "missing-1", title: "Momo", username: "0901234567", status: "missing", changed_fields: [], updated_at: now - 90 * day });
  return out;
}

// ------------------------------------------------------------------ sự kiện & hộp thoại giả

const listeners = new Map<string, Set<(p: unknown) => void>>();
export function mockListen(name: string, cb: (p: unknown) => void): () => void {
  if (!listeners.has(name)) listeners.set(name, new Set());
  listeners.get(name)!.add(cb);
  return () => listeners.get(name)?.delete(cb);
}
function emit(name: string, payload: unknown) {
  if (name === "vault-locked") lockMock(payload === "suspend" ? "Kho đã tự khoá vì máy vừa ngủ hoặc app bị tạm dừng." : null);
  listeners.get(name)?.forEach((cb) => cb(payload));
}
(window as unknown as { pwvMock: unknown }).pwvMock = {
  emit,
  /** Giả lập "mật khẩu chính đã đổi ở máy khác" ở lần đồng bộ tới. */
  passwordChangedElsewhere: () => setUrlFlag("syncreject", true, "password_changed"),
};

export async function mockPickFile(opts: { save?: boolean; defaultPath?: string; filters: { extensions: string[] }[] }): Promise<string | null> {
  await sleep(50);
  if (opts.save && flag("samefolder")) return "G:\\My Drive\\Passwords\\ban-sao.pwv";
  if (opts.save) return opts.defaultPath && /[\\/]/.test(opts.defaultPath) ? opts.defaultPath : `C:\\Users\\toi\\Documents\\${opts.defaultPath ?? "vault.pwv"}`;
  if (opts.filters.some((f) => f.extensions.includes("csv"))) return "C:\\Users\\toi\\Downloads\\Chrome Passwords.csv";
  if (IS_PHONE) return "content://com.google.android.apps.docs.storage/document/acc%3D1%3Bdoc%3Dencoded%3Dvault.pwv";
  if (flag("conflictpick")) return "G:\\My Drive\\Passwords\\vault (1).pwv";
  return "G:\\My Drive\\Passwords\\vault.pwv";
}

// ------------------------------------------------------------------ lệnh

export async function mockInvoke(cmd: string, a: Record<string, any> = {}): Promise<unknown> {
  await sleep(30);
  switch (cmd) {
    case "status":
      return {
        unlocked, read_only: unlocked && IS_PHONE, vault_path: vaultPath, vault_configured: vaultConfigured, vault_exists: vaultExists,
        conflict_copies: 0, memory_locked: true, entry_count: unlocked ? live().length : 0,
        trash_count: unlocked ? entries.length - live().length : 0, modified_at: unlocked ? modifiedAt : 0,
        disk_problem: unlocked ? diskProblem : null, lock_note: lockNote, auto_lock_minutes: settings.auto_lock_minutes,
        local_copy_at: !unlocked && flag("localcopy") ? now - 2 * 3_600_000 : null, rekey_advised: unlocked && rekeyAdvised,
      };
    case "suggest_path": return "G:\\My Drive\\Passwords\\vault.pwv";
    case "vault_traces": return flag("traces") ? ["vault.pwv.backups", "vault (1).pwv"] : [];
    case "touch": return null;
    case "page_loaded":
      if (IS_PHONE) lockMock(null);
      return null;
    case "lock":
      // Như backend: bản nháp form đang giữ được ghi vào stash TRƯỚC khi khoá.
      if (a.hasDraft && unlocked) {
        const st = loadStash();
        if (typeof a.draftSeq !== "number" || a.draftSeq >= (st.seq ?? 0)) { st.draft = a.draft ?? null; st.seq = a.draftSeq; }
        saveStash(st);
      }
      lockMock(null);
      return null;
    case "unlock": {
      await sleep(700);
      if (flag("missing")) throw err("file_missing", `Không tìm thấy file kho: ${a.path}`);
      if (flag("oldformat")) throw err("unsupported_version", "File kho được ghi bởi phiên bản app mới hơn (định dạng 3). Hãy cập nhật app.");
      if (a.password !== MASTER || flag("badheader")) throw err("wrong_password", "Sai mật khẩu chính hoặc file kho đã bị sửa đổi");
      if (flag("damaged")) throw err("file_damaged", "File kho bị hỏng hoặc chưa tải xong (không đọc được phần dữ liệu)");
      unlocked = true; lockNote = null;
      setUrlFlag("unlocked", true); setUrlFlag("note", false);
      const r = params.get("rollback");
      return {
        rollback:
          r !== null
            ? r === "key"
              ? { seen_modified_at: now - 1 * day, file_modified_at: now - 1 * day + 60_000, older_password: false, unknown_key: true }
              : { seen_modified_at: now - 1 * day, file_modified_at: now - 9 * day, older_password: r === "pw", unknown_key: false }
            : null,
        rescued: flag("rescued") ? 2 : 0,
        rescue_kept: flag("rescuekept") ? 1 : 0,
        sync: syncResult(),
        draft: loadStash().draft,
        local_restored: flag("localrestored") ? { added: 1, updated: 2, deleted: 0 } : null,
        old_version_wrote: flag("oldversion"),
        old_local_archived: flag("oldlocal") ? 1 : 0,
      };
    }
    case "recover_vault": {
      await sleep(900);
      if (typeof a.allowOlder !== "boolean") throw err("error", "mock: recover_vault thiếu allowOlder");
      const mode = params.get("recover");
      if (flag("oldformat") && !a.replaceNewer) throw err("unsupported_version", "File kho được ghi bởi phiên bản app mới hơn (định dạng 3). Hãy cập nhật app.");
      if (mode === "stale" && a.password === MASTER && !a.allowStale)
        throw { code: "older_than_seen", message: "Bản dựng lại được cũ hơn dữ liệu máy này từng thấy — có thể các bản sao lưu mới hơn chưa đồng bộ về máy này.", detail: { file_modified_at: now - 6 * day, seen_modified_at: now - 1 * day } };
      if (mode === "nobackup")
        throw err("no_backup", "không có bản sao lưu nào dùng được trong thư mục sao lưu của kho — hãy thử lịch sử phiên bản / thùng rác của Google Drive, Dropbox, OneDrive, hoặc một thiết bị khác còn giữ file kho");
      if (a.password !== MASTER) throw err("wrong_password", "Sai mật khẩu chính");
      if (mode === "prechange" && !a.allowOlder)
        throw err("old_backups_only", "chỉ còn các bản sao lưu có từ TRƯỚC lần đổi mật khẩu chính gần nhất — app không tự dùng chúng để dựng lại kho (nếu bạn đổi mật khẩu vì nghi bị lộ, nội dung các bản đó có thể đã bị người khác sửa trước khi bạn đổi)");
      if (mode === "older" && !a.allowOlder)
        throw err("older_password", "mật khẩu này chỉ mở được các bản sao lưu tạo TRƯỚC lần đổi mật khẩu chính gần nhất — hãy nhập mật khẩu chính HIỆN TẠI (mật khẩu bạn đặt gần đây nhất)");
      unlocked = true; lockNote = null; vaultExists = true;
      setUrlFlag("unlocked", true); setUrlFlag("damaged", false); setUrlFlag("missing", false); setUrlFlag("recover", false); setUrlFlag("oldformat", false); setUrlFlag("badheader", false);
      return { entries: live().length, files_used: mode === "local" ? 1 : 3, newest_backup_at: now - 3 * 3_600_000, archived: "G:\\My Drive\\Passwords\\vault.pwv.backups\\vault.damaged-20261120.pwv", rescue_kept: flag("rescuekept") ? 1 : 0, from_local_copy: mode === "local", old_local_archived: flag("oldlocal") ? 1 : 0 };
    }
    case "accept_rollback": needUnlocked(); setUrlFlag("rollback", false); return null;
    case "create_vault": {
      await sleep(700);
      const c = masterCheck(a.password);
      if (!c.ok) throw err("weak_password", `Mật khẩu chính chưa đủ mạnh. ${c.message}`);
      unlocked = true; vaultExists = true; vaultConfigured = true; vaultPath = a.path;
      setUrlFlag("setup", false); setUrlFlag("missing", false); setUrlFlag("unlocked", true);
      return null;
    }
    case "set_vault_path":
      lockMock(null); vaultPath = a.path; vaultConfigured = true; vaultExists = true;
      setUrlFlag("setup", false); setUrlFlag("missing", false);
      return null;
    case "list_entries": {
      needUnlocked();
      const q = String(a.query).toLowerCase();
      return live()
        .filter((e) => !q || [e.title, e.username, ...e.urls, ...e.tags].some((s) => s.toLowerCase().includes(q)))
        .sort((x, y) => Number(y.favorite) - Number(x.favorite) || x.title.localeCompare(y.title, "vi"))
        .map((e) => ({ id: e.id, title: e.title, username: e.username, url: e.urls[0] ?? null, favorite: e.favorite, tags: e.tags, has_totp: !!e.totp, updated_at: e.updated_at }));
    }
    case "get_entry": needUnlocked(); return detail(find(a.id));
    case "reveal_password": needUnlocked(); return find(a.id).password;
    case "reveal_notes": needUnlocked(); return find(a.id).notes;
    case "reveal_totp_secret": needUnlocked(); return find(a.id).totp ?? "";
    case "password_history": needUnlocked(); return find(a.id).history;
    case "totp_code": {
      needUnlocked();
      const e = find(a.id);
      if (!e.totp || !totpOk(e.totp)) throw err("error", "Mã 2FA không hợp lệ");
      const s = Math.floor(Date.now() / 1000);
      return { code: String(((s / 30) | 0) * 7919).slice(-6).padStart(6, "0"), remaining: 30 - (s % 30), period: 30 };
    }
    case "copy_field": {
      needUnlocked();
      const e = find(a.id);
      const f = String(a.field);
      if (entryChangedOnce) { entryChangedOnce = false; e.updated_at = Date.now(); }
      const changedErr = () => err("entry_changed", "Mục này vừa thay đổi (có thể do đồng bộ từ máy khác) nên đã được tải lại — hãy bấm sao chép lại.");
      if (a.updatedAt != null && a.updatedAt !== e.updated_at) throw changedErr();
      if (a.shown != null) {
        const actual = f.startsWith("url:") ? e.urls[Number(f.slice(4))] : f.startsWith("history:") ? String(e.history[Number(f.slice(8))]?.replaced_at) : a.shown;
        if (actual !== a.shown) throw changedErr();
      }
      const v = f === "password" ? e.password : f === "username" ? e.username : f === "notes" ? e.notes : f === "url" ? e.urls[0] : f === "totp" ? e.totp : f.startsWith("history:") ? e.history[Number(f.slice(8))]?.password : f.startsWith("url:") ? e.urls[Number(f.slice(4))] : undefined;
      if (v === undefined && !["password", "username", "notes", "url", "totp"].includes(f) && !f.startsWith("history:") && !f.startsWith("url:")) throw err("error", `Trường không hợp lệ: ${f}`);
      if (!v) throw err("error", "Trường này đang trống");
      return settings.clipboard_clear_secs;
    }
    case "set_draft": {
      needUnlocked();
      const st = loadStash();
      if (a.draft != null && String(a.draft).length > 256 * 1024) { st.draft = null; saveStash(st); throw err("draft_too_large", "Bản nháp quá lớn, chưa được giữ."); }
      // Bản đến muộn mà cũ hơn (số thứ tự nhỏ hơn) bị bỏ, như backend.
      if (typeof a.draftSeq === "number" && a.draftSeq < (st.seq ?? 0)) return null;
      st.draft = a.draft ?? null;
      if (typeof a.draftSeq === "number") st.seq = a.draftSeq;
      saveStash(st);
      return null;
    }
    case "get_draft": needUnlocked(); return loadStash().draft;
    case "record_generated": {
      needUnlocked();
      const st = loadStash();
      const g = st.generated.find((x) => x.value === a.value);
      if (g) { g.at = Date.now(); if (a.label) g.label = a.label; }
      else st.generated.push({ id: `g${Date.now()}`, value: a.value, at: Date.now(), label: a.label ?? null });
      saveStash(st);
      return null;
    }
    case "list_generated": needUnlocked(); return loadStash().generated.map(({ id, at, label }) => ({ id, at, label }));
    case "reveal_generated": case "copy_generated": {
      needUnlocked();
      const g = loadStash().generated.find((x) => x.id === a.id);
      if (!g) throw err("not_found", "Không còn mật khẩu này trong danh sách (đã quá 30 ngày hoặc đã bị xoá)");
      return cmd === "reveal_generated" ? g.value : settings.clipboard_clear_secs;
    }
    case "clear_generated": { needUnlocked(); const st = loadStash(); st.generated = []; saveStash(st); return null; }
    case "check_rekey": needUnlocked(); await sleep(300); return rekeyAdvised;
    case "restore_local_copy":
      if (unlocked) throw err("error", "Hãy khoá kho trước");
      if (!flag("localcopy")) throw err("error", "Máy này không có bản lưu riêng của kho này");
      await sleep(300);
      vaultExists = true; setUrlFlag("missing", false); setUrlFlag("localcopy", false);
      return null;
    case "prepare_copy_folder":
      needUnlocked();
      return `G:\\My Drive\\Passwords\\Ban sao ${String(a.day)}`;
    case "discard_copy_folder":
      return null;
    case "check_vault_choice":
      await sleep(50);
      return /\(1\)\.pwv$/.test(String(a.path)) ? { picked_name: "vault (1).pwv", original_name: "vault.pwv", original_path: "G:\\My Drive\\Passwords\\vault.pwv" } : null;
    case "copy_text":
      if (!a.text) throw err("error", "Không có gì để sao chép");
      return settings.clipboard_clear_secs;
    case "save_entry": {
      needUnlocked();
      await sleep(250);
      const i = a.entry as EntryInput;
      const title = i.title?.trim();
      if (title === "" || (!i.id && !title)) throw err("error", "Tiêu đề không được để trống");
      if (i.totp && !totpOk(i.totp.trim())) throw err("error", "Mã 2FA không hợp lệ: khoá bí mật phải là Base32 hoặc địa chỉ otpauth://");
      if (title?.toLowerCase() === "lỗi") throw err("error", "Không ghi được file kho: thư mục đồng bộ đang bị khoá (mock)");
      mutated();
      const clean = (xs: string[]) => xs.map((s) => s.trim()).filter(Boolean);
      if (i.id) {
        const e = find(i.id);
        if (i.password != null && i.password !== e.password && e.password) e.history.unshift({ password: e.password, replaced_at: Date.now() });
        if (title != null) e.title = title;
        if (i.username != null) e.username = i.username.trim();
        if (i.password != null) e.password = i.password;
        if (i.urls != null) e.urls = clean(i.urls);
        if (i.notes != null) e.notes = i.notes;
        if (i.tags != null) e.tags = clean(i.tags);
        if (i.favorite != null) e.favorite = i.favorite;
        if (i.totp != null) e.totp = i.totp.trim() || null;
        e.updated_at = Date.now();
        console.info("[mock] save_entry gửi các trường:", Object.keys(i).filter((k) => k !== "id").join(", ") || "(không có)");
        clearMockDraft();
        return [e.id, writeResult()];
      }
      const e = mk(title!, i.username ?? "", i.password ?? "", clean(i.urls ?? []), clean(i.tags ?? []), !!i.favorite, i.totp?.trim() || null, 0);
      e.notes = i.notes ?? "";
      entries.push(e);
      clearMockDraft();
      return [e.id, writeResult()];
    }
    case "delete_entry": { needUnlocked(); const e = find(a.id); mutated(); e.trashed_at = Date.now(); return writeResult(); }
    case "toggle_favorite": { needUnlocked(); const e = find(a.id); mutated(); e.favorite = !e.favorite; return e.favorite; }
    case "list_trash":
      needUnlocked();
      return entries.filter((e) => e.trashed_at !== null).sort((x, y) => y.trashed_at! - x.trashed_at!).map((e) => ({ id: e.id, title: e.title, username: e.username, deleted_at: e.trashed_at }));
    case "restore_entry": { needUnlocked(); const e = entries.find((x) => x.id === a.id); if (!e) throw err("not_found", "Không tìm thấy"); mutated(); e.trashed_at = null; return null; }
    case "purge_entry": { needUnlocked(); const i = entries.findIndex((x) => x.id === a.id && x.trashed_at !== null); if (i < 0) throw err("not_found", "Không tìm thấy"); mutated(); entries.splice(i, 1); return null; }
    case "empty_trash": {
      needUnlocked();
      if (!Array.isArray(a.ids)) throw err("error", "mock: empty_trash thiếu ids");
      mutated();
      // Như backend: gộp thay đổi của máy khác trước (?trashrace: máy khác vừa chuyển thêm một mục vào thùng rác)…
      if (flag("trashrace") && !entries.some((e) => e.title === "Momo (từ máy khác)")) {
        const extra = mk("Momo (từ máy khác)", "0901234567", "momo-pass", [], [], false, null, 50);
        extra.trashed_at = Date.now();
        entries.push(extra);
      }
      // …rồi chỉ xoá ĐÚNG các mục người dùng đã thấy.
      const ids = new Set(a.ids as string[]);
      let purged = 0;
      for (let i = entries.length - 1; i >= 0; i--)
        if (entries[i].trashed_at !== null && ids.has(entries[i].id)) {
          entries.splice(i, 1);
          purged++;
        }
      return { purged, remaining: entries.filter((e) => e.trashed_at !== null).length };
    }
    case "sync_now": {
      needUnlocked();
      await sleep(150);
      const rej = new URLSearchParams(location.search).get("syncreject");
      if (rej === "password_changed") { lockMock("Mật khẩu chính đã được đổi ở máy khác. Hãy mở khoá bằng mật khẩu MỚI."); setUrlFlag("syncreject", false); throw err("password_changed", "Mật khẩu chính đã được đổi ở máy khác"); }
      if (rej === "locked") { lockMock(null); setUrlFlag("syncreject", false); throw LOCKED; }
      if (rej === "error") throw err("error", "Không đọc được thư mục đồng bộ: thiết bị chưa sẵn sàng (mock)");
      const r = syncResult();
      if (backupFailOnce) { r.backup_failed = true; backupFailOnce = false; }
      return r;
    }
    case "force_write": {
      needUnlocked();
      await sleep(300);
      const wasDamaged = diskProblem?.code === "file_damaged";
      if (diskProblem && ["different_vault", "unsupported_version"].includes(diskProblem.code)) throw diskProblem;
      diskProblem = null; vaultExists = true;
      setUrlFlag("problem", false);
      return wasDamaged ? "G:\\My Drive\\Passwords\\vault.pwv.backups\\vault.damaged-20261120-1012.pwv" : null;
    }
    case "generate": {
      const r = a.request as GenRequest;
      if (r.mode === "passphrase") {
        const words = ["lettuce", "marbled", "posting", "raffle", "velocity", "mandatory", "canyon", "orbit", "tulip", "harbor", "pencil", "garden"];
        const rnd = crypto.getRandomValues(new Uint32Array(r.words));
        let v = Array.from(rnd, (x) => words[x % words.length]).map((w) => (r.capitalize ? w[0].toUpperCase() + w.slice(1) : w)).join(r.separator);
        if (r.add_number) v += String(rnd[0] % 10);
        return { value: v, entropy_bits: r.words * 12.9, strength: strength(v) };
      }
      const cs = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*";
      const v = Array.from(crypto.getRandomValues(new Uint32Array(r.length)), (x) => cs[x % cs.length]).join("");
      return { value: v, entropy_bits: r.length * 6.5, strength: strength(v) };
    }
    case "strength": return strength(a.password);
    case "master_check": return masterCheck(a.password);
    case "change_master_password": {
      needUnlocked();
      await sleep(500);
      const c = masterCheck(a.new);
      const same = a.new === a.current;
      // Như backend: giữ nguyên mật khẩu (chỉ thay khoá) không bị chặn bởi chính sách, chỉ cảnh báo.
      if (!c.ok && !same) throw err("weak_password", `Mật khẩu chính chưa đủ mạnh. ${c.message}`);
      if (a.current !== MASTER) throw err("wrong_password", "Mật khẩu chính hiện tại không đúng");
      rekeyAdvised = false; setUrlFlag("rekey", false);
      return {
        backups_reencrypted: 9, backups_skipped: 1, unverified: flag("unverified"),
        backups_failed: flag("pwfailed") ? ["vault-1795100000000.pwv", "merged-1795000000000-vault (1).pwv"] : [],
        policy_warning: same && !c.ok ? `Mật khẩu chính chưa đủ mạnh. ${c.message}` : null,
      };
    }
    case "health_report": {
      needUnlocked();
      await sleep(a.online ? 800 : 100);
      const failed = a.online && flag("breacherr");
      const done = a.online && !failed;
      return {
        score: 50, checked: live().length, breached: done ? 2 : 0, reused: 2, weak: 3, old: 2,
        breach_check_done: done, breach_error: failed ? "Không kết nối được api.pwnedpasswords.com (hết thời gian chờ)" : null,
        items: live().filter((e) => e.password.length < 10).map((e) => ({
          id: e.id, title: e.title, username: e.username, severity: done ? 0 : 1,
          issues: [...(done ? ["ĐÃ BỊ LỘ trong 104 vụ rò rỉ dữ liệu — hãy đổi ngay"] : []), "mật khẩu yếu (1/4)", ...(e.password === "Abc@2020" ? ["dùng chung với 1 mục khác"] : [])],
        })),
      };
    }
    case "import_csv":
      needUnlocked(); await sleep(300); mutated();
      lastImport = a.path;
      return { imported: 12, duplicates: 3, skipped: 1, similar: ["Facebook (2)", "Gmail công việc"], bad_totp: ["GitHub"], detected: "Chrome / Edge" };
    case "delete_imported_csv":
      if (!lastImport) throw err("error", "Không có file CSV nào vừa được nhập");
      lastImport = null; return null;
    case "move_vault":
      needUnlocked(); await sleep(400);
      if (typeof a.copyOnly !== "boolean") throw err("error", "mock: move_vault thiếu copyOnly");
      if (flag("movefail")) throw err("move_failed", `Chưa ghi được sang vị trí mới: không tìm thấy ổ đĩa (${a.path}). Kho vẫn ở vị trí cũ.`);
      {
        const dir = (x: string | null) => (x ?? "").replace(/[\\/][^\\/]*$/, "").toLowerCase();
        if (a.copyOnly && dir(a.path) === dir(vaultPath))
          throw err("move_failed", "Hãy chọn một thư mục KHÁC thư mục đang chứa file kho (ví dụ một thư mục con mới bên trong nó): file mới đặt ngay cạnh file kho cũ sẽ bị coi là bản xung đột của nó.");
        const rescued = a.copyOnly || diskProblem !== null;
        const old = vaultPath;
        diskProblem = null; vaultPath = a.path; vaultExists = true; setUrlFlag("problem", false);
        return { old_path: old, new_path: a.path, backups_moved: !rescued, old_removed: !rescued, conflicts_merged: 0, rescued };
      }
    case "list_backups": needUnlocked(); await sleep(100); return backups;
    case "backup_diff": needUnlocked(); await sleep(150); return diff(a.name);
    case "restore_from_backup": needUnlocked(); await sleep(200); mutated(); {
      for (const id of a.ids as string[]) { const e = entries.find((x) => x.id === id); if (e) e.trashed_at = null; }
      return (a.ids as string[]).length;
    }
    case "app_version": return "0.2.0";
    case "open_readonly": {
      await sleep(600);
      if (flag("readfail")) throw err("read_failed", "Không đọc được file kho: Permission Denial: quyền đọc đã hết hạn. Hãy chọn lại file kho.");
      if (flag("pwchanged")) throw err("password_changed", "File kho vừa đọc CŨ HƠN bản đã lưu trên máy (dùng mật khẩu chính cũ). Hãy nhập mật khẩu chính MỚI, hoặc chọn lại đúng file kho.");
      if (a.password !== MASTER) throw err("wrong_password", "Sai mật khẩu chính hoặc file kho đã bị sửa đổi");
      unlocked = true; lockNote = null;
      return flag("cache") ? { from_cache: true, note: "Không đọc được file kho: không có kết nối mạng" } : { from_cache: false, note: null };
    }
    case "reload_readonly": {
      needUnlocked(); await sleep(400);
      const f = params.get("reloadfail");
      if (f === "read_failed") throw err("read_failed", "Không đọc được file kho: Permission Denial (quyền đọc đã hết hạn)");
      if (f === "password_changed") { lockMock("Mật khẩu chính đã được đổi trên máy tính. Hãy nhập mật khẩu chính MỚI."); throw err("password_changed", "Mật khẩu chính đã được đổi trên máy tính"); }
      if (f === "error") throw err("file_damaged", "File kho vừa tải về bị hỏng hoặc chưa tải xong");
      return false;
    }
    case "repick_readonly": needUnlocked(); await sleep(400); vaultPath = a.location; modifiedAt = Date.now() - 60_000; return true;
    case "check_update": await sleep(300); return { current: "0.2.0", latest: "0.2.1", available: true, page_url: "https://github.com/example/pwv/releases/tag/v0.2.1", notes: "- Sửa lỗi đồng bộ\n- Thùng rác", published_at: "2026-11-19T10:00:00Z" };
    case "open_release_page":
      if (!/^\d+(\.\d+)*$/.test(String(a.version))) throw err("error", "Số phiên bản không hợp lệ");
      return null;
    case "get_settings": return settings;
    case "set_settings": settings = a.settings; return null;
    case "backups_dir": return unlocked ? "G:\\My Drive\\Passwords\\vault.pwv.backups" : null;
  }
  throw err("error", `mock: lệnh chưa hỗ trợ ${cmd}`);
}
