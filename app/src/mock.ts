// Backend giả — CHỈ dùng khi chạy `vite --mode mock` để xem giao diện trong trình duyệt.
import type { EntryDetail, EntryInput, GenRequest, Settings } from "./types";

interface MockEntry extends Omit<EntryDetail, "has_password" | "strength" | "history_count" | "totp_label" | "has_totp"> {
  password: string;
  totp: string | null;
  history: { password: string; replaced_at: number }[];
}

const now = Date.now();
const day = 86_400_000;
let unlocked = new URLSearchParams(location.search).has("unlocked");
let vaultExists = !new URLSearchParams(location.search).has("setup");
let settings: Settings = { auto_lock_minutes: 5, clipboard_clear_secs: 20 };

const entries: MockEntry[] = [
  mk("Vietcombank", "nguyenvana", "Qx7#mP2!vL9@wR4$", ["https://vcbdigibank.vietcombank.com.vn"], ["Ngân hàng"], true, null, 30),
  mk("Gmail", "toi@gmail.com", "Lettuce-Marbled1-Posting-Raffle", ["https://mail.google.com"], ["Email"], true, "otpauth://totp/Google:toi@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google", 10),
  mk("Facebook", "toi@gmail.com", "Abc@2020", ["https://facebook.com"], ["Mạng xã hội"], false, null, 500),
  mk("Shopee", "toi@gmail.com", "Abc@2020", ["https://shopee.vn"], ["Mua sắm"], false, null, 200),
  mk("Binance", "toi@gmail.com", "k9$Vb2#Lq8!mZ3@xT7", ["https://binance.com"], ["Crypto"], false, "JBSWY3DPEHPK3PXP", 5),
  mk("Wi-Fi nhà", "", "123456", [], [], false, null, 900),
];

function mk(title: string, username: string, password: string, urls: string[], tags: string[], favorite: boolean, totp: string | null, ageDays: number): MockEntry {
  return {
    id: crypto.randomUUID(), title, username, password, urls, tags, favorite, totp,
    notes: title === "Vietcombank" ? "Số tài khoản: 0123456789\nMã PIN thẻ: ****" : "",
    history: title === "Gmail" ? [{ password: "old-gmail-pass", replaced_at: now - 40 * day }] : [],
    created_at: now - ageDays * day, updated_at: now - ageDays * day,
  };
}

function strength(pw: string) {
  const score = pw.length === 0 ? 0 : pw.length < 8 ? 0 : pw.length < 10 ? 2 : pw.length < 14 ? 3 : 4;
  return { score, guesses_log10: pw.length * 1.5, label: ["Rất yếu", "Yếu", "Trung bình", "Mạnh", "Rất mạnh"][score] };
}

function detail(e: MockEntry): EntryDetail {
  return {
    id: e.id, title: e.title, username: e.username, urls: e.urls, notes: e.notes, tags: e.tags,
    favorite: e.favorite, has_password: !!e.password, has_totp: !!e.totp,
    totp_label: e.totp ? "Google (toi@gmail.com)" : null, history_count: e.history.length,
    strength: strength(e.password), created_at: e.created_at, updated_at: e.updated_at,
  };
}

const find = (id: string) => {
  const e = entries.find((x) => x.id === id);
  if (!e) throw `Không tìm thấy mục ${id}`;
  return e;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const noSync = { changed: false, added: 0, updated: 0, deleted: 0, conflicts_merged: 0, errors: [], password_changed_elsewhere: false };

export async function mockInvoke(cmd: string, a: Record<string, any> = {}): Promise<unknown> {
  await sleep(30);
  switch (cmd) {
    case "status":
      return {
        unlocked, vault_path: vaultExists ? "G:\\My Drive\\Passwords\\vault.pwv" : null, vault_exists: vaultExists,
        suggested_path: "G:\\My Drive\\Passwords\\vault.pwv", conflict_copies: 0, memory_locked: true, entry_count: entries.length,
      };
    case "touch": case "lock":
      if (cmd === "lock") unlocked = false;
      return null;
    case "unlock":
      await sleep(700);
      if (a.password !== "demo-demo-demo-demo") throw "sai mật khẩu chính hoặc file kho đã bị sửa đổi";
      unlocked = true; return null;
    case "create_vault":
      await sleep(700); unlocked = true; vaultExists = true; return null;
    case "set_vault_path": unlocked = false; return null;
    case "list_entries": {
      const q = String(a.query).toLowerCase();
      return entries
        .filter((e) => !q || [e.title, e.username, ...e.urls, ...e.tags].some((s) => s.toLowerCase().includes(q)))
        .sort((x, y) => Number(y.favorite) - Number(x.favorite) || x.title.localeCompare(y.title, "vi"))
        .map((e) => ({ id: e.id, title: e.title, username: e.username, url: e.urls[0] ?? null, favorite: e.favorite, tags: e.tags, has_totp: !!e.totp, updated_at: e.updated_at }));
    }
    case "get_entry": return detail(find(a.id));
    case "reveal_password": return find(a.id).password;
    case "password_history": return find(a.id).history;
    case "totp_code": {
      const s = Math.floor(Date.now() / 1000);
      return { code: String((s / 30) | 0).slice(-6).padStart(6, "0"), remaining: 30 - (s % 30), period: 30 };
    }
    case "copy_field": case "copy_text": return settings.clipboard_clear_secs;
    case "save_entry": {
      const i = a.entry as EntryInput;
      if (!i.title.trim()) throw "Tiêu đề không được để trống";
      if (i.id) {
        const e = find(i.id);
        if (i.password !== null && i.password !== e.password) e.history.unshift({ password: e.password, replaced_at: Date.now() });
        Object.assign(e, { title: i.title, username: i.username, urls: i.urls, notes: i.notes, tags: i.tags, favorite: i.favorite, updated_at: Date.now() });
        if (i.password !== null) e.password = i.password;
        if (i.totp !== null) e.totp = i.totp || null;
        return [e.id, noSync];
      }
      const e = mk(i.title, i.username, i.password ?? "", i.urls, i.tags, i.favorite, i.totp || null, 0);
      entries.push(e);
      return [e.id, noSync];
    }
    case "delete_entry": entries.splice(entries.indexOf(find(a.id)), 1); return noSync;
    case "toggle_favorite": { const e = find(a.id); e.favorite = !e.favorite; return null; }
    case "sync_now": return noSync;
    case "generate": {
      const r = a.request as GenRequest;
      if (r.mode === "passphrase") {
        const words = ["Lettuce", "Marbled", "Posting", "Raffle", "Velocity", "Mandatory", "Canyon", "Orbit", "Tulip", "Harbor"];
        const v = Array.from({ length: r.words }, (_, i) => words[(i * 7 + Date.now()) % words.length]).join(r.separator);
        return { value: v, entropy_bits: r.words * 12.9, strength: strength(v) };
      }
      const cs = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*";
      const v = Array.from(crypto.getRandomValues(new Uint32Array(r.length)), (x) => cs[x % cs.length]).join("");
      return { value: v, entropy_bits: r.length * 6.5, strength: strength(v) };
    }
    case "strength": return strength(a.password);
    case "change_master_password": await sleep(500); return null;
    case "health_report": {
      await sleep(a.online ? 800 : 100);
      return {
        score: 50, checked: entries.length, breached: a.online ? 2 : 0, reused: 2, weak: 3, old: 2,
        breach_check_done: a.online, breach_error: null,
        items: entries.filter((e) => e.password.length < 10).map((e) => ({
          id: e.id, title: e.title, username: e.username, severity: a.online ? 0 : 1,
          issues: [...(a.online ? ["ĐÃ BỊ LỘ trong 104 vụ rò rỉ dữ liệu — hãy đổi ngay"] : []), "mật khẩu yếu (1/4)", ...(e.password === "Abc@2020" ? ["dùng chung với 1 mục khác"] : [])],
        })),
      };
    }
    case "import_csv": return { imported: 12, duplicates: 3, skipped: 1, detected: "Chrome / Edge", csv_deleted: a.deleteAfter };
    case "move_vault": await sleep(400); return { new_path: a.path, backups_moved: true, old_removed: true, conflicts_merged: 0 };
    case "get_settings": return settings;
    case "set_settings": settings = a.settings; return null;
    case "backups_dir": return "G:\\My Drive\\Passwords\\vault.pwv.backups";
  }
  throw `mock: lệnh chưa hỗ trợ ${cmd}`;
}
