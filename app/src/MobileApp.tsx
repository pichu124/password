// Giao diện điện thoại (Android): chỉ xem + sao chép. Thêm/sửa làm trên máy tính.
import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorText, onEvent, pickFile } from "./api";
import { EntryView } from "./components/EntryView";
import { Generator } from "./components/Generator";
import { avatarHue, Icon, initials, useToast } from "./components/ui";
import type { EntrySummary, Settings, Status, UpdateInfo } from "./types";

/** Khoá ngay khi app bị đưa xuống nền quá lâu (ví dụ chuyển sang app khác rồi quên). */
const LOCK_WHEN_HIDDEN_MS = 60_000;

type Screen = { kind: "list" } | { kind: "detail"; id: string } | { kind: "settings" } | { kind: "generator" };

async function chooseVaultFile(): Promise<string | null> {
  // Không lọc theo đuôi file: trên Android bộ lọc theo đuôi .pwv thường làm ẩn mất file.
  return pickFile({ title: "Chọn file vault.pwv", filters: [] });
}

export default function MobileApp() {
  const toast = useToast();
  const [status, setStatus] = useState<Status | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.status());
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    let off: (() => void) | undefined;
    onEvent("vault-locked", () => {
      toast("Đã tự khoá do không sử dụng", "info");
      refresh();
    }).then((f) => (off = f));
    return () => off?.();
  }, [refresh, toast]);

  if (!status) return null;
  if (!status.vault_path) return <MobileSetup onDone={refresh} />;
  if (!status.unlocked) return <MobileUnlock status={status} onDone={refresh} />;
  return <MobileVault onLocked={refresh} />;
}

function MobileSetup({ onDone }: { onDone: () => void }) {
  const toast = useToast();
  async function choose() {
    const p = await chooseVaultFile();
    if (!p) return;
    try {
      await api.setVaultPath(p);
      onDone();
    } catch (e) {
      toast(errorText(e), "error");
    }
  }
  return (
    <div className="m-center">
      <div className="m-card">
        <img src="/icon.svg" alt="" className="lock-logo" />
        <h1>pwv trên điện thoại</h1>
        <p className="muted">Xem và sao chép mật khẩu, mã 2FA từ kho bạn tạo trên máy tính.</p>
        <ol className="m-steps">
          <li>Cài app Google Drive, Dropbox hoặc OneDrive trên điện thoại và đăng nhập.</li>
          <li>Bấm nút bên dưới, chọn dịch vụ đó trong danh sách bên trái, rồi chọn file <code>vault.pwv</code>.</li>
        </ol>
        <button className="btn primary wide" onClick={choose}>
          Chọn file kho
        </button>
        <p className="muted small">Điện thoại chỉ đọc file kho, không bao giờ ghi vào — kho trên máy tính luôn an toàn.</p>
      </div>
    </div>
  );
}

function MobileUnlock({ status, onDone }: { status: Status; onDone: () => void }) {
  const toast = useToast();
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => ref.current?.focus(), []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!pw) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.openReadonly(pw);
      setPw("");
      if (r.from_cache) toast("Không đọc được file mới — đang dùng bản đã lưu trên máy. Bấm ⟳ để tải bản mới.", "info");
      onDone();
    } catch (err) {
      setError(errorText(err));
      setPw("");
    } finally {
      setBusy(false);
    }
  }

  async function changeFile() {
    const p = await chooseVaultFile();
    if (p) {
      await api.setVaultPath(p);
      onDone();
    }
  }

  return (
    <div className="m-center">
      <form className="m-card" onSubmit={submit}>
        <img src="/icon.svg" alt="" className="lock-logo" />
        <h1>Mở khoá</h1>
        <p className="muted small m-path">{prettyLocation(status.vault_path)}</p>
        <input
          ref={ref}
          type="password"
          placeholder="Master password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          disabled={busy}
          autoComplete="current-password"
          aria-label="Master password"
        />
        {error && <p className="error">{error}</p>}
        <button className="btn primary wide" disabled={busy || !pw}>
          {busy ? "Đang giải mã…" : "Mở khoá"}
        </button>
        <button type="button" className="btn link" onClick={changeFile}>
          Chọn file kho khác
        </button>
      </form>
    </div>
  );
}

function MobileVault({ onLocked }: { onLocked: () => void }) {
  const toast = useToast();
  const [screen, setScreen] = useState<Screen>({ kind: "list" });
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [reloading, setReloading] = useState(false);
  const [needRepick, setNeedRepick] = useState(false);

  const load = useCallback(async () => {
    try {
      setEntries(await api.list(query));
    } catch (e) {
      const msg = errorText(e);
      if (msg.includes("khoá")) onLocked();
      else toast(msg, "error");
    }
  }, [query, onLocked, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const lock = useCallback(async () => {
    await api.lock();
    onLocked();
  }, [onLocked]);

  // Báo hoạt động cho bộ đếm tự khoá; khoá khi app nằm nền quá lâu.
  useEffect(() => {
    let last = 0;
    let hiddenAt = 0;
    const touch = () => {
      const now = Date.now();
      if (now - last > 15_000) {
        last = now;
        api.touch().catch(() => {});
      }
    };
    const onVis = () => {
      if (document.hidden) hiddenAt = Date.now();
      else if (hiddenAt && Date.now() - hiddenAt > LOCK_WHEN_HIDDEN_MS) lock();
    };
    window.addEventListener("touchstart", touch, { passive: true });
    window.addEventListener("keydown", touch);
    document.addEventListener("visibilitychange", onVis);
    return () => {
      window.removeEventListener("touchstart", touch);
      window.removeEventListener("keydown", touch);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [lock]);

  // Nút "back" của Android: quay về danh sách thay vì thoát app.
  useEffect(() => {
    if (screen.kind === "list") return;
    history.pushState({ pwv: true }, "");
    const onPop = () => setScreen({ kind: "list" });
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [screen.kind]);

  async function reload() {
    setReloading(true);
    try {
      const changed = await api.reloadReadonly();
      setNeedRepick(false);
      toast(changed ? "Đã tải bản mới nhất" : "Kho đã là bản mới nhất");
      if (changed) load();
    } catch (e) {
      setNeedRepick(true);
      toast(errorText(e), "error");
    } finally {
      setReloading(false);
    }
  }

  async function repick() {
    const p = await chooseVaultFile();
    if (!p) return;
    try {
      const changed = await api.repickReadonly(p);
      setNeedRepick(false);
      toast(changed ? "Đã tải bản mới nhất" : "Kho đã là bản mới nhất");
      load();
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  const back = () => history.back();

  if (screen.kind === "detail") {
    return (
      <div className="m-app">
        <header className="m-bar">
          <button className="icon-btn" onClick={back} aria-label="Quay lại">
            <Icon name="back" />
          </button>
          <span className="grow" />
          <button className="icon-btn" onClick={lock} aria-label="Khoá">
            <Icon name="lock" />
          </button>
        </header>
        <div className="m-detail">
          <EntryView id={screen.id} readOnly />
        </div>
      </div>
    );
  }

  if (screen.kind === "generator") {
    return (
      <div className="m-app">
        <header className="m-bar">
          <button className="icon-btn" onClick={back} aria-label="Quay lại">
            <Icon name="back" />
          </button>
          <strong className="grow">Tạo mật khẩu</strong>
        </header>
        <div className="m-scroll">
          <Generator />
        </div>
      </div>
    );
  }

  if (screen.kind === "settings") {
    return (
      <div className="m-app">
        <header className="m-bar">
          <button className="icon-btn" onClick={back} aria-label="Quay lại">
            <Icon name="back" />
          </button>
          <strong className="grow">Cài đặt</strong>
        </header>
        <div className="m-scroll">
          <MobileSettings onRepick={repick} onOpenGenerator={() => setScreen({ kind: "generator" })} />
        </div>
      </div>
    );
  }

  return (
    <div className="m-app">
      <header className="m-bar">
        <div className="brand">
          <img src="/icon.svg" alt="" />
          <span>pwv</span>
        </div>
        <span className="grow" />
        <button className={reloading ? "icon-btn spinning" : "icon-btn"} onClick={reload} aria-label="Tải bản mới">
          <Icon name="sync" />
        </button>
        <button className="icon-btn" onClick={() => setScreen({ kind: "settings" })} aria-label="Cài đặt">
          <Icon name="gear" />
        </button>
        <button className="icon-btn" onClick={lock} aria-label="Khoá">
          <Icon name="lock" />
        </button>
      </header>
      <div className="m-search">
        <input type="search" placeholder="Tìm theo tên, tài khoản, trang web…" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      {needRepick && (
        <div className="banner">
          Android đã hết quyền đọc file kho. <button className="btn link" onClick={repick}>Chọn lại file</button> để tải bản mới.
        </div>
      )}
      <ul className="m-list">
        {entries.map((e) => (
          <li key={e.id}>
            <button className="list-item" onClick={() => setScreen({ kind: "detail", id: e.id })}>
              <span className="avatar" style={{ background: `hsl(${avatarHue(e.title)} 45% 45%)` }}>
                {initials(e.title)}
              </span>
              <span className="grow ellipsis">
                <span className="item-title">
                  {e.title}
                  {e.favorite && <span className="star">★</span>}
                  {e.has_totp && <span className="badge">2FA</span>}
                </span>
                <span className="item-sub">{e.username || e.url || " "}</span>
              </span>
            </button>
          </li>
        ))}
        {entries.length === 0 && <li className="list-empty">{query ? `Không tìm thấy “${query}”.` : "Kho đang trống. Thêm mật khẩu trên máy tính."}</li>}
      </ul>
      <footer className="m-foot muted small">{entries.length} mục · chỉ xem — thêm/sửa trên máy tính</footer>
    </div>
  );
}

function MobileSettings({ onRepick, onOpenGenerator }: { onRepick: () => void; onOpenGenerator: () => void }) {
  const toast = useToast();
  const [s, setS] = useState<Settings | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [version, setVersion] = useState("");
  const [update, setUpdate] = useState<UpdateInfo | null>(null);

  useEffect(() => {
    api.getSettings().then(setS);
    api.status().then(setStatus);
    api.appVersion().then(setVersion);
  }, []);

  async function save(next: Settings) {
    setS(next);
    try {
      await api.setSettings(next);
      toast("Đã lưu cài đặt");
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  async function checkUpdate() {
    try {
      const u = await api.checkUpdate();
      if (!u) toast("Chưa có bản phát hành nào", "info");
      else if (!u.available) toast(`Bạn đang dùng bản mới nhất (${u.current})`);
      else setUpdate(u);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  return (
    <div className="m-settings">
      {s && (
        <section className="card">
          <h3>Bảo mật</h3>
          <label className="field">
            <span>Tự khoá sau khi không dùng</span>
            <select value={s.auto_lock_minutes} onChange={(e) => save({ ...s, auto_lock_minutes: Number(e.target.value) })}>
              {[1, 2, 5, 10, 15].map((m) => (
                <option key={m} value={m}>
                  {m} phút
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Tự xoá clipboard sau</span>
            <select value={s.clipboard_clear_secs} onChange={(e) => save({ ...s, clipboard_clear_secs: Number(e.target.value) })}>
              {[10, 20, 30, 60].map((x) => (
                <option key={x} value={x}>
                  {x} giây
                </option>
              ))}
            </select>
          </label>
          <p className="muted small">App cũng tự khoá khi bị đưa xuống nền quá 1 phút.</p>
        </section>
      )}
      <section className="card">
        <h3>File kho</h3>
        <p className="small m-path">{prettyLocation(status?.vault_path ?? null)}</p>
        <p className="muted small">
          Android chỉ cho đọc file trong một thời gian. Nếu “Tải bản mới” báo lỗi, chọn lại file — không cần nhập lại master password.
        </p>
        <button className="btn" onClick={onRepick}>
          Chọn lại file kho
        </button>
      </section>
      <section className="card">
        <h3>Công cụ</h3>
        <button className="btn" onClick={onOpenGenerator}>
          <Icon name="dice" /> Tạo mật khẩu
        </button>
      </section>
      <section className="card">
        <h3>Phiên bản</h3>
        <p className="small">pwv {version}</p>
        {update && (
          <button className="btn primary" onClick={() => api.openReleasePage(update.page_url)}>
            Tải bản {update.latest}
          </button>
        )}
        <button className="btn" onClick={checkUpdate}>
          Kiểm tra bản mới
        </button>
      </section>
    </div>
  );
}

/** URI content:// dài và khó đọc — rút gọn để hiển thị. */
function prettyLocation(loc: string | null): string {
  if (!loc) return "";
  if (!loc.includes("://")) return loc;
  try {
    const decoded = decodeURIComponent(loc);
    const provider = /dropbox/i.test(decoded) ? "Dropbox" : /google|drive/i.test(decoded) ? "Google Drive" : /onedrive|skydrive|microsoft/i.test(decoded) ? "OneDrive" : "Bộ nhớ";
    const name = decoded.split(/[/:]/).filter(Boolean).pop() ?? "vault.pwv";
    return `${provider} · ${name}`;
  } catch {
    return loc;
  }
}
