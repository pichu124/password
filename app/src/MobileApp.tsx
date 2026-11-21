// Giao diện điện thoại (Android): chỉ xem + sao chép. Thêm/sửa làm trên máy tính.
import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorCode, errorText, isReloading, lockAndReload, onEvent, onSessionLost, pickFile, reloadPage, STASHED_LOCK_NOTE } from "./api";
import { EntryView } from "./components/EntryView";
import { Generator } from "./components/Generator";
import { avatarHue, formatDateTime, Icon, initials, useClipboardGuard, useToast } from "./components/ui";
import type { AppError, EntrySummary, Settings, Status, UpdateInfo } from "./types";

/** Khoá ngay khi app bị đưa xuống nền quá lâu (ví dụ chuyển sang app khác rồi quên). */
const LOCK_WHEN_HIDDEN_MS = 60_000;

type Screen = { kind: "list" } | { kind: "detail"; id: string } | { kind: "settings" } | { kind: "generator" };

// Lý do khoá do trang trước để lại (dùng khi backend không tự ghi lý do, ví dụ lỗi "kho đã bị khoá").
const STASHED_NOTE = STASHED_LOCK_NOTE;

let pageLoaded: Promise<void> | null = null;
/** Trang mới trên điện thoại ⇒ backend khoá lại cho chắc (Android có thể vừa dựng lại WebView). */
const pageLoadedOnce = () => (pageLoaded ??= api.pageLoaded().catch(() => {}));

async function chooseVaultFile(): Promise<string | null> {
  // Bộ chọn riêng giữ quyền đọc file LÂU DÀI (bộ chọn thường chỉ cho quyền tạm thời, mất khi Android
  // đóng app ⇒ lần sau phải dùng bản đã lưu). Không có thì lùi về bộ chọn thường.
  try {
    const r = await api.pickVaultFile();
    return r.uri ?? null;
  } catch {
    // Không lọc theo đuôi file: trên Android bộ lọc theo đuôi .pwv thường làm ẩn mất file.
    return pickFile({ title: "Chọn file vault.pwv", filters: [] });
  }
}

export default function MobileApp() {
  const toast = useToast();
  const [status, setStatus] = useState<Status | null>(null);
  const [cacheNote, setCacheNote] = useState<string | null>(null);
  useClipboardGuard();

  const refresh = useCallback(async () => {
    try {
      await pageLoadedOnce();
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
    let alive = true;
    onEvent("vault-locked", (reason) => {
      reloadPage(reason === "suspend" ? "Kho đã tự khoá vì app bị tạm dừng." : "Kho đã tự khoá do không sử dụng.");
    }).then((f) => {
      if (alive) off = f;
      else f();
    });
    // Mật khẩu chính đã đổi trên máy tính / kho đã khoá ⇒ về màn hình mở khoá (nạp lại trang).
    onSessionLost((e: AppError) =>
      reloadPage(e.code === "password_changed" ? `${e.message.replace(/[.\s]*$/, ".")} Hãy nhập mật khẩu chính MỚI (mật khẩu bạn vừa đặt trên máy tính).` : "Kho đã bị khoá."),
    );
    return () => {
      alive = false;
      off?.();
      onSessionLost(null);
    };
  }, []);

  if (!status) return null;
  if (!status.vault_configured || !status.vault_path) return <MobileSetup onDone={refresh} />;
  if (!status.unlocked)
    return (
      <MobileUnlock
        status={status}
        note={status.lock_note ?? STASHED_NOTE}
        onDone={(note) => {
          setCacheNote(note);
          refresh();
        }}
        onFileChanged={refresh}
      />
    );
  return <MobileVault status={status} cacheNote={cacheNote} clearCacheNote={() => setCacheNote(null)} onStatus={refresh} />;
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
          <li>
            Bấm nút bên dưới, chọn dịch vụ đó trong danh sách bên trái, rồi chọn file <code>vault.pwv</code>.
          </li>
        </ol>
        <button className="btn primary wide" onClick={choose}>
          Chọn file kho
        </button>
        <p className="muted small">Điện thoại chỉ đọc file kho, không bao giờ ghi vào — kho trên máy tính luôn an toàn.</p>
      </div>
    </div>
  );
}

function MobileUnlock({
  status,
  note,
  onDone,
  onFileChanged,
}: {
  status: Status;
  note: string | null;
  onDone: (cacheNote: string | null) => void;
  onFileChanged: () => void;
}) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; text: string } | null>(null);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => ref.current?.focus(), []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!pw || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.openReadonly(pw);
      setPw("");
      onDone(r.from_cache ? r.note ?? "Không đọc được file kho mới — đang dùng bản đã lưu trên máy." : null);
    } catch (err) {
      const code = errorCode(err);
      setError({ code, text: errorText(err) });
      // Không đọc được file: giữ mật khẩu để chọn lại file rồi mở luôn.
      if (code !== "read_failed") setPw("");
    } finally {
      setBusy(false);
    }
  }

  async function changeFile() {
    const p = await chooseVaultFile();
    if (!p) return;
    try {
      await api.setVaultPath(p);
      setError(null);
      onFileChanged();
    } catch (e) {
      setError({ code: errorCode(e), text: errorText(e) });
    }
  }

  return (
    <div className="m-center">
      <form className="m-card" onSubmit={submit}>
        <img src="/icon.svg" alt="" className="lock-logo" />
        <h1>Mở khoá</h1>
        <p className="muted small m-path">{prettyLocation(status.vault_path)}</p>
        {note && <div className="note-box">{note}</div>}
        <input
          ref={ref}
          type="password"
          placeholder="Mật khẩu chính"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          disabled={busy}
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          data-secret
          aria-label="Mật khẩu chính"
        />
        {error?.code === "read_failed" ? (
          <div className="problem-box">
            <p>{error.text}</p>
            <p className="small muted">Android có thể đã hết quyền đọc file. Chọn lại đúng file vault.pwv rồi bấm “Mở khoá”.</p>
            <button type="button" className="btn primary wide" onClick={changeFile}>
              Chọn lại file kho
            </button>
          </div>
        ) : error?.code === "password_changed" ? (
          <div className="problem-box">
            <p>
              <strong>Mật khẩu chính đã được đổi trên máy tính.</strong> Hãy nhập mật khẩu chính MỚI.
            </p>
            <p className="small muted">{error.text}</p>
          </div>
        ) : (
          error && <p className="error">{error.text}</p>
        )}
        <button className="btn primary wide" disabled={busy || !pw}>
          {busy ? "Đang giải mã…" : "Mở khoá"}
        </button>
        {error?.code !== "read_failed" && (
          <button type="button" className="btn link" onClick={changeFile}>
            Chọn file kho khác
          </button>
        )}
      </form>
    </div>
  );
}

function MobileVault({ status, cacheNote, clearCacheNote, onStatus }: { status: Status; cacheNote: string | null; clearCacheNote: () => void; onStatus: () => void }) {
  const toast = useToast();
  const [screen, setScreen] = useState<Screen>({ kind: "list" });
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [reloading, setReloading] = useState(false);
  const [repickReason, setRepickReason] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setEntries(await api.list(query));
    } catch (e) {
      if (!isReloading()) toast(errorText(e), "error");
    }
  }, [query, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const lock = useCallback((note?: string) => lockAndReload(note), []);

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
      else if (hiddenAt && Date.now() - hiddenAt > LOCK_WHEN_HIDDEN_MS) lock("Kho đã tự khoá vì app nằm ở nền quá 1 phút.");
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
      setRepickReason(null);
      clearCacheNote();
      toast(changed ? "Đã nạp dữ liệu mới từ file kho" : "Không có thay đổi mới trong file kho");
      load();
      onStatus();
    } catch (e) {
      const code = errorCode(e);
      if (code === "read_failed") setRepickReason(errorText(e));
      else if (code !== "password_changed" && code !== "locked") toast(errorText(e), "error");
      // password_changed / locked: xử lý chung ⇒ nạp lại trang về màn hình mở khoá.
    } finally {
      setReloading(false);
    }
  }

  async function repick() {
    const p = await chooseVaultFile();
    if (!p) return;
    try {
      await api.repickReadonly(p);
      setRepickReason(null);
      clearCacheNote();
      toast("Đã nạp file kho");
      load();
      onStatus();
    } catch (e) {
      const code = errorCode(e);
      if (code === "read_failed") setRepickReason(errorText(e));
      if (code !== "password_changed" && code !== "locked") toast(errorText(e), "error");
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
          <button className="icon-btn" onClick={() => lock()} aria-label="Khoá">
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
          <Generator recordable={false} />
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
          <MobileSettings status={status} onRepick={repick} onOpenGenerator={() => setScreen({ kind: "generator" })} />
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
        <button className={reloading ? "icon-btn spinning" : "icon-btn"} onClick={reload} aria-label="Nạp lại file kho" disabled={reloading}>
          <Icon name="sync" />
        </button>
        <button className="icon-btn" onClick={() => setScreen({ kind: "settings" })} aria-label="Cài đặt">
          <Icon name="gear" />
        </button>
        <button className="icon-btn" onClick={() => lock()} aria-label="Khoá">
          <Icon name="lock" />
        </button>
      </header>
      <div className="m-search">
        <input type="search" placeholder="Tìm theo tên, tài khoản, trang web…" value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" spellCheck={false} />
        <div className="m-updated muted small">Dữ liệu cập nhật lúc {formatDateTime(status.modified_at)}</div>
      </div>
      {repickReason && (
        <div className="banner danger m-banner">
          <div className="banner-body">
            Không đọc được file kho. <span className="muted small">{repickReason}</span>
          </div>
          <button className="btn primary" onClick={repick}>
            Chọn lại file
          </button>
        </div>
      )}
      {cacheNote && !repickReason && (
        <div className="banner m-banner">
          <div className="banner-body">
            Đang dùng bản đã lưu trên điện thoại. <span className="muted small">{cacheNote}</span> Bấm ⟳ để thử nạp lại file kho.
          </div>
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
                <span className="item-sub">{e.username || e.url || " "}</span>
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

function MobileSettings({ status, onRepick, onOpenGenerator }: { status: Status; onRepick: () => void; onOpenGenerator: () => void }) {
  const toast = useToast();
  const [s, setS] = useState<Settings | null>(null);
  const [version, setVersion] = useState("");
  const [update, setUpdate] = useState<UpdateInfo | null>(null);

  useEffect(() => {
    api.getSettings().then(setS).catch((e) => toast(errorText(e), "error"));
    api.appVersion().then(setVersion).catch(() => {});
  }, [toast]);

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

  const lockChoices = [1, 2, 5, 10, 15];
  const clipChoices = [10, 20, 30, 60];
  return (
    <div className="m-settings">
      {s && (
        <section className="card">
          <h3>Bảo mật</h3>
          <label className="field">
            <span>Tự khoá sau khi không dùng</span>
            <select value={s.auto_lock_minutes} onChange={(e) => save({ ...s, auto_lock_minutes: Number(e.target.value) })}>
              {(lockChoices.includes(s.auto_lock_minutes) ? lockChoices : [...lockChoices, s.auto_lock_minutes]).map((m) => (
                <option key={m} value={m}>
                  {m === 0 ? "Không tự khoá" : `${m} phút`}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Tự xoá clipboard sau</span>
            <select value={s.clipboard_clear_secs} onChange={(e) => save({ ...s, clipboard_clear_secs: Number(e.target.value) })}>
              {(clipChoices.includes(s.clipboard_clear_secs) ? clipChoices : [...clipChoices, s.clipboard_clear_secs]).map((x) => (
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
        <p className="small m-path">{prettyLocation(status.vault_path)}</p>
        <p className="small">Dữ liệu cập nhật lúc {formatDateTime(status.modified_at)}</p>
        <p className="muted small">
          Android chỉ cho đọc file trong một thời gian. Nếu nút ⟳ báo không đọc được file, hãy chọn lại file — không cần nhập lại mật khẩu chính.
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
          <button className="btn primary" onClick={() => api.openReleasePage(update.latest).catch((e) => toast(errorText(e), "error"))}>
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
    const name = decoded.split(/[/:=]/).filter(Boolean).pop() ?? "vault.pwv";
    return `${provider} · ${name}`;
  } catch {
    return loc;
  }
}
