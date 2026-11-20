import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorText, onEvent, pickFile } from "./api";
import { EntryForm } from "./components/EntryForm";
import { EntryView } from "./components/EntryView";
import { Generator } from "./components/Generator";
import { Health } from "./components/Health";
import { SetupScreen, UnlockScreen } from "./components/Lock";
import { SettingsView } from "./components/SettingsView";
import { avatarHue, Icon, initials, useToast } from "./components/ui";
import type { EntrySummary, Status } from "./types";

type View =
  | { kind: "empty" }
  | { kind: "entry"; id: string }
  | { kind: "edit"; id: string | null }
  | { kind: "generator" }
  | { kind: "health" }
  | { kind: "settings" };

const SYNC_EVERY_MS = 20_000;
const TOUCH_EVERY_MS = 15_000;

export default function App() {
  const toast = useToast();
  const [status, setStatus] = useState<Status | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api.status());
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [toast]);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  // Backend tự khoá khi không dùng ⇒ quay về màn hình mở khoá.
  useEffect(() => {
    let off: (() => void) | undefined;
    onEvent("vault-locked", () => {
      toast("Đã tự khoá do không sử dụng", "info");
      refreshStatus();
    }).then((f) => (off = f));
    return () => off?.();
  }, [refreshStatus, toast]);

  async function switchVault() {
    const p = await pickFile({ title: "Chọn file kho (.pwv)", filters: [{ name: "Kho pwv", extensions: ["pwv"] }] });
    if (!p) return;
    await api.setVaultPath(p);
    refreshStatus();
  }

  if (!status) return null;
  if (!status.vault_path || !status.vault_exists) return <SetupScreen status={status} onDone={refreshStatus} />;
  if (!status.unlocked) return <UnlockScreen status={status} onUnlocked={refreshStatus} onChangeVault={switchVault} />;
  return <VaultScreen status={status} onLocked={refreshStatus} onSwitchVault={switchVault} />;
}

function VaultScreen({ status, onLocked, onSwitchVault }: { status: Status; onLocked: () => void; onSwitchVault: () => void }) {
  const toast = useToast();
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [view, setView] = useState<View>({ kind: "empty" });
  const [syncing, setSyncing] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  const reload = useCallback(async () => {
    try {
      setEntries(await api.list(query));
    } catch (e) {
      const msg = errorText(e);
      if (msg.includes("khoá")) onLocked();
      else toast(msg, "error");
    }
  }, [query, onLocked, toast]);

  useEffect(() => {
    reload();
  }, [reload]);

  const lock = useCallback(async () => {
    await api.lock();
    onLocked();
  }, [onLocked]);

  const sync = useCallback(
    async (manual: boolean) => {
      setSyncing(true);
      try {
        const r = await api.sync();
        if (r.changed) {
          toast(`Đã cập nhật từ máy khác: +${r.added} mới, ${r.updated} sửa, ${r.deleted} xoá`, "info");
          reload();
        } else if (manual) {
          toast("Đã đồng bộ — không có thay đổi mới");
        }
        if (r.conflicts_merged) toast(`Đã gộp ${r.conflicts_merged} bản xung đột từ dịch vụ đồng bộ`, "info");
        r.errors.forEach((e) => toast(e, "error"));
        if (r.password_changed_elsewhere) toast("Master password đã được đổi ở máy khác — lần sau hãy dùng mật khẩu mới", "info");
      } catch (e) {
        if (manual) toast(errorText(e), "error");
      } finally {
        setSyncing(false);
      }
    },
    [reload, toast],
  );

  // Kiểm tra thay đổi từ Google Drive định kỳ và khi cửa sổ được focus lại.
  useEffect(() => {
    const t = setInterval(() => sync(false), SYNC_EVERY_MS);
    const onFocus = () => sync(false);
    window.addEventListener("focus", onFocus);
    return () => {
      clearInterval(t);
      window.removeEventListener("focus", onFocus);
    };
  }, [sync]);

  // Báo cho backend biết người dùng đang hoạt động (để tính thời gian tự khoá).
  useEffect(() => {
    let last = 0;
    const onActivity = () => {
      const now = Date.now();
      if (now - last > TOUCH_EVERY_MS) {
        last = now;
        api.touch().catch(() => {});
      }
    };
    const evs = ["mousemove", "keydown", "mousedown", "wheel"];
    evs.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));
    return () => evs.forEach((e) => window.removeEventListener(e, onActivity));
  }, []);

  // Phím tắt: Ctrl+F tìm, Ctrl+N thêm, Ctrl+L khoá, Esc đóng.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key.toLowerCase() === "f") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.ctrlKey && e.key.toLowerCase() === "n") {
        e.preventDefault();
        setView({ kind: "edit", id: null });
      } else if (e.ctrlKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        lock();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lock]);

  const selectedId = view.kind === "entry" || view.kind === "edit" ? view.id : null;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <img src="/icon.svg" alt="" />
          <span>pwv</span>
        </div>
        <input
          ref={searchRef}
          className="search"
          type="search"
          placeholder="Tìm theo tên, tài khoản, trang web, nhóm…  (Ctrl+F)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && entries[0]) setView({ kind: "entry", id: entries[0].id });
            if (e.key === "Escape") setQuery("");
          }}
        />
        <nav className="actions">
          <button className="btn primary" onClick={() => setView({ kind: "edit", id: null })} title="Ctrl+N">
            <Icon name="plus" /> Thêm
          </button>
          <button className={view.kind === "generator" ? "icon-btn active" : "icon-btn"} onClick={() => setView({ kind: "generator" })} title="Tạo mật khẩu">
            <Icon name="dice" />
          </button>
          <button className={view.kind === "health" ? "icon-btn active" : "icon-btn"} onClick={() => setView({ kind: "health" })} title="Sức khoẻ mật khẩu">
            <Icon name="shield" />
          </button>
          <button className={syncing ? "icon-btn spinning" : "icon-btn"} onClick={() => sync(true)} title="Đồng bộ ngay">
            <Icon name="sync" />
          </button>
          <button className={view.kind === "settings" ? "icon-btn active" : "icon-btn"} onClick={() => setView({ kind: "settings" })} title="Cài đặt">
            <Icon name="gear" />
          </button>
          <button className="icon-btn" onClick={lock} title="Khoá (Ctrl+L)">
            <Icon name="lock" />
          </button>
        </nav>
      </header>

      {status.conflict_copies > 0 && (
        <div className="banner">
          Dịch vụ đồng bộ (Drive/Dropbox/OneDrive) đã tạo {status.conflict_copies} bản xung đột. <button className="btn link" onClick={() => sync(true)}>Gộp ngay</button>
        </div>
      )}

      <main className="main">
        <aside className="list" aria-label="Danh sách mục">
          {entries.length === 0 ? (
            <div className="list-empty">
              {query ? (
                <p>Không tìm thấy “{query}”.</p>
              ) : (
                <>
                  <p>Kho đang trống.</p>
                  <button className="btn primary" onClick={() => setView({ kind: "edit", id: null })}>
                    <Icon name="plus" /> Thêm mật khẩu đầu tiên
                  </button>
                  <button className="btn link" onClick={() => setView({ kind: "settings" })}>
                    hoặc nhập từ Chrome / Bitwarden…
                  </button>
                </>
              )}
            </div>
          ) : (
            <ul>
              {entries.map((e) => (
                <li key={e.id}>
                  <button className={selectedId === e.id ? "list-item selected" : "list-item"} onClick={() => setView({ kind: "entry", id: e.id })}>
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
            </ul>
          )}
          <div className="list-foot muted small">{entries.length} mục</div>
        </aside>

        <section className="pane">
          {view.kind === "empty" && (
            <div className="detail empty">
              <div className="hint">
                <img src="/icon.svg" alt="" />
                <p>Chọn một mục ở bên trái, hoặc bấm <strong>Thêm</strong> để lưu mật khẩu mới.</p>
                <p className="muted small">Ctrl+F tìm · Ctrl+N thêm · Ctrl+L khoá</p>
              </div>
            </div>
          )}
          {view.kind === "entry" && (
            <EntryView
              key={view.id}
              id={view.id}
              onEdit={() => setView({ kind: "edit", id: view.id })}
              onDeleted={() => {
                setView({ kind: "empty" });
                reload();
              }}
              onChanged={reload}
            />
          )}
          {view.kind === "edit" && (
            <EntryForm
              key={view.id ?? "new"}
              id={view.id}
              onCancel={() => setView(view.id ? { kind: "entry", id: view.id } : { kind: "empty" })}
              onSaved={(id) => {
                reload();
                setView({ kind: "entry", id });
              }}
            />
          )}
          {view.kind === "generator" && (
            <div className="detail">
              <header className="detail-head">
                <h2 className="grow">Tạo mật khẩu</h2>
              </header>
              <div className="fields">
                <Generator />
              </div>
            </div>
          )}
          {view.kind === "health" && <Health onOpen={(id) => setView({ kind: "entry", id })} />}
          {view.kind === "settings" && <SettingsView status={status} onImported={reload} onSwitchVault={onSwitchVault} />}
        </section>
      </main>
    </div>
  );
}
