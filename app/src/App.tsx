import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorCode, errorText, isReloading, lockAndReload, onDiskProblem, onEvent, onSessionLost, pickFile, reloadPage, stashForReload, takeStashed } from "./api";
import { EntryForm } from "./components/EntryForm";
import { EntryView } from "./components/EntryView";
import { Generator } from "./components/Generator";
import { Health } from "./components/Health";
import { FirstRunScreen, NotFoundScreen, UnlockScreen } from "./components/Lock";
import { MoveVault, moveMessage } from "./components/MoveVault";
import { SettingsView } from "./components/SettingsView";
import { Trash } from "./components/Trash";
import { avatarHue, ConfirmBox, formatDateTime, Icon, initials, useClipboardGuard, useToast } from "./components/ui";
import type { AppError, EntrySummary, MoveView, RollbackView, Status, SyncResult, UnlockInfo, UpdateInfo } from "./types";

type View =
  | { kind: "empty" }
  | { kind: "entry"; id: string }
  | { kind: "edit"; id: string | null }
  | { kind: "generator" }
  | { kind: "health" }
  | { kind: "trash" }
  | { kind: "settings" };

const SYNC_EVERY_MS = 20_000;
const UPDATE_CHECK_EVERY_MS = 24 * 60 * 60 * 1000;
const TOUCH_EVERY_MS = 15_000;

// Thông tin (không bí mật) mà trang trước để lại trước khi nạp lại: lý do khoá, kết quả mở khoá.
// Đọc một lần khi nạp module (StrictMode chạy effect hai lần).
const STASHED_NOTE = takeStashed<string>("lock-note");
const STASHED_UNLOCK = takeStashed<UnlockInfo>("unlock-info");

let pageLoaded: Promise<void> | null = null;
/** Báo backend trang vừa được nạp — đúng một lần cho mỗi lần nạp trang. */
const pageLoadedOnce = () => (pageLoaded ??= api.pageLoaded().catch(() => {}));

/** Kiểm tra bản mới khi mở app và mỗi 24 giờ (nếu người dùng bật trong Cài đặt). */
function useUpdateCheck(): UpdateInfo | null {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  useEffect(() => {
    let alive = true;
    const run = async () => {
      try {
        const s = await api.getSettings();
        if (!s.check_updates) return;
        const u = await api.checkUpdate();
        if (alive && u?.available) setInfo(u);
      } catch {
        /* mất mạng hoặc GitHub lỗi: thử lại lần sau, không làm phiền người dùng */
      }
    };
    const first = setTimeout(run, 4000);
    const every = setInterval(run, UPDATE_CHECK_EVERY_MS);
    return () => {
      alive = false;
      clearTimeout(first);
      clearInterval(every);
    };
  }, []);
  return info;
}

export default function App() {
  const toast = useToast();
  const [status, setStatus] = useState<Status | null>(null);
  const [forceMissing, setForceMissing] = useState(false);
  const [unlockInfo, setUnlockInfo] = useState<UnlockInfo | null>(STASHED_UNLOCK);
  const update = useUpdateCheck();
  useClipboardGuard();

  const refreshStatus = useCallback(async () => {
    try {
      await pageLoadedOnce();
      const s = await api.status();
      setStatus(s);
      if (s.vault_exists) setForceMissing(false);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [toast]);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  // Kho bị khoá ở backend (tự khoá khi không dùng, máy ngủ, hoặc một lệnh báo "đã khoá" / "mật khẩu đã
  // đổi ở máy khác") ⇒ nạp lại trang để WebView vứt bỏ mọi bí mật còn trong bộ nhớ JavaScript.
  useEffect(() => {
    let off: (() => void) | undefined;
    let alive = true;
    onEvent("vault-locked", (reason) => {
      reloadPage(reason === "suspend" ? "Kho đã tự khoá vì máy vừa ngủ hoặc app bị tạm dừng." : "Kho đã tự khoá do không sử dụng.");
    }).then((f) => {
      if (alive) off = f;
      else f();
    });
    onSessionLost((e: AppError) => reloadPage(e.code === "password_changed" ? e.message : "Kho đã bị khoá."));
    return () => {
      alive = false;
      off?.();
      onSessionLost(null);
    };
  }, []);

  /** Mở khoá xong: nạp lại trang (xoá mật khẩu chính khỏi bộ nhớ JavaScript), mang theo kết quả mở khoá. */
  const afterUnlock = useCallback(
    (info: UnlockInfo | null) => {
      if (info === null || stashForReload("unlock-info", info)) {
        reloadPage();
        return;
      }
      setUnlockInfo(info);
      refreshStatus();
    },
    [refreshStatus],
  );

  async function switchVault() {
    const p = await pickFile({ title: "Chọn file kho (.pwv)", filters: [{ name: "Kho pwv", extensions: ["pwv"] }] });
    if (!p) return;
    try {
      await api.setVaultPath(p);
      reloadPage();
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  if (!status) return null;
  const note = status.lock_note ?? STASHED_NOTE;
  if (!status.vault_configured) return <FirstRunScreen onDone={refreshStatus} onCreated={() => afterUnlock(null)} />;
  if (!status.unlocked && (!status.vault_exists || forceMissing))
    return <NotFoundScreen status={status} note={note} onRetry={refreshStatus} onRecovered={() => afterUnlock(null)} />;
  if (!status.unlocked)
    return (
      <UnlockScreen
        status={status}
        note={note}
        onUnlocked={afterUnlock}
        onRecovered={() => afterUnlock(null)}
        onChangeVault={switchVault}
        onMissing={() => {
          setForceMissing(true);
          refreshStatus();
        }}
      />
    );
  return <VaultScreen status={status} update={update} unlockInfo={unlockInfo} onStatusChange={refreshStatus} onSwitchVault={switchVault} />;
}

// ------------------------------------------------------------------ thông báo cố định

interface Notice {
  text: string;
  kind: "error" | "warn" | "info";
}

/** Danh sách thông báo cố định, bỏ trùng theo nội dung; đã đóng thì không hiện lại trong phiên này. */
function useNotices() {
  const [notices, setNotices] = useState<Notice[]>([]);
  const dismissed = useRef(new Set<string>());
  const add = useCallback((text: string, kind: Notice["kind"]) => {
    if (dismissed.current.has(text)) return;
    setNotices((cur) => (cur.some((n) => n.text === text) ? cur : [...cur, { text, kind }]));
  }, []);
  const dismiss = useCallback((text: string) => {
    dismissed.current.add(text);
    setNotices((cur) => cur.filter((n) => n.text !== text));
  }, []);
  return { notices, add, dismiss };
}

// ------------------------------------------------------------------ màn hình chính

function VaultScreen({
  status,
  update,
  unlockInfo,
  onStatusChange,
  onSwitchVault,
}: {
  status: Status;
  update: UpdateInfo | null;
  unlockInfo: UnlockInfo | null;
  onStatusChange: () => void;
  onSwitchVault: () => void;
}) {
  const toast = useToast();
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [view, setView] = useState<View>({ kind: "empty" });
  const [syncing, setSyncing] = useState(false);
  const [updateDismissed, setUpdateDismissed] = useState(false);
  const [problem, setProblem] = useState<AppError | null>(status.disk_problem);
  const [rollback, setRollback] = useState<RollbackView | null>(unlockInfo?.rollback ?? null);
  const { notices, add: addNotice, dismiss } = useNotices();
  const searchRef = useRef<HTMLInputElement>(null);
  const syncBusy = useRef(false);

  // Mỗi lần đọc lại status: vấn đề với file kho hiện / mất theo đúng status.
  useEffect(() => {
    setProblem(status.disk_problem);
  }, [status]);

  // Lệnh nào báo file kho có vấn đề ⇒ hiện ngay cảnh báo cố định.
  useEffect(() => {
    onDiskProblem((e) => setProblem(e));
    return () => onDiskProblem(null);
  }, []);

  const reload = useCallback(async () => {
    try {
      setEntries(await api.list(query));
    } catch (e) {
      if (!isReloading()) toast(errorText(e), "error");
    }
  }, [query, toast]);

  useEffect(() => {
    reload();
  }, [reload]);

  const lock = useCallback(() => lockAndReload(), []);

  const applySync = useCallback(
    (r: SyncResult, manual: boolean) => {
      setProblem(r.problem);
      if (r.changed) {
        toast(`Đã cập nhật từ máy khác: +${r.added} mới, ${r.updated} sửa, ${r.deleted} xoá`, "info");
        reload();
        onStatusChange();
      } else if (manual && !r.problem) {
        toast("Đã đồng bộ — không có thay đổi mới");
      }
      if (r.conflicts_merged) toast(`Đã gộp ${r.conflicts_merged} bản xung đột từ dịch vụ đồng bộ`, "info");
      r.errors.forEach((e) => addNotice(`Bản xung đột chưa gộp được: ${e}`, "error"));
      if (r.backup_failed) addNotice("Lần ghi vừa rồi không tạo được bản sao lưu tự động (thư mục sao lưu bị đầy hoặc không ghi được). Dữ liệu vẫn được lưu.", "warn");
      if (r.password_changed_elsewhere) addNotice("Mật khẩu chính đã được đổi ở máy khác — lần sau hãy mở khoá bằng mật khẩu MỚI.", "info");
    },
    [toast, reload, addNotice, onStatusChange],
  );

  // Kết quả lần mở khoá vừa rồi.
  const unlockShown = useRef(false);
  useEffect(() => {
    if (!unlockInfo || unlockShown.current) return;
    unlockShown.current = true;
    if (unlockInfo.rescued > 0)
      addNotice(
        `Đã khôi phục những thay đổi chưa kịp lưu của lần dùng trước (${unlockInfo.rescued} bản cứu hộ) và gộp lại vào kho. Hãy xem lại các mục bạn sửa gần đây.`,
        "info",
      );
    applySync(unlockInfo.sync, false);
  }, [unlockInfo, addNotice, applySync]);

  const sync = useCallback(
    async (manual: boolean) => {
      if (syncBusy.current) return;
      syncBusy.current = true;
      setSyncing(true);
      try {
        applySync(await api.sync(), manual);
      } catch (e) {
        // "Đã khoá" / "mật khẩu đổi ở máy khác" ⇒ xử lý chung (nạp lại trang). Lỗi khác: không nuốt mất.
        const code = errorCode(e);
        if (code !== "locked" && code !== "password_changed") {
          addNotice(`Đồng bộ không thành công: ${errorText(e)}`, "error");
          if (manual) toast(errorText(e), "error");
        }
      } finally {
        syncBusy.current = false;
        setSyncing(false);
      }
    },
    [applySync, addNotice, toast],
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

  // Phím tắt: Ctrl+F tìm, Ctrl+N thêm, Ctrl+L khoá.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      const k = e.key.toLowerCase();
      if (k === "f") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (k === "n") {
        e.preventDefault();
        setView({ kind: "edit", id: null });
      } else if (k === "l") {
        e.preventDefault();
        lock();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lock]);

  async function acceptRollback() {
    try {
      await api.acceptRollback();
      setRollback(null);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  function afterMove(r: MoveView) {
    if (r.rescued) addNotice(moveMessage(r), "info");
    else toast(moveMessage(r), r.old_removed ? "ok" : "info");
    setProblem(null);
    onStatusChange();
  }

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
          autoComplete="off"
          spellCheck={false}
          onKeyDown={(e) => {
            if (e.key === "Enter" && entries[0]) setView({ kind: "entry", id: entries[0].id });
            if (e.key === "Escape") setQuery("");
          }}
        />
        {status.auto_lock_minutes === 0 && (
          <button className="pill warn" onClick={() => setView({ kind: "settings" })} title="Bật lại trong Cài đặt → Bảo mật">
            Tự khoá đang tắt
          </button>
        )}
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
          <button className={view.kind === "trash" ? "icon-btn active with-count" : "icon-btn with-count"} onClick={() => setView({ kind: "trash" })} title={`Thùng rác (${status.trash_count})`}>
            <Icon name="trash" />
            {status.trash_count > 0 && <span className="count">{status.trash_count}</span>}
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

      {problem && <DiskProblemBanner problem={problem} status={status} onRetry={() => sync(true)} onResolved={() => { setProblem(null); onStatusChange(); }} onMoved={afterMove} />}

      {rollback && (
        <div className="banner danger">
          <div className="banner-body">
            <strong>File kho đang mở CŨ HƠN bản mà máy này từng thấy.</strong> File được sửa lần cuối lúc {formatDateTime(rollback.file_modified_at)}, trong
            khi máy này đã thấy bản lúc {formatDateTime(rollback.seen_modified_at)}.
            {rollback.older_password && <> File này còn dùng một mật khẩu chính CŨ hơn mật khẩu hiện tại.</>} Có thể dịch vụ đồng bộ đã khôi phục một
            bản cũ — những mục thêm hoặc sửa gần đây có thể bị thiếu. Nếu thiếu, xem <button className="btn link" onClick={() => setView({ kind: "settings" })}>Cài đặt → Sao lưu &amp; khôi phục</button>.
          </div>
          <button className="btn" onClick={acceptRollback}>
            Đã hiểu
          </button>
        </div>
      )}

      {notices.map((n) => (
        <div key={n.text} className={`banner ${n.kind === "info" ? "info" : n.kind === "error" ? "danger" : ""}`}>
          <div className="banner-body">{n.text}</div>
          <button className="icon-btn small-btn" onClick={() => dismiss(n.text)} title="Đóng thông báo" aria-label="Đóng thông báo">
            <Icon name="close" size={16} />
          </button>
        </div>
      ))}

      {update && !updateDismissed && (
        <div className="banner info">
          <div className="banner-body">
            Có phiên bản mới <strong>{update.latest}</strong> (bạn đang dùng {update.current}).{" "}
            <button className="btn link" onClick={() => api.openReleasePage(update.latest).catch((e) => toast(errorText(e), "error"))}>
              Mở trang tải
            </button>{" "}
            <button className="btn link muted-link" onClick={() => setUpdateDismissed(true)}>
              Để sau
            </button>
          </div>
        </div>
      )}
      {status.conflict_copies > 0 && (
        <div className="banner">
          <div className="banner-body">
            Dịch vụ đồng bộ (Drive/Dropbox/OneDrive) đã tạo {status.conflict_copies} bản xung đột.{" "}
            <button className="btn link" onClick={() => sync(true)}>
              Gộp ngay
            </button>
          </div>
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
                      <span className="item-sub">{e.username || e.url || " "}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="list-foot muted small">
            <span className="grow">{entries.length} mục</span>
            <button className="btn link" onClick={() => setView({ kind: "trash" })}>
              Thùng rác ({status.trash_count})
            </button>
          </div>
        </aside>

        <section className="pane">
          {view.kind === "empty" && (
            <div className="detail empty">
              <div className="hint">
                <img src="/icon.svg" alt="" />
                <p>
                  Chọn một mục ở bên trái, hoặc bấm <strong>Thêm</strong> để lưu mật khẩu mới.
                </p>
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
                onStatusChange();
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
                onStatusChange();
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
          {view.kind === "trash" && (
            <Trash
              onChanged={() => {
                reload();
                onStatusChange();
              }}
            />
          )}
          {view.kind === "settings" && (
            <SettingsView
              status={status}
              onImported={() => {
                reload();
                onStatusChange();
              }}
              onSwitchVault={onSwitchVault}
              onMoved={afterMove}
              onChanged={onStatusChange}
            />
          )}
        </section>
      </main>
    </div>
  );
}

// ------------------------------------------------------------------ cảnh báo file kho

/** Cảnh báo cố định khi file kho trên đĩa có vấn đề. Không bao giờ tự ghi đè: người dùng quyết định. */
function DiskProblemBanner({
  problem,
  status,
  onRetry,
  onResolved,
  onMoved,
}: {
  problem: AppError;
  status: Status;
  onRetry: () => void;
  onResolved: () => void;
  onMoved: (r: MoveView) => void;
}) {
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);

  async function forceWrite() {
    setBusy(true);
    try {
      const archived = await api.forceWrite();
      toast(archived ? `Đã ghi bản đang mở vào file kho. File hỏng được cất ở: ${archived}` : "Đã ghi bản đang mở vào file kho");
      setConfirm(false);
      onResolved();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const code = problem.code;
  const title =
    code === "file_damaged"
      ? "File kho trên đĩa bị hỏng hoặc chưa tải xong."
      : code === "file_missing"
        ? "File kho không còn ở vị trí cũ."
        : code === "different_vault"
          ? "Ở vị trí file kho giờ là một kho KHÁC."
          : code === "unsupported_version"
            ? "File kho trên đĩa được ghi bởi phiên bản app mới hơn."
            : "File kho trên đĩa đang có vấn đề.";
  const explain =
    code === "file_damaged"
      ? "Những gì bạn đang thấy là bản đang mở trên máy này. Chưa có thay đổi mới nào được ghi ra đĩa."
      : code === "file_missing"
        ? "Có thể dịch vụ đồng bộ đang tải lại file, hoặc kho đã được chuyển đi ở máy khác. Thay đổi mới chưa được ghi ra đĩa."
        : "App sẽ không ghi đè lên file đó. Hãy lưu bản đang mở sang một vị trí khác để không mất dữ liệu.";
  const canOverwrite = code === "file_damaged" || code === "file_missing";

  return (
    <div className="banner danger problem-banner" role="alert">
      <div className="banner-body">
        <strong>
          <Icon name="warn" size={16} /> {title}
        </strong>{" "}
        {explain}
        <div className="muted small">{problem.message}</div>
        {confirm && (
          <ConfirmBox
            danger={code === "file_damaged"}
            busy={busy}
            text={
              code === "file_damaged" ? (
                <>
                  Ghi bản đang mở trên máy này đè lên file kho hỏng? File hỏng sẽ được cất vào thư mục sao lưu (không bị xoá). Chỉ làm vậy nếu bạn chắc dịch
                  vụ đồng bộ đã tải xong.
                </>
              ) : (
                <>
                  Tạo lại file kho ở <span className="path">{status.vault_path}</span> từ bản đang mở? Nếu kho đã được chuyển sang thư mục khác ở máy kia, hãy
                  chọn “Chọn vị trí khác…” thay vì tạo lại ở đây.
                </>
              )
            }
            confirmLabel={code === "file_damaged" ? "Ghi đè" : "Tạo lại file"}
            onConfirm={forceWrite}
            onCancel={() => setConfirm(false)}
          />
        )}
        {!confirm && (
          <div className="row gap banner-actions">
            {canOverwrite && (
              <button className="btn" onClick={onRetry} disabled={busy}>
                <Icon name="sync" /> Thử lại
              </button>
            )}
            {canOverwrite && (
              <button className="btn" onClick={() => setConfirm(true)} disabled={busy}>
                {code === "file_damaged" ? "Ghi đè bằng bản đang mở" : "Tạo lại file ở đây"}
              </button>
            )}
            <MoveVault
              status={status}
              rescue
              onMoved={onMoved}
              label={code === "file_damaged" ? "Lưu sang vị trí khác…" : code === "file_missing" ? "Chọn vị trí khác…" : "Lưu bản đang mở sang vị trí khác…"}
              buttonClass={canOverwrite ? "btn" : "btn primary"}
            />
          </div>
        )}
      </div>
    </div>
  );
}
