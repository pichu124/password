import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorCode, errorText, isReloading, lockAndReload, onDiskProblem, onEvent, onSessionLost, onWriteResult, reloadPage, STASHED_LOCK_NOTE, STASHED_UNLOCK_INFO, stashForReload } from "./api";
import { EMPTY_FIELDS, EntryForm, type EntryFormHandle, parseDraft, type Restore } from "./components/EntryForm";
import { EntryView } from "./components/EntryView";
import { Generator } from "./components/Generator";
import { Health } from "./components/Health";
import { FirstRunScreen, NotFoundScreen, UnlockScreen } from "./components/Lock";
import { MoveVault, moveMessage } from "./components/MoveVault";
import { SettingsView } from "./components/SettingsView";
import { Trash } from "./components/Trash";
import { avatarHue, ConfirmBox, formatDateTime, Icon, initials, useClipboardGuard, useToast } from "./components/ui";
import { useVaultChooser } from "./components/VaultChooser";
import type { AppError, EntrySummary, MoveView, RollbackView, Status, SyncResult, UnlockInfo, UpdateInfo } from "./types";

type View =
  | { kind: "empty" }
  | { kind: "entry"; id: string }
  /** `restore`: bản nháp giữ từ trước khi kho bị khoá. */
  | { kind: "edit"; id: string | null; restore?: Restore; nonce?: number }
  | { kind: "generator" }
  | { kind: "health" }
  | { kind: "trash" }
  /** `section`: cuộn tới mục đó khi mở (ví dụ từ thông báo "bản ghi bằng mật khẩu cũ"). */
  | { kind: "settings"; section?: "backups" | "master"; at?: number };

const SYNC_EVERY_MS = 20_000;
const UPDATE_CHECK_EVERY_MS = 24 * 60 * 60 * 1000;
const TOUCH_EVERY_MS = 15_000;

/** Ghi xong nhưng chưa đọc lại kiểm tra được (SyncResult.unverified). */
const UNVERIFIED_TEXT =
  "Đã lưu, nhưng chưa kiểm tra lại được file vừa ghi (có thể chương trình đồng bộ hoặc diệt virus đang giữ file). App sẽ tự kiểm tra lại ở lần đồng bộ tới.";

// Thông tin (không bí mật) mà trang trước để lại trước khi nạp lại: lý do khoá, kết quả mở khoá.
const STASHED_NOTE = STASHED_LOCK_NOTE;
const STASHED_UNLOCK = STASHED_UNLOCK_INFO;

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
      // "close": cửa sổ vừa được đóng (app ẩn chờ xoá clipboard rồi thoát) — chỉ cần vứt bí mật, không cần lời nhắn.
      if (reason === "close") reloadPage();
      else reloadPage(reason === "suspend" ? "Kho đã tự khoá vì máy vừa ngủ hoặc app bị tạm dừng." : "Kho đã tự khoá do không sử dụng.");
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

  /**
   * Mở khoá xong: nạp lại trang (xoá mật khẩu chính khỏi bộ nhớ JavaScript), mang theo kết quả mở khoá. Bản nháp (có
   * thể chứa mật khẩu) KHÔNG đi qua sessionStorage: trang sau tự hỏi backend (`get_draft`).
   */
  const afterUnlock = useCallback(
    (info: UnlockInfo | null) => {
      if (info === null || stashForReload("unlock-info", { ...info, draft: null })) {
        reloadPage();
        return;
      }
      setUnlockInfo(info);
      refreshStatus();
    },
    [refreshStatus],
  );

  // Chọn một file kho có sẵn (kể cả khi kho đang mở: ghi nhớ đường dẫn rồi khoá ⇒ màn hình mở khoá của file đó).
  const chooser = useVaultChooser(async (p) => {
    await api.setVaultPath(p);
    reloadPage();
  });
  useEffect(() => {
    if (chooser.error) toast(chooser.error, "error");
  }, [chooser.error, toast]);
  const switchVault = chooser.choose;

  if (!status) return null;
  const note = status.lock_note ?? STASHED_NOTE;
  if (!status.vault_configured) return <FirstRunScreen onDone={refreshStatus} onCreated={() => afterUnlock(null)} />;
  if (!status.unlocked && (!status.vault_exists || forceMissing))
    return <NotFoundScreen status={status} note={note} onRetry={refreshStatus} onRecovered={() => afterUnlock(null)} />;
  if (!status.unlocked)
    return (
      <>
      {chooser.box}
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
      </>
    );
  return (
    <>
      {chooser.box}
      <VaultScreen status={status} update={update} unlockInfo={unlockInfo} onStatusChange={refreshStatus} onSwitchVault={switchVault} />
    </>
  );
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
  const [view, setViewState] = useState<View>({ kind: "empty" });
  // Mỗi lần vào form là một form MỚI (khoá component có `nonce`): "Bỏ thay đổi" rồi mở lại cùng form luôn được một form
  // sạch, đang giữ bản nháp bình thường — không bao giờ là form cũ đã đóng.
  const nonce = useRef(0);
  const setViewRaw = useCallback((v: View) => setViewState(v.kind === "edit" ? { ...v, nonce: ++nonce.current } : v), []);
  const [syncing, setSyncing] = useState(false);
  /** Đổi ⇒ mục đang mở được tải lại (đồng bộ vừa đổi dữ liệu, vừa khôi phục từ sao lưu). */
  const [refreshKey, setRefreshKey] = useState(0);
  const [rekey, setRekey] = useState(status.rekey_advised);
  const [rekeyLater, setRekeyLater] = useState(false);
  // Form đang sửa dở: rời đi (bấm mục khác, Ctrl+N, nút trên thanh công cụ…) phải hỏi trước. Khoá thì không bao giờ hỏi.
  const formDirty = useRef(false);
  const formHandle = useRef<EntryFormHandle>(null);
  const [pendingView, setPendingView] = useState<View | null>(null);
  const [leaving, setLeaving] = useState(false);
  const viewRef = useRef(view);
  viewRef.current = view;
  const setView = useCallback((v: View) => {
    if (viewRef.current.kind === "edit" && formDirty.current) {
      setPendingView(v);
      return;
    }
    setPendingView(null);
    setViewRaw(v);
  }, []);
  const onDirtyChange = useCallback((d: boolean) => {
    formDirty.current = d;
    if (!d) setPendingView(null);
  }, []);
  async function leave(how: "discard" | "save") {
    const target = pendingView;
    if (!target) return;
    setLeaving(true);
    try {
      if (how === "save") {
        if (!(await formHandle.current?.save())) return;
      } else {
        await formHandle.current?.discard();
      }
      formDirty.current = false;
      setPendingView(null);
      setViewRaw(target);
    } finally {
      setLeaving(false);
    }
  }
  const [updateDismissed, setUpdateDismissed] = useState(false);
  const [problem, setProblem] = useState<AppError | null>(status.disk_problem);
  const [rollback, setRollback] = useState<RollbackView | null>(unlockInfo?.rollback ?? null);
  // Số bản ghi bằng mật khẩu cũ vừa được cất (cộng dồn cho tới khi người dùng đóng thông báo; một lần
  // đồng bộ MỚI có bản như vậy thì hiện lại).
  const [oldKeyCopies, setOldKeyCopies] = useState(0);
  const { notices, add: addNotice, dismiss } = useNotices();
  const searchRef = useRef<HTMLInputElement>(null);
  const syncBusy = useRef(false);

  // Mỗi lần đọc lại status: vấn đề với file kho hiện / mất theo đúng status.
  useEffect(() => {
    setProblem(status.disk_problem);
    if (!status.rekey_advised) setRekey(false);
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

  /** Những điều cần báo trong một kết quả ghi/đồng bộ (dùng cả cho kết quả của "lưu mục" / "xoá mục"). */
  const applyNotices = useCallback(
    (r: SyncResult) => {
      if (r.old_key_archived > 0) setOldKeyCopies((n) => n + r.old_key_archived);
      if (r.unverified) addNotice(UNVERIFIED_TEXT, "warn");
      if (r.backup_failed) addNotice("Lần ghi vừa rồi không tạo được bản sao lưu tự động (thư mục sao lưu bị đầy hoặc không ghi được). Dữ liệu vẫn được lưu.", "warn");
      if (r.password_changed_elsewhere) addNotice("Mật khẩu chính đã được đổi ở máy khác — lần sau hãy mở khoá bằng mật khẩu MỚI.", "info");
    },
    [addNotice],
  );

  useEffect(() => {
    onWriteResult(applyNotices);
    return () => onWriteResult(null);
  }, [applyNotices]);

  const applySync = useCallback(
    (r: SyncResult, manual: boolean) => {
      setProblem(r.problem);
      if (r.changed) {
        toast(`Đã cập nhật từ máy khác: +${r.added} mới, ${r.updated} sửa, ${r.deleted} xoá`, "info");
        reload();
        setRefreshKey((k) => k + 1);
        onStatusChange();
      } else if (manual && !r.problem) {
        toast("Đã đồng bộ — không có thay đổi mới");
      }
      if (r.conflicts_merged) toast(`Đã gộp ${r.conflicts_merged} bản xung đột từ dịch vụ đồng bộ`, "info");
      r.errors.forEach((e) => addNotice(`Bản xung đột chưa gộp được: ${e}`, "error"));
      applyNotices(r);
    },
    [toast, reload, addNotice, applyNotices, onStatusChange],
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
    if (unlockInfo.rescue_kept > 0)
      addNotice(
        `${unlockInfo.rescue_kept} bản cứu hộ (thay đổi chưa kịp lưu của lần dùng trước) chưa gộp được vào kho — có thể chúng được ghi bằng một mật khẩu chính khác. Chúng vẫn được giữ lại trên máy này; app sẽ thử gộp lại ở lần mở khoá sau.`,
        "warn",
      );
    if (unlockInfo.local_restored) {
      const n = unlockInfo.local_restored.added + unlockInfo.local_restored.updated + unlockInfo.local_restored.deleted;
      addNotice(
        `File kho vừa mở thiếu một số thay đổi mà máy này đã lưu trước đó (${n} mục). App đã gộp lại từ bản lưu riêng trên máy này. Nguyên nhân thường gặp: một máy khác ghi đè file kho khi chưa đồng bộ xong.`,
        "warn",
      );
    }
    if (unlockInfo.old_version_wrote)
      addNotice(
        "File kho vừa được một máy còn chạy bản 0.1.x ghi lại. Hãy cập nhật app trên máy đó: khi còn máy chạy bản cũ, thay đổi ở hai bên có thể ghi đè lẫn nhau.",
        "warn",
      );
    applySync(unlockInfo.sync, false);
  }, [unlockInfo, addNotice, applySync]);

  // Bản nháp giữ từ trước khi kho bị khoá (form đang sửa dở): mở lại form với nó.
  const draftChecked = useRef(false);
  useEffect(() => {
    if (draftChecked.current) return;
    draftChecked.current = true;
    (async () => {
      const raw = unlockInfo?.draft ?? (await api.getDraft().catch(() => null));
      const draft = parseDraft(raw);
      if (!draft) return;
      if (draft.id) {
        try {
          const e = await api.get(draft.id);
          setViewRaw({ kind: "edit", id: draft.id, restore: { draft, changedSince: !!draft.changedSince || e.updated_at !== draft.updated_at } });
          addNotice("Đã khôi phục mục đang sửa dở từ trước khi kho bị khoá.", "info");
          return;
        } catch (e) {
          if (errorCode(e) !== "not_found") return;
        }
        // Mở thành mục MỚI với TOÀN BỘ nội dung lần cuối (gốc rỗng ⇒ mọi ô đều được áp, kể cả ô chưa sửa).
        setViewRaw({ kind: "edit", id: null, restore: { draft: { ...draft, id: null, updated_at: null, base: EMPTY_FIELDS }, asNew: true } });
        addNotice("Đã khôi phục mục đang sửa dở từ trước khi kho bị khoá. Mục đó không còn trong kho (có thể đã bị xoá ở máy khác) nên được mở thành một mục MỚI.", "warn");
        return;
      }
      setViewRaw({ kind: "edit", id: null, restore: { draft } });
      addNotice("Đã khôi phục mục đang sửa dở từ trước khi kho bị khoá.", "info");
    })();
  }, [unlockInfo, addNotice]);

  // Kho từng đổi mật khẩu chính bằng bản 0.1.x? (quét một lần cho mỗi khoá, ngoài luồng giao diện.)
  // Việc quét đọc các bản sao lưu trong thư mục đồng bộ và giữ khoá phiên trong lúc đó, nên chờ vài
  // giây cho danh sách hiện xong rồi mới quét.
  useEffect(() => {
    const t = window.setTimeout(() => {
      api
        .checkRekey()
        .then(setRekey)
        .catch(() => {});
    }, 4000);
    return () => window.clearTimeout(t);
  }, []);

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
        if (viewRef.current.kind !== "edit" || viewRef.current.id !== null) setView({ kind: "edit", id: null });
      } else if (k === "l") {
        e.preventDefault();
        lock();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lock, setView]);

  async function acceptRollback() {
    try {
      await api.acceptRollback();
      setRollback(null);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  /** Kết quả thật của việc chuyển / lưu sang chỗ khác: thông báo cố định (không phải toast 3,5 giây). */
  function afterMove(r: MoveView) {
    addNotice(moveMessage(r), r.rescued || !r.old_removed ? "warn" : "info");
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

      {problem && (
        <DiskProblemBanner
          problem={problem}
          status={status}
          onRetry={() => sync(true)}
          onResolved={() => {
            setProblem(null);
            onStatusChange();
          }}
          onMoved={afterMove}
          onChooseFile={onSwitchVault}
        />
      )}

      {rekey && !rekeyLater && (
        <div className="banner" role="status">
          <div className="banner-body">
            <strong>Kho này từng được đổi mật khẩu chính bằng bản 0.1.x.</strong> Bản đó không thay khoá mã hoá, nên ai biết mật khẩu CŨ và có một bản sao
            lưu cũ vẫn mở được dữ liệu mới. Hãy đổi mật khẩu chính một lần để thay khoá — làm ở MỘT máy, khi các máy khác đã khoá app; có thể nhập lại đúng
            mật khẩu đang dùng nếu nó vẫn an toàn.
            <div className="row gap banner-actions">
              <button className="btn primary" onClick={() => setView({ kind: "settings", section: "master", at: Date.now() })}>
                <Icon name="key" /> Đổi mật khẩu chính…
              </button>
              <button className="btn link muted-link" onClick={() => setRekeyLater(true)}>
                Để sau
              </button>
            </div>
          </div>
        </div>
      )}

      {rollback && rollback.unknown_key && (
        // Mạnh hơn cảnh báo "file cũ hơn": kho này không biết khoá mà máy này dùng lần trước ⇒ hoặc vừa gõ
        // một mật khẩu chính CŨ, hoặc file kho đã bị thay bằng file do người biết mật khẩu cũ làm ra.
        <div className="banner danger" role="alert">
          <div className="banner-body">
            <strong>
              <Icon name="warn" size={16} /> Kho vừa mở KHÔNG phải là phần tiếp nối của kho mà máy này dùng lần trước.
            </strong>{" "}
            Có thể bạn vừa mở bằng một mật khẩu chính CŨ, hoặc file kho đã bị thay bằng một file do người biết mật khẩu cũ tạo ra. Nếu bạn đã đổi mật
            khẩu chính, hãy <strong>khoá lại ngay</strong> và mở bằng mật khẩu chính HIỆN TẠI (mật khẩu bạn đặt gần đây nhất).{" "}
            <strong>Đừng tin các địa chỉ trang web hay mật khẩu hiện ở đây</strong> cho tới khi bạn đã kiểm tra.
            <div className="row gap banner-actions">
              <button className="btn primary" onClick={lock}>
                <Icon name="lock" /> Khoá lại
              </button>
              <button className="btn" onClick={acceptRollback}>
                Đã hiểu, vẫn dùng kho này
              </button>
            </div>
          </div>
        </div>
      )}
      {rollback && !rollback.unknown_key && (
        <div className="banner danger">
          <div className="banner-body">
            <strong>File kho đang mở CŨ HƠN bản mà máy này từng thấy.</strong> File được sửa lần cuối lúc {formatDateTime(rollback.file_modified_at)}, trong
            khi máy này đã thấy bản lúc {formatDateTime(rollback.seen_modified_at)}.
            {rollback.older_password && <> File này còn dùng một mật khẩu chính CŨ hơn mật khẩu hiện tại.</>} Có thể dịch vụ đồng bộ đã khôi phục một
            bản cũ — những mục thêm hoặc sửa gần đây có thể bị thiếu. Nếu thiếu, xem <button className="btn link" onClick={() => setView({ kind: "settings", section: "backups", at: Date.now() })}>Cài đặt → Sao lưu &amp; khôi phục</button>.
          </div>
          <button className="btn" onClick={acceptRollback}>
            Đã hiểu
          </button>
        </div>
      )}

      {oldKeyCopies > 0 && (
        <div className="banner" role="status">
          <div className="banner-body">
            <strong>Tìm thấy {oldKeyCopies > 1 ? `${oldKeyCopies} bản` : "một bản"} của kho được ghi bằng mật khẩu chính CŨ.</strong> Thường là do một
            thiết bị chưa nhận mật khẩu mới vẫn tiếp tục ghi, hoặc dịch vụ đồng bộ vừa đặt lại một bản cũ — hiếm hơn, do một người khác biết mật khẩu
            cũ. App <strong>không gộp</strong> bản đó vào kho; nó được cất trong Cài đặt → Sao lưu &amp; khôi phục, đánh dấu “ghi bằng mật khẩu cũ”. Ở
            đó bạn xem được những gì khác với kho hiện tại và khôi phục từng mục — <strong>chỉ khi bạn biết chắc những thay đổi đó là của bạn</strong>.
            <div className="row gap banner-actions">
              <button
                className="btn"
                onClick={() => setView({ kind: "settings", section: "backups", at: Date.now() })}
              >
                <Icon name="restore" /> Mở Sao lưu &amp; khôi phục
              </button>
            </div>
          </div>
          <button className="icon-btn small-btn" onClick={() => setOldKeyCopies(0)} title="Đóng thông báo" aria-label="Đóng thông báo">
            <Icon name="close" size={16} />
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
          {pendingView && view.kind === "edit" && (
            <div className="confirm-box unsaved-bar" role="alertdialog">
              <span className="small grow">
                <strong>Bạn đang sửa dở mục này.</strong> Rời đi thì những thay đổi chưa lưu sẽ mất.
              </span>
              <button className="btn primary" disabled={leaving} onClick={() => setPendingView(null)}>
                Tiếp tục sửa
              </button>
              <button className="btn" disabled={leaving} onClick={() => leave("save")}>
                Lưu
              </button>
              <button className="btn danger" disabled={leaving} onClick={() => leave("discard")}>
                Bỏ thay đổi
              </button>
            </div>
          )}
          {view.kind === "entry" && (
            <EntryView
              key={view.id}
              id={view.id}
              refreshKey={refreshKey}
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
              key={`${view.id ?? "new"}-${view.nonce ?? 0}`}
              id={view.id}
              restore={view.restore}
              handleRef={formHandle}
              onDirtyChange={onDirtyChange}
              onCancel={() => setView(view.id ? { kind: "entry", id: view.id } : { kind: "empty" })}
              onSaved={(id) => {
                formDirty.current = false;
                reload();
                onStatusChange();
                setViewRaw({ kind: "entry", id });
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
              section={view.section}
              focusAt={view.at}
              status={status}
              onImported={() => {
                reload();
                setRefreshKey((k) => k + 1);
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
  onChooseFile,
}: {
  problem: AppError;
  status: Status;
  onRetry: () => void;
  onResolved: () => void;
  onMoved: (r: MoveView) => void;
  /** Chọn một file kho CÓ SẴN (ví dụ ở vị trí mới sau khi máy kia chuyển kho) ⇒ khoá, mở khoá file đó. */
  onChooseFile: () => void;
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
                  bấm “Chọn file kho…” và chọn file ở vị trí mới thay vì tạo lại ở đây (những gì đang mở trên máy này được giữ lại trên máy và tự gộp vào file đó nếu là cùng một kho).
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
            {code === "file_missing" && (
              <button className="btn" onClick={onChooseFile} disabled={busy}>
                <Icon name="folder" /> Chọn file kho…
              </button>
            )}
            <MoveVault
              status={status}
              rescue
              onMoved={onMoved}
              label={code === "file_damaged" || code === "file_missing" ? "Lưu sang chỗ khác…" : "Lưu bản đang mở sang chỗ khác…"}
              buttonClass={canOverwrite ? "btn" : "btn primary"}
            />
          </div>
        )}
      </div>
    </div>
  );
}
