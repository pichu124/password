import { useCallback, useEffect, useImperativeHandle, useRef, useState, type Ref } from "react";
import { api, errorCode, errorText, onBeforeLock } from "../api";
import type { EntryDetail, EntryInput, Strength } from "../types";
import { Generator } from "./Generator";
import { Icon, StrengthMeter, useDebounced, useToast } from "./ui";

const cleanList = (s: string, sep: string) =>
  s
    .split(sep)
    .map((x) => x.trim())
    .filter(Boolean);
const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Các ô của form có giá trị gốc (so với lúc mở) — để biết người dùng đã sửa ô nào. */
interface FormFields {
  title: string;
  username: string;
  urls: string;
  tags: string;
  notes: string;
  favorite: boolean;
}
export const EMPTY_FIELDS: FormFields = { title: "", username: "", urls: "", tags: "", notes: "", favorite: false };
const FIELD_KEYS: (keyof FormFields)[] = ["title", "username", "urls", "tags", "notes", "favorite"];

/**
 * Bản nháp của form, giữ trong backend (mã hoá bằng khoá kho, qua được lần khoá / thoát app). `base` = giá trị lúc mở
 * form: khi khôi phục, chỉ những ô người dùng ĐÃ SỬA (cur ≠ base) được áp lên dữ liệu hiện tại của mục — các ô khác lấy
 * giá trị mới nhất (có thể vừa đồng bộ về từ máy khác).
 */
export interface FormDraft {
  v: 1;
  id: string | null;
  /** `updated_at` của mục lúc mở form (null = mục mới). */
  updated_at: number | null;
  base: FormFields;
  cur: FormFields;
  password: string;
  passwordTouched: boolean;
  removePassword: boolean;
  totp: string;
  totpAction: "keep" | "set" | "remove";
  /**
   * Mục đã thay đổi kể từ khi bắt đầu sửa (đã phát hiện ở một lần khôi phục trước). Giữ lại qua các lần khoá tiếp theo —
   * cùng `updated_at` GỐC — cho tới khi lưu hoặc bỏ thay đổi, để cảnh báo không biến mất.
   */
  changedSince?: boolean;
}

export function parseDraft(raw: string | null): FormDraft | null {
  if (!raw) return null;
  try {
    const d = JSON.parse(raw) as FormDraft;
    return d && d.v === 1 && d.cur && d.base ? d : null;
  } catch {
    return null;
  }
}

/** Cách khôi phục một bản nháp. */
export interface Restore {
  draft: FormDraft;
  /** Mục đã thay đổi (máy khác, hoặc lần lưu đã xảy ra) kể từ lúc bắt đầu sửa. */
  changedSince?: boolean;
  /** Mục không còn trong kho ⇒ mở thành mục MỚI với cùng nội dung. */
  asNew?: boolean;
}

export interface EntryFormHandle {
  /** Lưu như bấm nút Lưu. true nếu đã lưu (hoặc không có gì để lưu). */
  save: () => Promise<boolean>;
  /** Bỏ thay đổi: ngừng giữ bản nháp và xoá nó khỏi backend (sau mọi lần đẩy đang dở). */
  discard: () => Promise<void>;
}

const DRAFT_DEBOUNCE_MS = 400;
const GEN_HINT = "Bấm Lưu trước khi đổi mật khẩu trên trang web — mật khẩu cũ vẫn nằm trong Lịch sử của mục.";

/** Thêm mới (id = null) hoặc sửa một mục. */
export function EntryForm({
  id,
  restore,
  onSaved,
  onCancel,
  onDirtyChange,
  handleRef,
}: {
  id: string | null;
  restore?: Restore | null;
  onSaved: (id: string) => void;
  onCancel: () => void;
  onDirtyChange?: (dirty: boolean) => void;
  handleRef?: Ref<EntryFormHandle>;
}) {
  const toast = useToast();
  const [orig, setOrig] = useState<EntryDetail | null>(null);
  /** Ghi chú lúc mở form (null = chưa tải / không tải được ⇒ không cho sửa để tránh ghi đè). */
  const [origNotes, setOrigNotes] = useState<string | null>(id ? null : "");
  const [notesError, setNotesError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [base, setBase] = useState<FormFields | null>(id ? null : EMPTY_FIELDS);
  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordTouched, setPasswordTouched] = useState(false);
  const [removePassword, setRemovePassword] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [urls, setUrls] = useState("");
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [favorite, setFavorite] = useState(false);
  const [totp, setTotp] = useState("");
  const [totpAction, setTotpAction] = useState<"keep" | "set" | "remove">("keep");
  const [showGen, setShowGen] = useState(false);
  const [genHint, setGenHint] = useState(false);
  const [strength, setStrength] = useState<Strength | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draftError, setDraftError] = useState<string | null>(null);
  const dpw = useDebounced(password, 200);

  /** Áp bản nháp lên dữ liệu vừa tải (chỉ những ô người dùng đã sửa). */
  const applyRestore = useCallback(
    (loaded: FormFields) => {
      const d = restore?.draft;
      const pick = <K extends keyof FormFields>(k: K): FormFields[K] => (d && d.cur[k] !== d.base[k] ? d.cur[k] : loaded[k]);
      setTitle(pick("title"));
      setUsername(pick("username"));
      setUrls(pick("urls"));
      setTags(pick("tags"));
      setNotes(pick("notes"));
      setFavorite(pick("favorite"));
      if (d) {
        setPassword(d.password);
        setPasswordTouched(d.passwordTouched);
        setRemovePassword(d.removePassword);
        setTotp(d.totp);
        setTotpAction(d.totpAction);
        if (d.passwordTouched && d.password) setShowPw(false);
      }
    },
    [restore],
  );

  useEffect(() => {
    if (!id) {
      setShowGen(!restore);
      applyRestore(EMPTY_FIELDS);
      return;
    }
    let alive = true;
    api
      .get(id)
      .then(async (e) => {
        if (!alive) return;
        const loaded: FormFields = { title: e.title, username: e.username, urls: e.urls.join("\n"), tags: e.tags.join(", "), notes: "", favorite: e.favorite };
        if (e.has_notes) {
          try {
            const n = await api.revealNotes(id);
            if (!alive) return;
            loaded.notes = n;
            setOrigNotes(n);
          } catch (err) {
            if (alive) setNotesError(`Không tải được ghi chú (${errorText(err)}) — ghi chú sẽ được giữ nguyên.`);
          }
        } else {
          setOrigNotes("");
        }
        if (!alive) return;
        setOrig(e);
        setBase(loaded);
        applyRestore(loaded);
      })
      .catch((err) => alive && setLoadError(errorText(err)));
    return () => {
      alive = false;
    };
  }, [id, restore, applyRestore]);

  useEffect(() => {
    if (!dpw) return setStrength(null);
    api.strength(dpw).then(setStrength).catch(() => {});
  }, [dpw]);

  // ------------------------------------------------------------------ bản nháp

  const cur: FormFields = { title, username, urls, tags, notes, favorite };
  const dirty =
    base !== null &&
    (FIELD_KEYS.some((k) => cur[k] !== base[k]) || (passwordTouched && password !== "") || removePassword || (totpAction === "set" && totp.trim() !== "") || totpAction === "remove");

  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);

  const draftJson = dirty
    ? JSON.stringify({
        v: 1,
        id,
        // Bản nháp khôi phục lại: giữ `updated_at` GỐC (lúc bắt đầu sửa) và dấu "đã thay đổi".
        updated_at: restore && !restore.asNew ? restore.draft.updated_at : (orig?.updated_at ?? null),
        base: base!,
        cur,
        password,
        passwordTouched,
        removePassword,
        totp,
        totpAction,
        changedSince: !!restore?.changedSince,
      } satisfies FormDraft)
    : null;
  const latest = useRef<string | null>(null);
  latest.current = draftJson;
  /** Bản đã gửi gần nhất (undefined = chưa gửi gì: không có bản nháp nào của form này trong backend). */
  const sent = useRef<string | null | undefined>(restore ? "restored" : undefined);
  const inflight = useRef<Promise<void>>(Promise.resolve());
  const closed = useRef(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flush = useCallback(async () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    if (closed.current) return;
    const d = latest.current;
    if (d === sent.current || (d === null && sent.current === undefined)) return inflight.current;
    sent.current = d;
    const p = inflight.current.then(() =>
      api.setDraft(d).then(
        () => setDraftError(null),
        (e) => {
          if (errorCode(e) === "draft_too_large") setDraftError("Bản nháp quá lớn, chưa được giữ — hãy bấm Lưu sớm.");
        },
      ),
    );
    inflight.current = p;
    return p;
  }, []);

  // Đẩy bản nháp sau mỗi thay đổi (chờ ~400 ms), và NGAY khi người dùng rời cửa sổ (sang trình duyệt để đổi mật khẩu).
  useEffect(() => {
    if (base === null || closed.current) return;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(flush, DRAFT_DEBOUNCE_MS);
  }, [draftJson, base, flush]);
  useEffect(() => {
    const onHidden = () => {
      if (document.visibilityState === "hidden") flush();
    };
    document.addEventListener("visibilitychange", onHidden);
    window.addEventListener("blur", flush);
    onBeforeLock(flush);
    return () => {
      document.removeEventListener("visibilitychange", onHidden);
      window.removeEventListener("blur", flush);
      onBeforeLock(null);
      if (timer.current) clearTimeout(timer.current);
      // Rời form (Huỷ, bấm mục khác…) trong lúc đang chờ đẩy: đẩy nốt — form đã sạch lại thì bản nháp cũ bị xoá.
      if (!closed.current) flush();
    };
  }, [flush]);

  // ------------------------------------------------------------------ lưu

  async function loadCurrent() {
    if (!id) return;
    try {
      setPassword(await api.reveal(id));
      setPasswordTouched(false);
      setRemovePassword(false);
      setShowPw(true);
    } catch (err) {
      toast(errorText(err), "error");
    }
  }

  /** Khi SỬA: chỉ những trường người dùng thực sự đổi so với lúc mở form (để không đè thay đổi từ máy khác). */
  function buildInput(): EntryInput {
    const totpValue = totpAction === "remove" ? "" : totpAction === "set" && totp.trim() ? totp.trim() : null;
    if (!id || !orig) {
      return {
        title: title.trim(),
        username: username.trim(),
        password,
        urls: cleanList(urls, "\n"),
        tags: cleanList(tags, ","),
        notes,
        favorite,
        ...(totpValue ? { totp: totpValue } : {}),
      };
    }
    const input: EntryInput = { id };
    if (title.trim() !== orig.title) input.title = title.trim();
    if (username.trim() !== orig.username) input.username = username.trim();
    // Ô mật khẩu trống luôn nghĩa là "giữ nguyên" (kể cả sau khi gõ rồi xoá); muốn xoá phải bấm "Xoá mật khẩu đã lưu".
    if (removePassword) input.password = "";
    else if (passwordTouched && password !== "") input.password = password;
    const u = cleanList(urls, "\n");
    if (!sameList(u, orig.urls)) input.urls = u;
    const t = cleanList(tags, ",");
    if (!sameList(t, orig.tags)) input.tags = t;
    if (origNotes !== null && notes !== origNotes) input.notes = notes;
    if (favorite !== orig.favorite) input.favorite = favorite;
    if (totpValue !== null) input.totp = totpValue;
    return input;
  }

  async function save(): Promise<boolean> {
    if (busy) return false;
    setError(null);
    const input = buildInput();
    if (id && Object.keys(input).length === 1) {
      toast("Không có thay đổi nào", "info");
      closed.current = true;
      if (timer.current) clearTimeout(timer.current);
      timer.current = null;
      // Chờ lần đẩy đang dở xong rồi mới xoá, để nó không đến SAU lệnh xoá.
      await inflight.current.catch(() => {});
      if (sent.current !== undefined) await api.setDraft(null).catch(() => {});
      sent.current = null;
      onSaved(id);
      return true;
    }
    if (!title.trim()) {
      setError("Tiêu đề không được để trống");
      return false;
    }
    setBusy(true);
    // Không để một lần đẩy bản nháp đến SAU lần lưu (backend xoá bản nháp ngay trong lệnh lưu).
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    closed.current = true;
    await inflight.current.catch(() => {});
    try {
      const [newId, sync] = await api.save(input);
      if (sync.changed) toast("Đã gộp thay đổi từ máy khác trước khi lưu", "info");
      toast(id ? "Đã lưu thay đổi" : "Đã thêm mục mới");
      setPassword("");
      sent.current = null;
      onSaved(newId);
      return true;
    } catch (e) {
      // Form vẫn mở, giữ nguyên những gì người dùng đã nhập (và bản nháp tiếp tục được giữ).
      closed.current = false;
      setError(errorText(e));
      flush();
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function discard() {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    closed.current = true;
    await inflight.current.catch(() => {});
    await api.setDraft(null).catch(() => {});
    sent.current = null;
  }

  useImperativeHandle(handleRef, () => ({ save, discard }));

  async function submit(ev: React.FormEvent) {
    ev.preventDefault();
    await save();
  }

  function takeGenerated(v: string, hide: boolean) {
    setPassword(v);
    setPasswordTouched(true);
    setRemovePassword(false);
    setGenHint(true);
    if (hide) setShowGen(false);
  }

  const editing = id !== null;
  if (editing && loadError) {
    return (
      <div className="detail">
        <div className="fields">
          <p className="error">{loadError}</p>
          <button className="btn" onClick={onCancel}>
            Quay lại
          </button>
        </div>
      </div>
    );
  }
  const loading = editing && !orig;

  return (
    <form
      className="detail form"
      onSubmit={submit}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !busy) {
          e.preventDefault();
          onCancel();
        }
      }}
    >
      <header className="detail-head">
        <button type="button" className="icon-btn" onClick={onCancel} title="Quay lại" aria-label="Quay lại">
          <Icon name="back" />
        </button>
        <h2 className="grow">{editing ? `Sửa “${orig?.title ?? ""}”` : "Thêm mục mới"}</h2>
      </header>

      {(restore?.changedSince || restore?.asNew || draftError) && (
        <div className="fields-error">
          {restore?.changedSince && <p className="warn-text">Mục này đã thay đổi sau khi bạn bắt đầu sửa — kiểm tra lại trước khi lưu.</p>}
          {restore?.asNew && (
            <p className="warn-text">
              Mục bạn đang sửa dở không còn trong kho (có thể đã bị xoá ở máy khác) — toàn bộ nội dung lần cuối được mở thành một mục MỚI. Mật khẩu chỉ có
              nếu bạn đã nhập nó trong lúc sửa; nếu mục còn trong Thùng rác, bạn cũng có thể khôi phục nó từ đó. Kiểm tra lại rồi bấm Lưu.
            </p>
          )}
          {draftError && <p className="error">{draftError}</p>}
        </div>
      )}

      <fieldset className="fields plain" disabled={busy || loading}>
        <label className="field">
          <span>Tiêu đề *</span>
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ví dụ: Vietcombank, Gmail…" autoFocus required autoComplete="off" spellCheck={false} />
        </label>
        <label className="field">
          <span>Tên đăng nhập / email</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} spellCheck={false} autoComplete="off" />
        </label>

        <div className="field">
          <span>Mật khẩu</span>
          {removePassword ? (
            <div className="row gap">
              <span className="muted">Mật khẩu đã lưu sẽ bị xoá khi lưu (nó vẫn nằm trong Lịch sử của mục).</span>
              <button type="button" className="btn link" onClick={() => setRemovePassword(false)}>
                Hoàn tác
              </button>
            </div>
          ) : (
            <div className="row">
              <input
                type={showPw ? "text" : "password"}
                className="mono"
                value={password}
                placeholder={editing && orig?.has_password ? "(để trống = giữ nguyên mật khẩu hiện tại)" : ""}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setPasswordTouched(true);
                }}
                autoComplete="off"
                spellCheck={false}
                data-secret
                aria-label="Mật khẩu"
              />
              <button type="button" className="icon-btn" onClick={() => setShowPw(!showPw)} title={showPw ? "Ẩn" : "Hiện"} aria-label={showPw ? "Ẩn" : "Hiện"}>
                <Icon name={showPw ? "eyeOff" : "eye"} />
              </button>
              <button type="button" className="btn" onClick={() => setShowGen(!showGen)}>
                <Icon name="dice" /> Tạo
              </button>
            </div>
          )}
          {password && !removePassword && <StrengthMeter strength={strength} />}
          {editing && orig?.has_password && !passwordTouched && !password && !removePassword && (
            <div className="row gap">
              <button type="button" className="btn link" onClick={loadCurrent}>
                Hiện mật khẩu hiện tại để sửa
              </button>
              <button type="button" className="btn link muted-link" onClick={() => setRemovePassword(true)}>
                Xoá mật khẩu đã lưu
              </button>
            </div>
          )}
          {editing && passwordTouched && password !== "" && !genHint && <small className="muted">Mật khẩu cũ sẽ được lưu vào lịch sử.</small>}
          {genHint && passwordTouched && password !== "" && (
            <small className="gen-hint" role="note">
              <Icon name="warn" size={14} /> {GEN_HINT}
            </small>
          )}
          {showGen && !removePassword && (
            <div className="inline-gen">
              <Generator compact label={title} onUse={(v) => takeGenerated(v, true)} onCopied={(v) => takeGenerated(v, false)} />
            </div>
          )}
        </div>

        <label className="field">
          <span>Trang web (mỗi dòng một địa chỉ)</span>
          <textarea rows={2} value={urls} onChange={(e) => setUrls(e.target.value)} spellCheck={false} autoComplete="off" placeholder="https://…" />
        </label>

        <div className="field">
          <span>Mã xác thực 2 bước (TOTP)</span>
          {editing && orig?.has_totp && totpAction === "keep" ? (
            <div className="row gap">
              <span className={orig.totp_error ? "error" : "muted"}>
                {orig.totp_error ? "Mã 2FA đã lưu không đọc được" : `Đã có mã 2FA${orig.totp_label ? ` · ${orig.totp_label}` : ""}`}
              </span>
              <button type="button" className="btn" onClick={() => setTotpAction("set")}>
                Thay
              </button>
              <button type="button" className="btn subtle" onClick={() => setTotpAction("remove")}>
                Xoá
              </button>
            </div>
          ) : totpAction === "remove" ? (
            <div className="row gap">
              <span className="muted">Mã 2FA sẽ bị xoá khi lưu.</span>
              <button type="button" className="btn link" onClick={() => setTotpAction("keep")}>
                Hoàn tác
              </button>
            </div>
          ) : (
            <>
              <input
                className="mono"
                value={totp}
                onChange={(e) => {
                  setTotp(e.target.value);
                  setTotpAction("set");
                }}
                placeholder="otpauth://totp/… hoặc khoá bí mật dạng JBSWY3DP…"
                spellCheck={false}
                autoComplete="off"
                data-secret
              />
              <small className="muted">Khi bật 2FA, trang web hiện mã QR kèm dòng “nhập thủ công / khoá bí mật” — dán dòng đó vào đây.</small>
              {editing && orig?.has_totp && (
                <button
                  type="button"
                  className="btn link"
                  onClick={() => {
                    setTotp("");
                    setTotpAction("keep");
                  }}
                >
                  Giữ mã 2FA cũ
                </button>
              )}
            </>
          )}
        </div>

        <label className="field">
          <span>Nhóm / tag (cách nhau bởi dấu phẩy)</span>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="Ngân hàng, Công việc" autoComplete="off" spellCheck={false} />
        </label>
        <label className="field">
          <span>Ghi chú</span>
          <textarea
            rows={4}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder={origNotes === null && !notesError ? "Đang tải ghi chú…" : "Câu hỏi bảo mật, mã khôi phục, số tài khoản…"}
            disabled={origNotes === null}
            autoComplete="off"
            spellCheck={false}
            data-secret
          />
          {notesError && <small className="error">{notesError}</small>}
        </label>
        <label className="check">
          <input type="checkbox" checked={favorite} onChange={(e) => setFavorite(e.target.checked)} /> Yêu thích (hiện lên đầu danh sách)
        </label>
        {editing && <small className="muted">Chỉ những ô bạn sửa mới được lưu — thay đổi vừa đồng bộ từ máy khác ở các ô còn lại được giữ nguyên.</small>}
        {dirty && <small className="muted">Bản nháp đang được giữ trên máy này (đã mã hoá) — kho có tự khoá thì lần mở sau vẫn còn.</small>}
      </fieldset>

      {error && (
        <div className="fields-error">
          <p className="error">Chưa lưu được: {error}</p>
        </div>
      )}
      <footer className="detail-foot end">
        <button type="button" className="btn" onClick={onCancel} disabled={busy}>
          Huỷ
        </button>
        <button className="btn primary" disabled={busy || loading || !title.trim()}>
          {busy ? "Đang lưu…" : "Lưu"}
        </button>
      </footer>
    </form>
  );
}
