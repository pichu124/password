import { useEffect, useState } from "react";
import { api, errorText } from "../api";
import type { EntryDetail, EntryInput, Strength } from "../types";
import { Generator } from "./Generator";
import { Icon, StrengthMeter, useDebounced, useToast } from "./ui";

const cleanList = (s: string, sep: string) =>
  s
    .split(sep)
    .map((x) => x.trim())
    .filter(Boolean);
const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Thêm mới (id = null) hoặc sửa một mục. */
export function EntryForm({ id, onSaved, onCancel }: { id: string | null; onSaved: (id: string) => void; onCancel: () => void }) {
  const toast = useToast();
  const [orig, setOrig] = useState<EntryDetail | null>(null);
  /** Ghi chú lúc mở form (null = chưa tải / không tải được ⇒ không cho sửa để tránh ghi đè). */
  const [origNotes, setOrigNotes] = useState<string | null>(id ? null : "");
  const [notesError, setNotesError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordTouched, setPasswordTouched] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [urls, setUrls] = useState("");
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [favorite, setFavorite] = useState(false);
  const [totp, setTotp] = useState("");
  const [totpAction, setTotpAction] = useState<"keep" | "set" | "remove">("keep");
  const [showGen, setShowGen] = useState(false);
  const [strength, setStrength] = useState<Strength | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dpw = useDebounced(password, 200);

  useEffect(() => {
    if (!id) {
      setShowGen(true);
      return;
    }
    let alive = true;
    api
      .get(id)
      .then(async (e) => {
        if (!alive) return;
        setOrig(e);
        setTitle(e.title);
        setUsername(e.username);
        setUrls(e.urls.join("\n"));
        setTags(e.tags.join(", "));
        setFavorite(e.favorite);
        if (!e.has_notes) {
          setOrigNotes("");
          return;
        }
        try {
          const n = await api.revealNotes(id);
          if (!alive) return;
          setOrigNotes(n);
          setNotes(n);
        } catch (err) {
          if (alive) setNotesError(`Không tải được ghi chú (${errorText(err)}) — ghi chú sẽ được giữ nguyên.`);
        }
      })
      .catch((err) => alive && setLoadError(errorText(err)));
    return () => {
      alive = false;
    };
  }, [id]);

  useEffect(() => {
    if (!dpw) return setStrength(null);
    api.strength(dpw).then(setStrength).catch(() => {});
  }, [dpw]);

  async function loadCurrent() {
    if (!id) return;
    try {
      setPassword(await api.reveal(id));
      setPasswordTouched(false);
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
    if (passwordTouched) input.password = password;
    const u = cleanList(urls, "\n");
    if (!sameList(u, orig.urls)) input.urls = u;
    const t = cleanList(tags, ",");
    if (!sameList(t, orig.tags)) input.tags = t;
    if (origNotes !== null && notes !== origNotes) input.notes = notes;
    if (favorite !== orig.favorite) input.favorite = favorite;
    if (totpValue !== null) input.totp = totpValue;
    return input;
  }

  async function submit(ev: React.FormEvent) {
    ev.preventDefault();
    if (busy) return;
    setError(null);
    const input = buildInput();
    if (id && Object.keys(input).length === 1) {
      toast("Không có thay đổi nào", "info");
      onSaved(id);
      return;
    }
    setBusy(true);
    try {
      const [newId, sync] = await api.save(input);
      if (sync.changed) toast("Đã gộp thay đổi từ máy khác trước khi lưu", "info");
      toast(id ? "Đã lưu thay đổi" : "Đã thêm mục mới");
      setPassword("");
      onSaved(newId);
    } catch (e) {
      // Form vẫn mở, giữ nguyên những gì người dùng đã nhập.
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
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
    <form className="detail form" onSubmit={submit}>
      <header className="detail-head">
        <button type="button" className="icon-btn" onClick={onCancel} title="Quay lại" aria-label="Quay lại">
          <Icon name="back" />
        </button>
        <h2 className="grow">{editing ? `Sửa “${orig?.title ?? ""}”` : "Thêm mục mới"}</h2>
      </header>

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
          <div className="row">
            <input
              type={showPw ? "text" : "password"}
              className="mono"
              value={password}
              placeholder={editing && !passwordTouched ? "(giữ nguyên mật khẩu hiện tại)" : ""}
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
          {password && <StrengthMeter strength={strength} />}
          {editing && orig?.has_password && !passwordTouched && !password && (
            <button type="button" className="btn link" onClick={loadCurrent}>
              Hiện mật khẩu hiện tại để sửa
            </button>
          )}
          {editing && passwordTouched && <small className="muted">Mật khẩu cũ sẽ được lưu vào lịch sử.</small>}
          {showGen && (
            <div className="inline-gen">
              <Generator
                compact
                onUse={(v) => {
                  setPassword(v);
                  setPasswordTouched(true);
                  setShowGen(false);
                }}
              />
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
                <button type="button" className="btn link" onClick={() => { setTotp(""); setTotpAction("keep"); }}>
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
