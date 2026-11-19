import { useEffect, useState } from "react";
import { api, errorText } from "../api";
import type { EntryDetail, Strength } from "../types";
import { Generator } from "./Generator";
import { Icon, StrengthMeter, useDebounced, useToast } from "./ui";

/** Thêm mới (id = null) hoặc sửa một mục. */
export function EntryForm({ id, onSaved, onCancel }: { id: string | null; onSaved: (id: string) => void; onCancel: () => void }) {
  const toast = useToast();
  const [orig, setOrig] = useState<EntryDetail | null>(null);
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
    api.get(id).then((e) => {
      setOrig(e);
      setTitle(e.title);
      setUsername(e.username);
      setUrls(e.urls.join("\n"));
      setTags(e.tags.join(", "));
      setNotes(e.notes);
      setFavorite(e.favorite);
    });
  }, [id]);

  useEffect(() => {
    if (!dpw) return setStrength(null);
    api.strength(dpw).then(setStrength).catch(() => {});
  }, [dpw]);

  async function loadCurrent() {
    if (!id) return;
    setPassword(await api.reveal(id));
    setPasswordTouched(false);
    setShowPw(true);
  }

  async function submit(ev: React.FormEvent) {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const [newId, sync] = await api.save({
        id,
        title,
        username,
        password: id === null || passwordTouched ? password : null,
        urls: urls.split("\n"),
        tags: tags.split(","),
        notes,
        favorite,
        totp: totpAction === "keep" && id !== null ? null : totpAction === "remove" ? "" : totp,
      });
      if (sync.changed) toast("Đã gộp thay đổi từ máy khác trước khi lưu", "info");
      toast(id ? "Đã lưu thay đổi" : "Đã thêm mục mới");
      setPassword("");
      onSaved(newId);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  const editing = id !== null;
  return (
    <form className="detail form" onSubmit={submit}>
      <header className="detail-head">
        <button type="button" className="icon-btn" onClick={onCancel} title="Quay lại">
          <Icon name="back" />
        </button>
        <h2 className="grow">{editing ? `Sửa “${orig?.title ?? ""}”` : "Thêm mục mới"}</h2>
      </header>

      <div className="fields">
        <label className="field">
          <span>Tiêu đề *</span>
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ví dụ: Vietcombank, Gmail…" autoFocus required />
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
              autoComplete="new-password"
              spellCheck={false}
            />
            <button type="button" className="icon-btn" onClick={() => setShowPw(!showPw)} title={showPw ? "Ẩn" : "Hiện"}>
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
          <textarea rows={2} value={urls} onChange={(e) => setUrls(e.target.value)} spellCheck={false} placeholder="https://…" />
        </label>

        <div className="field">
          <span>Mã xác thực 2 bước (TOTP)</span>
          {editing && orig?.has_totp && totpAction === "keep" ? (
            <div className="row gap">
              <span className="muted">Đã có mã 2FA{orig.totp_label ? ` · ${orig.totp_label}` : ""}</span>
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
              />
              <small className="muted">Khi bật 2FA, trang web hiện mã QR kèm dòng “nhập thủ công / khoá bí mật” — dán dòng đó vào đây.</small>
            </>
          )}
        </div>

        <label className="field">
          <span>Nhóm / tag (cách nhau bởi dấu phẩy)</span>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="Ngân hàng, Công việc" />
        </label>
        <label className="field">
          <span>Ghi chú</span>
          <textarea rows={4} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Câu hỏi bảo mật, mã khôi phục, số tài khoản…" />
        </label>
        <label className="check">
          <input type="checkbox" checked={favorite} onChange={(e) => setFavorite(e.target.checked)} /> Yêu thích (hiện lên đầu danh sách)
        </label>
        {error && <p className="error">{error}</p>}
      </div>

      <footer className="detail-foot end">
        <button type="button" className="btn" onClick={onCancel}>
          Huỷ
        </button>
        <button className="btn primary" disabled={busy || !title.trim()}>
          {busy ? "Đang lưu…" : "Lưu"}
        </button>
      </footer>
    </form>
  );
}
