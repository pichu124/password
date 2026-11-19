import { useEffect, useRef, useState } from "react";
import { api, errorText, pickFile } from "../api";
import type { Status, Strength } from "../types";
import { Icon, StrengthMeter, useDebounced } from "./ui";

const VAULT_FILTER = [{ name: "Kho pwv", extensions: ["pwv"] }];

/** Màn hình mở khoá. */
export function UnlockScreen({ status, onUnlocked, onChangeVault }: { status: Status; onUnlocked: () => void; onChangeVault: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => inputRef.current?.focus(), []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!password || !status.vault_path) return;
    setBusy(true);
    setError(null);
    try {
      await api.unlock(status.vault_path, password);
      setPassword("");
      onUnlocked();
    } catch (err) {
      setError(errorText(err));
      setPassword("");
      inputRef.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  const fileName = status.vault_path?.split(/[\\/]/).pop();
  return (
    <div className="lock-screen">
      <form className="lock-card" onSubmit={submit}>
        <img src="/icon.svg" alt="" className="lock-logo" />
        <h1>Mở khoá kho mật khẩu</h1>
        <p className="muted small" title={status.vault_path ?? ""}>
          {fileName} <span className="path">— {status.vault_path}</span>
        </p>
        <input
          ref={inputRef}
          type="password"
          placeholder="Master password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
          autoComplete="current-password"
          aria-label="Master password"
        />
        {error && <p className="error">{error}</p>}
        <button className="btn primary wide" disabled={busy || !password}>
          {busy ? "Đang giải mã…" : "Mở khoá"}
        </button>
        <button type="button" className="btn link" onClick={onChangeVault}>
          Dùng kho khác
        </button>
      </form>
    </div>
  );
}

/** Lần đầu sử dụng: tạo kho mới hoặc mở kho có sẵn (ví dụ từ máy khác qua Google Drive). */
export function SetupScreen({ status, onDone }: { status: Status; onDone: () => void }) {
  const [mode, setMode] = useState<"choose" | "create">("choose");
  const [path, setPath] = useState(status.suggested_path);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [strength, setStrength] = useState<Strength | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dpw = useDebounced(pw, 200);

  useEffect(() => {
    if (!dpw) return setStrength(null);
    api.strength(dpw).then(setStrength).catch(() => {});
  }, [dpw]);

  async function openExisting() {
    const p = await pickFile({ title: "Chọn file kho (.pwv)", filters: VAULT_FILTER });
    if (!p) return;
    await api.setVaultPath(p);
    onDone();
  }

  async function browse() {
    const p = await pickFile({ save: true, title: "Lưu kho mới", defaultPath: path, filters: VAULT_FILTER });
    if (p) setPath(p);
  }

  async function suggestPassphrase() {
    const g = await api.generate({ mode: "passphrase", words: 6, separator: "-", capitalize: true, add_number: true });
    setPw(g.value);
    setPw2("");
  }

  const tooWeak = !!pw && (pw.length < 12 || (strength?.score ?? 0) < 3);
  const canCreate = !!path && !!pw && pw === pw2 && !tooWeak && !busy;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!canCreate) return;
    setBusy(true);
    setError(null);
    try {
      await api.createVault(path, pw);
      setPw("");
      setPw2("");
      onDone();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  if (mode === "choose") {
    return (
      <div className="lock-screen">
        <div className="lock-card">
          <img src="/icon.svg" alt="" className="lock-logo" />
          <h1>Chào mừng đến với pwv</h1>
          <p className="muted">Kho mật khẩu cá nhân, mã hoá trên máy bạn và đồng bộ qua Google Drive.</p>
          <button className="btn primary wide" onClick={() => setMode("create")}>
            <Icon name="plus" /> Tạo kho mới
          </button>
          <button className="btn wide" onClick={openExisting}>
            Mở kho có sẵn (từ máy khác / Google Drive)
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="lock-screen">
      <form className="lock-card wide-card" onSubmit={create}>
        <h1>Tạo kho mới</h1>
        <label className="field">
          <span>Vị trí file kho</span>
          <div className="row">
            <input value={path} onChange={(e) => setPath(e.target.value)} spellCheck={false} />
            <button type="button" className="btn" onClick={browse}>
              Chọn…
            </button>
          </div>
          <small className="muted">Đặt trong thư mục Google Drive (ví dụ “G:\My Drive”) để tự đồng bộ giữa các máy.</small>
        </label>
        <label className="field">
          <span>Master password</span>
          <div className="row">
            <input type="text" className="mono" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" spellCheck={false} />
            <button type="button" className="btn" onClick={suggestPassphrase} title="Gợi ý một cụm 6 từ ngẫu nhiên">
              <Icon name="dice" /> Gợi ý
            </button>
          </div>
          <StrengthMeter strength={strength} />
          {tooWeak && <small className="error">Cần ít nhất 12 ký tự và độ mạnh từ “Mạnh” trở lên.</small>}
        </label>
        <label className="field">
          <span>Nhập lại master password</span>
          <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" />
          {pw2 && pw !== pw2 && <small className="error">Hai lần nhập chưa khớp.</small>}
        </label>
        <div className="warning">
          <strong>Quên master password = mất toàn bộ dữ liệu.</strong> Không ai khôi phục được, kể cả phần mềm này. Hãy viết nó ra
          giấy và cất ở nơi an toàn.
        </div>
        {error && <p className="error">{error}</p>}
        <div className="row end">
          <button type="button" className="btn" onClick={() => setMode("choose")}>
            Quay lại
          </button>
          <button className="btn primary" disabled={!canCreate}>
            {busy ? "Đang tạo kho…" : "Tạo kho"}
          </button>
        </div>
      </form>
    </div>
  );
}
