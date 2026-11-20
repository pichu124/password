import { useEffect, useRef, useState } from "react";
import { api, errorCode, errorText, pickFile } from "../api";
import type { RecoverInfo, Status, UnlockInfo, UpdateInfo } from "../types";
import { MasterPasswordField, useMasterCheck } from "./MasterField";
import { formatDateTime, Icon } from "./ui";

const VAULT_FILTER = [{ name: "Kho pwv", extensions: ["pwv"] }];

/** Mở hộp thoại chọn file kho có sẵn rồi ghi nhớ nó. Trả về true nếu đã chọn. */
async function pickExistingVault(): Promise<boolean> {
  const p = await pickFile({ title: "Chọn file kho (.pwv)", filters: VAULT_FILTER });
  if (!p) return false;
  await api.setVaultPath(p);
  return true;
}

// ------------------------------------------------------------------ mở khoá

/** Màn hình mở khoá. */
export function UnlockScreen({
  status,
  note,
  onUnlocked,
  onRecovered,
  onChangeVault,
  onMissing,
}: {
  status: Status;
  /** Lý do khoá (status.lock_note hoặc lời nhắn từ trang trước khi nạp lại). */
  note: string | null;
  onUnlocked: (info: UnlockInfo) => void;
  onRecovered: () => void;
  onChangeVault: () => void;
  onMissing: () => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; text: string } | null>(null);
  const [recovered, setRecovered] = useState<RecoverInfo | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => inputRef.current?.focus(), []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!password || !status.vault_path || busy) return;
    setBusy(true);
    setError(null);
    try {
      const info = await api.unlock(status.vault_path, password);
      setPassword("");
      onUnlocked(info);
    } catch (err) {
      const code = errorCode(err);
      if (code === "file_missing") {
        setPassword("");
        onMissing();
        return;
      }
      setError({ code, text: errorText(err) });
      // File hỏng: giữ mật khẩu vừa gõ để khôi phục từ bản sao lưu mà không phải gõ lại.
      if (code !== "file_damaged") {
        setPassword("");
        inputRef.current?.focus();
      }
    } finally {
      setBusy(false);
    }
  }

  async function recover() {
    if (!status.vault_path || !password) return;
    setBusy(true);
    try {
      const r = await api.recoverVault(status.vault_path, password);
      setPassword("");
      setRecovered(r);
    } catch (err) {
      setError({ code: errorCode(err), text: `Không khôi phục được: ${errorText(err)}` });
    } finally {
      setBusy(false);
    }
  }

  if (recovered) return <RecoveredCard info={recovered} onContinue={onRecovered} />;

  const fileName = status.vault_path?.split(/[\\/]/).pop();
  return (
    <div className="lock-screen">
      <form className="lock-card" onSubmit={submit}>
        <img src="/icon.svg" alt="" className="lock-logo" />
        <h1>Mở khoá kho mật khẩu</h1>
        <p className="muted small" title={status.vault_path ?? ""}>
          {fileName} <span className="path">— {status.vault_path}</span>
        </p>
        {note && <div className="note-box">{note}</div>}
        <input
          ref={inputRef}
          type="password"
          placeholder="Mật khẩu chính (master password)"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
          data-secret
          aria-label="Mật khẩu chính"
        />
        {error && <UnlockError code={error.code} text={error.text} busy={busy} canRecover={!!password} onRecover={recover} />}
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

function UnlockError({ code, text, busy, canRecover, onRecover }: { code: string; text: string; busy: boolean; canRecover: boolean; onRecover: () => void }) {
  if (code === "file_damaged") {
    return (
      <div className="problem-box">
        <p>
          <strong>File kho bị hỏng hoặc chưa tải xong.</strong>
        </p>
        <p className="small muted">
          Nếu dịch vụ đồng bộ đang tải file về, hãy chờ một chút rồi bấm “Mở khoá” lại. Nếu vẫn lỗi, app có thể dựng lại kho từ các bản sao lưu tự
          động (file hỏng được cất lại, không bị xoá).
        </p>
        <p className="small muted">Chi tiết: {text}</p>
        <button type="button" className="btn primary" disabled={busy || !canRecover} onClick={onRecover}>
          <Icon name="restore" /> {busy ? "Đang khôi phục…" : "Khôi phục từ bản sao lưu"}
        </button>
      </div>
    );
  }
  if (code === "unsupported_version") {
    return (
      <div className="problem-box">
        <p>
          <strong>File kho được tạo bởi phiên bản app mới hơn.</strong> {text}
        </p>
        <p className="small muted">Hãy cập nhật pwv lên bản mới nhất trên máy này rồi mở lại.</p>
        <UpdateLink />
      </div>
    );
  }
  return <p className="error">{text}</p>;
}

/** Nút kiểm tra và mở trang tải bản mới (dùng được cả khi kho đang khoá). */
function UpdateLink() {
  const [u, setU] = useState<UpdateInfo | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  async function check() {
    try {
      const r = await api.checkUpdate();
      if (r?.available) setU(r);
      else setMsg(r ? `Chưa có bản nào mới hơn ${r.current}.` : "Chưa có bản phát hành nào.");
    } catch (e) {
      setMsg(errorText(e));
    }
  }
  if (u)
    return (
      <button type="button" className="btn" onClick={() => api.openReleasePage(u.latest).catch((e) => setMsg(errorText(e)))}>
        Tải bản {u.latest}
      </button>
    );
  return (
    <>
      <button type="button" className="btn" onClick={check}>
        Kiểm tra bản mới
      </button>
      {msg && <small className="muted">{msg}</small>}
    </>
  );
}

function RecoveredCard({ info, onContinue }: { info: RecoverInfo; onContinue: () => void }) {
  return (
    <div className="lock-screen">
      <div className="lock-card wide-card">
        <h1>Đã khôi phục kho</h1>
        <ul className="result-list">
          <li>
            Kho hiện có <strong>{info.entries}</strong> mục, dựng lại từ {info.files_used} bản sao lưu.
          </li>
          <li>Bản sao lưu mới nhất được dùng: {formatDateTime(info.newest_backup_at)}.</li>
          {info.archived && (
            <li>
              File hỏng đã được cất ở: <span className="path selectable">{info.archived}</span>
            </li>
          )}
        </ul>
        <p className="small muted">
          Những thay đổi làm SAU thời điểm của bản sao lưu đó (trên máy này) có thể không có trong kho. Hãy kiểm tra các mục bạn vừa thêm hoặc
          sửa gần đây.
        </p>
        <div className="row end">
          <button className="btn primary" onClick={onContinue}>
            Mở kho
          </button>
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ không tìm thấy file kho

/** Đã từng dùng kho trên máy này nhưng không thấy file ở vị trí đã nhớ. */
export function NotFoundScreen({ status, note, onRetry, onRecovered }: { status: Status; note: string | null; onRetry: () => void; onRecovered: () => void }) {
  const [mode, setMode] = useState<"main" | "recover" | "create">("main");
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovered, setRecovered] = useState<RecoverInfo | null>(null);

  async function choose() {
    setError(null);
    try {
      if (await pickExistingVault()) onRetry();
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function recover(e: React.FormEvent) {
    e.preventDefault();
    if (!status.vault_path || !pw || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.recoverVault(status.vault_path, pw);
      setPw("");
      setRecovered(r);
    } catch (err) {
      setError(errorText(err));
      setPw("");
    } finally {
      setBusy(false);
    }
  }

  if (recovered) return <RecoveredCard info={recovered} onContinue={onRecovered} />;
  if (mode === "create") return <CreateVault onBack={() => setMode("main")} onOpenExisting={choose} onCreated={onRecovered} />;

  return (
    <div className="lock-screen">
      <div className="lock-card wide-card">
        <h1>
          <Icon name="warn" size={22} /> Không tìm thấy file kho
        </h1>
        <p className="small">
          <span className="muted">App đang tìm ở:</span> <span className="path selectable">{status.vault_path}</span>
        </p>
        {note && <div className="note-box">{note}</div>}
        <p className="small">Thường là do một trong các lý do sau:</p>
        <ul className="small result-list">
          <li>Google Drive / Dropbox / OneDrive chưa đồng bộ xong (máy vừa bật, mất mạng, hoặc ứng dụng đồng bộ chưa chạy).</li>
          <li>Kho đã được chuyển sang thư mục khác trên máy kia.</li>
          <li>Ổ đĩa của thư mục đồng bộ chưa được gắn (ví dụ ổ G: của Google Drive).</li>
        </ul>
        <p className="small muted">Dữ liệu của bạn KHÔNG mất chỉ vì file tạm thời không có ở đây. Đừng tạo kho mới nếu bạn đã có kho.</p>
        {error && <p className="error">{error}</p>}
        {mode === "recover" ? (
          <form className="confirm-box" onSubmit={recover}>
            <p className="small">
              Dựng lại kho từ các bản sao lưu tự động trong thư mục <span className="path">{status.vault_path}.backups</span>. Nhập mật khẩu chính:
            </p>
            <input
              type="password"
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              data-secret
              autoFocus
              aria-label="Mật khẩu chính"
              disabled={busy}
            />
            <div className="row gap confirm-actions">
              <button className="btn primary" disabled={busy || !pw}>
                {busy ? "Đang khôi phục…" : "Khôi phục"}
              </button>
              <button type="button" className="btn" onClick={() => setMode("main")} disabled={busy}>
                Huỷ
              </button>
            </div>
          </form>
        ) : (
          <div className="choice-col">
            <button className="btn primary wide" onClick={onRetry}>
              <Icon name="sync" /> Thử lại
            </button>
            <button className="btn wide" onClick={choose}>
              <Icon name="folder" /> Chọn file kho…
            </button>
            <button className="btn wide" onClick={() => setMode("recover")}>
              <Icon name="restore" /> Khôi phục từ bản sao lưu…
            </button>
          </div>
        )}
        <button className="btn subtle-link" onClick={() => setMode("create")}>
          Tạo kho mới ở vị trí khác
        </button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ lần đầu sử dụng

/** Lần đầu sử dụng trên máy này: mở kho có sẵn (ưu tiên) hoặc tạo kho mới. */
export function FirstRunScreen({ onDone, onCreated }: { onDone: () => void; onCreated: () => void }) {
  const [mode, setMode] = useState<"choose" | "create">("choose");
  const [error, setError] = useState<string | null>(null);

  async function openExisting() {
    setError(null);
    try {
      if (await pickExistingVault()) onDone();
    } catch (e) {
      setError(errorText(e));
    }
  }

  if (mode === "create") return <CreateVault onBack={() => setMode("choose")} onOpenExisting={openExisting} onCreated={onCreated} />;

  return (
    <div className="lock-screen">
      <div className="lock-card wide-card">
        <img src="/icon.svg" alt="" className="lock-logo" />
        <h1 className="center">Chào mừng đến với pwv</h1>
        <p className="muted center">Kho mật khẩu cá nhân, mã hoá trên máy bạn và đồng bộ qua Google Drive, Dropbox hoặc OneDrive.</p>
        <div className="choices">
          <button className="choice" onClick={openExisting}>
            <Icon name="folder" size={26} />
            <strong>Tôi đã có kho — mở file có sẵn</strong>
            <span className="muted small">Bạn đã dùng pwv trên máy khác: chọn file vault.pwv trong thư mục đồng bộ.</span>
          </button>
          <button className="choice" onClick={() => setMode("create")}>
            <Icon name="plus" size={26} />
            <strong>Tạo kho mới</strong>
            <span className="muted small">Lần đầu dùng pwv: tạo một kho trống và đặt mật khẩu chính.</span>
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}

/** Form tạo kho mới. Trước khi tạo, kiểm tra thư mục đã có dấu vết của một kho chưa. */
function CreateVault({ onBack, onOpenExisting, onCreated }: { onBack: () => void; onOpenExisting: () => void; onCreated: () => void }) {
  const [path, setPath] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [traces, setTraces] = useState<string[] | null>(null);
  const mc = useMasterCheck();

  useEffect(() => {
    api
      .suggestPath()
      .then((p) => setPath((cur) => cur || p))
      .catch(() => {});
  }, []);

  async function browse() {
    const p = await pickFile({ save: true, title: "Lưu kho mới", defaultPath: path, filters: VAULT_FILTER });
    if (p) setPath(p);
  }

  const canSubmit = !!path && !!pw && pw === pw2 && !busy;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setError(null);
    setBusy(true);
    try {
      const c = await mc.run(pw);
      if (!c?.ok) return;
      const found = await api.vaultTraces(path).catch(() => [] as string[]);
      if (found.length > 0) {
        setTraces(found);
        return;
      }
      await create();
    } finally {
      setBusy(false);
    }
  }

  async function create() {
    setBusy(true);
    setError(null);
    try {
      await api.createVault(path, pw);
      setPw("");
      setPw2("");
      onCreated();
    } catch (err) {
      setError(errorText(err));
      setTraces(null);
    } finally {
      setBusy(false);
    }
  }

  if (traces) {
    return (
      <div className="lock-screen">
        <div className="lock-card wide-card" role="alertdialog">
          <h1>
            <Icon name="warn" size={22} /> Thư mục này đã có dấu vết của một kho
          </h1>
          <p className="small">
            <span className="muted">Thư mục:</span> <span className="path">{path.replace(/[\\/][^\\/]*$/, "")}</span>
          </p>
          <ul className="small result-list">
            {traces.map((t) => (
              <li key={t} className="mono">
                {t}
              </li>
            ))}
          </ul>
          <p className="small">
            Nếu đây là máy thứ hai, rất có thể file kho <strong>chỉ chưa kịp đồng bộ về</strong>. Tạo kho mới ở đây sẽ sinh ra{" "}
            <strong>hai kho khác nhau trùng tên</strong> — mật khẩu lưu ở máy này sẽ không xuất hiện ở máy kia và ngược lại.
          </p>
          <p className="small muted">Hãy chờ dịch vụ đồng bộ chạy xong rồi mở file kho có sẵn.</p>
          {error && <p className="error">{error}</p>}
          <div className="choice-col">
            <button className="btn primary wide" onClick={onOpenExisting} disabled={busy}>
              <Icon name="folder" /> Mở kho có sẵn / chờ đồng bộ
            </button>
            <button className="btn subtle-link" onClick={create} disabled={busy}>
              {busy ? "Đang tạo kho…" : "Vẫn tạo kho mới"}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="lock-screen">
      <form className="lock-card wide-card" onSubmit={submit}>
        <h1>Tạo kho mới</h1>
        <label className="field">
          <span>Vị trí file kho</span>
          <div className="row">
            <input value={path} onChange={(e) => setPath(e.target.value)} spellCheck={false} autoComplete="off" />
            <button type="button" className="btn" onClick={browse}>
              Chọn…
            </button>
          </div>
          <small className="muted">Đặt trong thư mục Google Drive, Dropbox hoặc OneDrive để tự đồng bộ giữa các máy.</small>
        </label>
        <MasterPasswordField label="Mật khẩu chính (master password)" value={pw} onChange={setPw} mc={mc} autoFocus />
        <label className="field">
          <span>Nhập lại mật khẩu chính</span>
          <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="off" spellCheck={false} data-secret />
          {pw2 && pw !== pw2 && <small className="error">Hai lần nhập chưa khớp.</small>}
        </label>
        <div className="warning">
          <strong>Quên mật khẩu chính = mất toàn bộ dữ liệu.</strong> Không ai khôi phục được, kể cả phần mềm này. Hãy viết nó ra giấy và cất ở nơi
          an toàn.
        </div>
        {error && <p className="error">{error}</p>}
        <div className="row end">
          <button type="button" className="btn" onClick={onBack}>
            Quay lại
          </button>
          <button className="btn primary" disabled={!canSubmit}>
            {busy ? "Đang tạo kho…" : "Tạo kho"}
          </button>
        </div>
      </form>
    </div>
  );
}
