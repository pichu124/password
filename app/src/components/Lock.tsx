import { useEffect, useRef, useState } from "react";
import { api, errorCode, errorText, pickFile } from "../api";
import type { AppError, RecoverInfo, Status, UnlockInfo, UpdateInfo } from "../types";
import { MasterPasswordField, useMasterCheck } from "./MasterField";
import { formatDateTime, Icon } from "./ui";
import { useVaultChooser, VAULT_FILTER } from "./VaultChooser";

/** Chọn một file kho có sẵn (có kiểm tra "bản xung đột"), ghi nhớ nó rồi gọi `then`. */
function useExistingVaultChooser(then: () => void) {
  return useVaultChooser(async (p) => {
    await api.setVaultPath(p);
    then();
  });
}

/** Các lựa chọn rõ ràng của chủ kho khi khôi phục (xem api.recoverVault). */
type RecoverOpts = { allowOlder?: boolean; allowStale?: boolean; replaceNewer?: boolean };

interface ShownError {
  code: string;
  text: string;
  detail?: AppError["detail"];
}
const toShown = (e: unknown, prefix = ""): ShownError => {
  const code = errorCode(e);
  const detail = typeof e === "object" && e !== null ? (e as AppError).detail : null;
  return { code, text: prefix + errorText(e), detail };
};
/** Các mã lỗi của việc khôi phục có hộp giải thích riêng. */
const RECOVER_BOXES = new Set(["older_password", "old_backups_only", "no_backup", "older_than_seen"]);

interface Recovered {
  info: RecoverInfo;
  older: OlderChoice;
  stale: boolean;
}

/** Sau bao nhiêu lần "sai mật khẩu" liên tiếp thì gợi ý dựng lại từ sao lưu. */
const WRONG_BEFORE_HINT = 2;

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
  const [error, setError] = useState<ShownError | null>(null);
  const [wrongCount, setWrongCount] = useState(0);
  const [recovered, setRecovered] = useState<Recovered | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const lastOpts = useRef<RecoverOpts>({});

  useEffect(() => inputRef.current?.focus(), []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!password || !status.vault_path || busy) return;
    setBusy(true);
    setError(null);
    lastOpts.current = {};
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
      setError(toShown(err));
      const wrong = code === "wrong_password" ? wrongCount + 1 : 0;
      setWrongCount(wrong);
      // File hỏng / định dạng lạ, hoặc đã sai nhiều lần: giữ mật khẩu vừa gõ để dựng lại từ bản sao lưu mà không
      // phải gõ lại (bôi đen sẵn để gõ lại thì thay luôn).
      if (code === "file_damaged" || code === "unsupported_version" || wrong >= WRONG_BEFORE_HINT) {
        setTimeout(() => inputRef.current?.select(), 0);
      } else {
        setPassword("");
        inputRef.current?.focus();
      }
    } finally {
      setBusy(false);
    }
  }

  /** Dựng lại từ sao lưu. `opts` cộng dồn các lựa chọn rõ ràng đã chọn trước đó (ví dụ "thay file định dạng mới hơn"). */
  async function recover(opts: RecoverOpts = {}) {
    if (!status.vault_path || !password) return;
    const merged = { ...lastOpts.current, ...opts };
    lastOpts.current = merged;
    setBusy(true);
    try {
      const r = await api.recoverVault(status.vault_path, password, merged);
      setPassword("");
      setRecovered({ info: r, older: merged.allowOlder ? (error?.code === "old_backups_only" ? "backups" : "password") : false, stale: !!merged.allowStale });
    } catch (err) {
      const code = errorCode(err);
      // Mật khẩu cũ / bản cũ hơn: giữ nguyên ô mật khẩu để nút "vẫn khôi phục…" dùng được ngay.
      setError(toShown(err, RECOVER_BOXES.has(code) || code === "wrong_password" ? "" : "Không khôi phục được: "));
    } finally {
      setBusy(false);
    }
  }

  if (recovered) return <RecoveredCard {...recovered} onContinue={onRecovered} />;

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
          onChange={(e) => {
            setPassword(e.target.value);
            // Mọi hộp lựa chọn (khôi phục, "vẫn khôi phục bản cũ hơn"…) chỉ áp cho ĐÚNG mật khẩu đã tạo ra nó.
            setError(null);
            lastOpts.current = {};
          }}
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
          data-secret
          aria-label="Mật khẩu chính"
        />
        {error && (
          <UnlockError
            error={error}
            busy={busy}
            canRecover={!!password}
            wrongCount={wrongCount}
            localCopyAt={status.local_copy_at}
            onRecover={recover}
          />
        )}
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

function UnlockError({
  error,
  busy,
  canRecover,
  wrongCount,
  localCopyAt,
  onRecover,
}: {
  error: ShownError;
  busy: boolean;
  canRecover: boolean;
  wrongCount: number;
  localCopyAt: number | null;
  onRecover: (opts?: RecoverOpts) => void;
}) {
  const { code, text } = error;
  if (RECOVER_BOXES.has(code)) return <RecoverErrorBox error={error} busy={busy} canRecover={canRecover} localCopyAt={localCopyAt} onRecover={onRecover} />;
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
        <button type="button" className="btn primary" disabled={busy || !canRecover} onClick={() => onRecover()}>
          <Icon name="restore" /> {busy ? "Đang khôi phục…" : "Khôi phục từ bản sao lưu"}
        </button>
      </div>
    );
  }
  if (code === "unsupported_version") return <NewerFormatBox text={text} busy={busy} canRecover={canRecover} onRecover={onRecover} />;
  if (code === "wrong_password" && wrongCount >= WRONG_BEFORE_HINT) {
    return (
      <div className="secondary-action">
        <p className="error">{text}</p>
        <button type="button" className="btn link wrap" disabled={busy || !canRecover} onClick={() => onRecover()}>
          {busy ? "Đang thử dựng lại…" : "Chắc chắn mật khẩu đúng? Thử dựng lại kho từ các bản sao lưu"}
        </button>
      </div>
    );
  }
  return <p className="error">{text}</p>;
}

/** File kho báo "định dạng mới hơn": cập nhật app; hoặc (phụ) file hỏng ở đúng chỗ số phiên bản ⇒ dựng lại từ sao lưu. */
function NewerFormatBox({ text, busy, canRecover, onRecover }: { text: string; busy: boolean; canRecover: boolean; onRecover: (opts?: RecoverOpts) => void }) {
  const [open, setOpen] = useState(false);
  const [ack, setAck] = useState(false);
  return (
    <div className="problem-box">
      <p>
        <strong>File kho được tạo bởi phiên bản app mới hơn.</strong> {text}
      </p>
      <p className="small muted">Hãy cập nhật pwv lên bản mới nhất trên máy này rồi mở lại.</p>
      <UpdateLink />
      {!open ? (
        <button type="button" className="btn link wrap" onClick={() => setOpen(true)}>
          Chưa cập nhật app ở máy nào khác? File có thể bị hỏng — dựng lại từ bản sao lưu
        </button>
      ) : (
        <div className="confirm-box">
          <p className="small">
            App sẽ cất file kho hiện tại vào thư mục sao lưu (<span className="mono">damaged-…</span>, không xoá) rồi dựng lại kho từ các bản sao lưu bằng mật
            khẩu vừa nhập.
          </p>
          <label className="check small">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            <span>Tôi hiểu: nếu file này thật sự do một bản app mới hơn ghi, nó sẽ được thay bằng dữ liệu CŨ HƠN từ các bản sao lưu.</span>
          </label>
          <button type="button" className="btn subtle wrap" disabled={busy || !ack || !canRecover} onClick={() => onRecover({ replaceNewer: true })}>
            {busy ? "Đang khôi phục…" : "Dựng lại từ bản sao lưu"}
          </button>
        </div>
      )}
    </div>
  );
}

/** Hộp giải thích cho các lỗi của việc khôi phục (mật khẩu cũ, chỉ còn bản cũ, không có bản nào, bản cũ hơn dữ liệu đã thấy). */
function RecoverErrorBox({
  error,
  busy,
  canRecover,
  localCopyAt,
  onRecover,
}: {
  error: ShownError;
  busy: boolean;
  canRecover: boolean;
  localCopyAt: number | null;
  onRecover: (opts?: RecoverOpts) => void;
}) {
  if (error.code === "older_password") return <OlderPasswordBox busy={busy} canRecover={canRecover} onRecoverOlder={() => onRecover({ allowOlder: true })} />;
  if (error.code === "old_backups_only") return <OldBackupsOnlyBox busy={busy} canRecover={canRecover} onRecoverOlder={() => onRecover({ allowOlder: true })} />;
  if (error.code === "older_than_seen") return <StaleBox error={error} busy={busy} canRecover={canRecover} onRecoverStale={() => onRecover({ allowStale: true })} />;
  return <NoBackupBox text={error.text} localCopyAt={localCopyAt} />;
}

/** Bản dựng lại được CŨ HƠN dữ liệu máy này từng thấy: không ghi gì, giải thích, và chỉ làm tiếp khi chủ kho chọn rõ ràng. */
function StaleBox({ error, busy, canRecover, onRecoverStale }: { error: ShownError; busy: boolean; canRecover: boolean; onRecoverStale: () => void }) {
  const d = error.detail;
  return (
    <div className="problem-box" role="alert">
      <p>
        <strong>Bản dựng lại được cũ hơn dữ liệu máy này từng thấy.</strong>
      </p>
      <p className="small">
        Bản dựng lại được {d ? <>(sửa lần cuối lúc {formatDateTime(d.file_modified_at)}) </> : null}cũ hơn dữ liệu máy này từng thấy
        {d ? <> (lúc {formatDateTime(d.seen_modified_at)})</> : null}; có thể các bản sao lưu mới hơn chưa đồng bộ về máy này: hãy chờ đồng bộ xong,
        kiểm tra máy còn lại, hoặc xem lịch sử phiên bản của dịch vụ đồng bộ. Chưa có gì được ghi.
      </p>
      <button type="button" className="btn subtle wrap" disabled={busy || !canRecover} onClick={onRecoverStale}>
        {busy ? "Đang khôi phục…" : "Vẫn khôi phục bản cũ hơn này"}
      </button>
      <p className="small muted">Nếu bấm, những gì thêm hoặc sửa sau thời điểm của bản đó sẽ không có trong kho.</p>
    </div>
  );
}

/**
 * Khôi phục bằng một mật khẩu chính CŨ: các bản sao lưu nó mở được đều có từ TRƯỚC lần đổi mật khẩu
 * gần nhất. Khôi phục từ đó làm mất mọi thứ sau lần đổi ⇒ khuyên nhập mật khẩu hiện tại; nút "vẫn
 * khôi phục" chỉ là lựa chọn phụ, nói rõ hậu quả.
 */
function OlderPasswordBox({ busy, canRecover, onRecoverOlder }: { busy: boolean; canRecover: boolean; onRecoverOlder: () => void }) {
  return (
    <div className="problem-box" role="alert">
      <p>
        <strong>Mật khẩu này có vẻ là một mật khẩu chính CŨ.</strong>
      </p>
      <p className="small">
        Thư mục sao lưu (hoặc chính máy này) ghi nhận một lần đổi mật khẩu chính <strong>mới hơn</strong> mà mật khẩu vừa nhập không mở được. Nếu
        khôi phục bằng mật khẩu này, kho chỉ gồm những bản sao lưu nó mở được và sẽ dùng lại mật khẩu này — bạn có thể{" "}
        <strong>mất mọi thứ đã thêm hoặc sửa kể từ lần đổi mật khẩu</strong>.
      </p>
      <p className="small">
        <strong>Tốt nhất:</strong> xoá ô mật khẩu, nhập mật khẩu chính HIỆN TẠI (mật khẩu bạn đặt gần đây nhất) rồi thử lại.
      </p>
      <button type="button" className="btn subtle wrap" disabled={busy || !canRecover} onClick={onRecoverOlder}>
        {busy ? "Đang khôi phục…" : "Vẫn khôi phục bằng mật khẩu này"}
      </button>
      <p className="small muted">
        Chỉ bấm nếu bạn không còn nhớ mật khẩu mới hơn, hoặc bạn chắc chắn đây chính là mật khẩu hiện tại (khi đó trong thư mục sao lưu đang có
        file lạ — hãy kiểm tra ai khác có quyền vào thư mục đồng bộ của bạn).
      </p>
    </div>
  );
}

/**
 * Mật khẩu ĐÚNG, nhưng mọi bản sao lưu ghi sau lần đổi mật khẩu chính đã mất: chỉ còn các bản có từ
 * trước lần đổi. App không tự dùng chúng (trước lần đổi, người biết mật khẩu cũ có thể đã sửa hoặc
 * cài bản sao lưu) ⇒ chủ kho phải chọn rõ ràng, và được nhắc kiểm tra lại sau khi khôi phục.
 */
function OldBackupsOnlyBox({ busy, canRecover, onRecoverOlder }: { busy: boolean; canRecover: boolean; onRecoverOlder: () => void }) {
  return (
    <div className="problem-box" role="alert">
      <p>
        <strong>Chỉ còn các bản sao lưu có từ trước lần đổi mật khẩu chính gần nhất.</strong>
      </p>
      <p className="small">
        Mật khẩu bạn nhập là đúng, nhưng những bản sao lưu ghi <strong>sau</strong> lần đổi mật khẩu đều đã mất. App không tự dùng các bản cũ hơn:
        nếu bạn đã đổi mật khẩu vì nghi bị lộ, nội dung của chúng có thể đã bị người khác sửa trước khi bạn đổi.
      </p>
      <p className="small">
        Trước khi bấm, hãy thử tìm bản mới hơn: lịch sử phiên bản / thùng rác của Google Drive, Dropbox, OneDrive, hoặc một thiết bị khác còn mở
        được kho.
      </p>
      <button type="button" className="btn subtle wrap" disabled={busy || !canRecover} onClick={onRecoverOlder}>
        {busy ? "Đang khôi phục…" : "Vẫn khôi phục từ các bản cũ này"}
      </button>
      <p className="small muted">
        Sau khi khôi phục, hãy kiểm tra lại địa chỉ trang web và mật khẩu của các tài khoản quan trọng (ngân hàng, email) trước khi dùng.
      </p>
    </div>
  );
}

/** Không có bản nào dùng được (thư mục sao lưu, bản lưu riêng trên máy): chỉ ra những nơi khác còn có thể giữ bản sao. */
function NoBackupBox({ text, localCopyAt }: { text: string; localCopyAt: number | null }) {
  return (
    <div className="problem-box" role="alert">
      <p>
        <strong>Không khôi phục được: thư mục sao lưu không có bản nào dùng được.</strong>
      </p>
      <p className="small muted">Chi tiết: {text}</p>
      <p className="small">
        {localCopyAt
          ? `Máy này còn giữ một bản lưu riêng của kho (lưu lần cuối: ${formatDateTime(localCopyAt)}), nhưng app không dựng lại được kho từ nó cho file này.`
          : "Máy này cũng không còn bản lưu riêng nào của kho (bản app tự giữ ngoài thư mục đồng bộ mỗi lần lưu)."}
      </p>
      <p className="small">Những nơi khác có thể còn bản sao của kho:</p>
      <ul className="small result-list">
        <li>Lịch sử phiên bản (version history) hoặc thùng rác của Google Drive / Dropbox / OneDrive trên trang web của dịch vụ đó.</li>
        <li>Một máy tính khác còn mở được kho, hoặc điện thoại (app trên điện thoại giữ một bản xem ngoại tuyến).</li>
        <li>
          Công cụ cứu dữ liệu không cần app (<span className="mono">tools/pwv_recover.py</span>) — xem mục “Cứu hộ dữ liệu không cần app” trong
          hướng dẫn README.
        </li>
      </ul>
      <p className="small muted">Đừng tạo kho mới đè lên chỗ này cho tới khi đã tìm hết các nơi trên.</p>
    </div>
  );
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

/** Chủ kho đã chọn rõ ràng khôi phục bằng một mật khẩu cũ ("password"), hay từ các bản có từ trước lần đổi mật khẩu ("backups"). */
type OlderChoice = false | "password" | "backups";

function RecoveredCard({ info, older, stale, onContinue }: Recovered & { onContinue: () => void }) {
  return (
    <div className="lock-screen">
      <div className="lock-card wide-card">
        <h1>Đã khôi phục kho</h1>
        <ul className="result-list">
          {info.from_local_copy ? (
            <li>
              Kho hiện có <strong>{info.entries}</strong> mục. Không còn bản sao lưu nào dùng được, nên kho được dựng lại từ{" "}
              <strong>bản lưu riêng trên máy này</strong> (bản app tự giữ ngoài thư mục đồng bộ mỗi lần lưu), ghi lúc {formatDateTime(info.newest_backup_at)}.
            </li>
          ) : (
            <>
              <li>
                Kho hiện có <strong>{info.entries}</strong> mục, dựng lại từ {info.files_used} bản sao lưu (và bản lưu riêng trên máy này, nếu có).
              </li>
              <li>Bản sao lưu mới nhất được dùng: {formatDateTime(info.newest_backup_at)}.</li>
            </>
          )}
          {info.archived && (
            <li>
              File hỏng đã được cất ở: <span className="path selectable">{info.archived}</span>
            </li>
          )}
          {info.rescue_kept > 0 && <li>{info.rescue_kept} bản cứu hộ chưa gộp được, vẫn được giữ lại (app thử lại ở lần mở khoá sau).</li>}
          {info.old_local_archived > 0 && <li className="warn-text">Bản lưu riêng trên máy này được ghi bằng mật khẩu chính CŨ và có nội dung mà kho hiện tại không có. App KHÔNG tự gộp nội dung ghi bằng mật khẩu cũ (nếu mật khẩu cũ từng bị lộ, đó có thể không phải thay đổi của bạn). Bản đó đã được cất vào thư mục sao lưu với nhãn «ghi bằng mật khẩu cũ» — mở Cài đặt → Sao lưu để xem và lấy lại từng mục nếu đúng là của bạn.</li>}
        </ul>
        {older === "password" && (
          <div className="warning small">
            Kho đã quay về <strong>mật khẩu chính cũ</strong> (mật khẩu bạn vừa nhập) và chỉ có dữ liệu của các bản sao lưu cũ. Những gì thêm hoặc sửa sau
            lần đổi mật khẩu không có trong kho. Các bản sao lưu ghi bằng mật khẩu mới hơn vẫn còn trong thư mục sao lưu một thời gian — nếu nhớ ra mật
            khẩu đó, có thể mở chúng bằng công cụ cứu dữ liệu (xem README). Trên các thiết bị khác, hãy mở kho bằng mật khẩu bạn vừa nhập.
          </div>
        )}
        {older === "backups" && (
          <div className="warning small">
            Kho được dựng lại từ các bản sao lưu có từ <strong>trước lần đổi mật khẩu chính gần nhất</strong>; những gì thêm hoặc sửa sau lần đổi không có
            trong kho. Trước khi dùng, hãy kiểm tra lại <strong>địa chỉ trang web và mật khẩu</strong> của các tài khoản quan trọng (ngân hàng, email).
          </div>
        )}
        {stale && (
          <div className="warning small">
            Bạn đã chọn khôi phục một bản <strong>cũ hơn</strong> dữ liệu máy này từng thấy: những gì thêm hoặc sửa sau thời điểm đó không có trong kho. Nếu
            máy khác còn bản mới hơn, mở kho ở máy đó — app sẽ tự gộp khi file của nó đồng bộ về.
          </div>
        )}
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
  const [mode, setMode] = useState<"main" | "recover" | "create" | "local">("main");
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ShownError | null>(null);
  const [recovered, setRecovered] = useState<Recovered | null>(null);
  const lastOpts = useRef<RecoverOpts>({});
  const chooser = useExistingVaultChooser(onRetry);

  async function runRecover(opts: RecoverOpts) {
    if (!status.vault_path || !pw || busy) return;
    const merged = { ...lastOpts.current, ...opts };
    lastOpts.current = merged;
    setBusy(true);
    setError(null);
    try {
      const r = await api.recoverVault(status.vault_path, pw, merged);
      setPw("");
      setRecovered({ info: r, older: merged.allowOlder ? (error?.code === "old_backups_only" ? "backups" : "password") : false, stale: !!merged.allowStale });
    } catch (err) {
      const code = errorCode(err);
      setError(toShown(err));
      // Mật khẩu cũ / bản cũ hơn: giữ lại để nút "vẫn khôi phục…" dùng được ngay.
      if (code !== "older_password" && code !== "old_backups_only" && code !== "older_than_seen") setPw("");
    } finally {
      setBusy(false);
    }
  }

  function recover(e: React.FormEvent) {
    e.preventDefault();
    lastOpts.current = {};
    runRecover({});
  }

  async function restoreLocal() {
    setBusy(true);
    setError(null);
    try {
      await api.restoreLocalCopy();
      onRetry();
    } catch (e) {
      setError(toShown(e));
    } finally {
      setBusy(false);
    }
  }

  if (recovered) return <RecoveredCard {...recovered} onContinue={onRecovered} />;
  if (mode === "create") return <CreateVault onBack={() => setMode("main")} onOpenExisting={chooser.choose} onCreated={onRecovered} chooserBox={chooser.box} />;

  return (
    <div className="lock-screen">
      {chooser.box}
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
        {status.local_copy_at && mode !== "recover" && (
          <div className="note-box">
            <p className="small">
              Máy này còn giữ một bản lưu riêng của kho (lưu lần cuối: <strong>{formatDateTime(status.local_copy_at)}</strong>).
            </p>
            {mode === "local" ? (
              <div className="confirm-box">
                <p className="small">
                  Ghi bản lưu riêng này thành file kho ở <span className="path">{status.vault_path}</span>? App không ghi đè nếu ở đó đã có file. Nếu kho đã được
                  chuyển sang thư mục khác ở máy kia, hãy bấm “Chọn file kho…” và chọn file ở vị trí mới thay vì tạo lại ở đây.
                </p>
                <div className="row gap confirm-actions">
                  <button className="btn primary" disabled={busy} onClick={restoreLocal}>
                    {busy ? "Đang ghi…" : "Tạo lại file kho"}
                  </button>
                  <button className="btn" disabled={busy} onClick={() => setMode("main")}>
                    Huỷ
                  </button>
                </div>
              </div>
            ) : (
              <button className="btn" onClick={() => setMode("local")}>
                <Icon name="restore" /> Tạo lại file kho từ bản lưu riêng
              </button>
            )}
          </div>
        )}
        {error && (RECOVER_BOXES.has(error.code) ? (
          <RecoverErrorBox error={error} busy={busy} canRecover={!!pw} localCopyAt={status.local_copy_at} onRecover={(o) => runRecover(o ?? {})} />
        ) : (
          <p className="error">{error.text}</p>
        ))}
        {chooser.error && <p className="error">{chooser.error}</p>}
        {mode === "recover" ? (
          <form className="confirm-box" onSubmit={recover}>
            <p className="small">
              Dựng lại kho từ các bản sao lưu tự động trong thư mục <span className="path">{status.vault_path}.backups</span> (không còn bản nào thì từ bản lưu
              riêng trên máy này). Nhập mật khẩu chính:
            </p>
            <input
              type="password"
              value={pw}
              onChange={(e) => {
                setPw(e.target.value);
                setError(null);
                lastOpts.current = {};
              }}
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
            <button className="btn wide" onClick={chooser.choose}>
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
  const chooser = useExistingVaultChooser(onDone);
  const openExisting = chooser.choose;
  const error = chooser.error;

  if (mode === "create") return <CreateVault onBack={() => setMode("choose")} onOpenExisting={openExisting} onCreated={onCreated} chooserBox={chooser.box} />;

  return (
    <div className="lock-screen">
      {chooser.box}
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
function CreateVault({
  onBack,
  onOpenExisting,
  onCreated,
  chooserBox,
}: {
  onBack: () => void;
  onOpenExisting: () => void;
  onCreated: () => void;
  /** Hộp hỏi "bản xung đột" của việc mở kho có sẵn (hiện nổi). */
  chooserBox?: React.ReactNode;
}) {
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
        {chooserBox}
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
