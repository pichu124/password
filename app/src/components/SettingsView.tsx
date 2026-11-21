import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorText, pickFile } from "../api";
import type { BackupEntryView, BackupKind, BackupView, ImportView, MoveView, PasswordChangeView, Settings, Status, UpdateInfo } from "../types";
import { MasterPasswordField, useMasterCheck } from "./MasterField";
import { MoveVault, moveMessage } from "./MoveVault";
import { formatDate, formatDateTime, Icon, useToast } from "./ui";

export function SettingsView({
  status,
  section,
  focusAt,
  onImported,
  onSwitchVault,
  onMoved,
  onChanged,
}: {
  status: Status;
  /** Cuộn tới mục này khi mở (ví dụ từ thông báo "bản ghi bằng mật khẩu cũ"). */
  section?: "backups";
  /** Đổi giá trị ⇒ cuộn lại (bấm lại cùng một nút khi trang cài đặt đang mở). */
  focusAt?: number;
  /** Dữ liệu kho vừa thay đổi (nhập CSV, khôi phục từ bản sao lưu) ⇒ tải lại danh sách. */
  onImported: () => void;
  onSwitchVault: () => void;
  onMoved: (r: MoveView) => void;
  /** Cài đặt / trạng thái vừa đổi ⇒ đọc lại status. */
  onChanged: () => void;
}) {
  const toast = useToast();
  const [s, setS] = useState<Settings | null>(null);
  const [backups, setBackups] = useState<string | null>(null);
  const [moved, setMoved] = useState<MoveView | null>(null);
  const backupsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (section === "backups") backupsRef.current?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [section, focusAt]);

  useEffect(() => {
    api.getSettings().then(setS).catch((e) => toast(errorText(e), "error"));
    api.backupsDir().then(setBackups).catch(() => {});
  }, [toast]);

  async function update(next: Settings) {
    setS(next);
    try {
      await api.setSettings(next);
      toast("Đã lưu cài đặt");
      onChanged();
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  return (
    <div className="detail">
      <header className="detail-head">
        <h2 className="grow">Cài đặt</h2>
      </header>
      <div className="fields">
        <section className="card">
          <h3>Bảo mật</h3>
          {s && (
            <>
              <label className="field inline">
                <span>Tự khoá sau khi không dùng</span>
                <select value={s.auto_lock_minutes} onChange={(e) => update({ ...s, auto_lock_minutes: Number(e.target.value) })}>
                  {[1, 2, 5, 10, 15, 30, 60].map((m) => (
                    <option key={m} value={m}>
                      {m} phút
                    </option>
                  ))}
                  <option value={0}>Không tự khoá (không khuyến nghị)</option>
                </select>
              </label>
              <label className="field inline">
                <span>Tự xoá clipboard sau</span>
                <select value={s.clipboard_clear_secs} onChange={(e) => update({ ...s, clipboard_clear_secs: Number(e.target.value) })}>
                  {[10, 20, 30, 60, 120].map((x) => (
                    <option key={x} value={x}>
                      {x} giây
                    </option>
                  ))}
                </select>
              </label>
            </>
          )}
          <ul className="small security-notes">
            <li>
              <strong>Bộ nhớ:</strong> chỉ <em>khoá giải mã</em> được giữ trong vùng RAM không bị ghi xuống đĩa
              {status.memory_locked ? "" : " (máy này không cho phép khoá vùng RAM đó)"}. Mật khẩu bạn đang mở xem không được bảo vệ như vậy — hãy bật mã
              hoá ổ đĩa (BitLocker) và khoá app (Ctrl+L) mỗi khi rời máy.
            </li>
            <li>
              <strong>Chụp màn hình:</strong> cửa sổ app được loại khỏi ảnh chụp và quay màn hình trên Windows 10 bản 2004 trở lên.
            </li>
            <li>
              <strong>Clipboard:</strong> thứ bạn sao chép từ app không vào lịch sử clipboard (Win+V) và được xoá sau {s?.clipboard_clear_secs ?? "N"} giây
              — kể cả khi app đã khoá hoặc bạn đã đóng cửa sổ (app chờ xoá xong rồi mới thoát hẳn).
            </li>
          </ul>
        </section>

        {s && <AboutUpdates settings={s} onChange={update} />}

        <ChangeMaster />

        <ImportCsv onImported={onImported} />

        <div ref={backupsRef} className="scroll-anchor">
          <BackupsPanel onRestored={onImported} />
        </div>

        <section className="card">
          <h3>File kho & đồng bộ</h3>
          <p className="small">
            <span className="muted">File kho:</span> <span className="path selectable">{status.vault_path}</span>
          </p>
          <p className="small">
            <span className="muted">Thư mục sao lưu tự động:</span> <span className="path selectable">{backups ?? "—"}</span>
          </p>
          <p className="muted small">
            Đồng bộ: đặt file kho trong thư mục Google Drive, Dropbox hoặc OneDrive trên mỗi máy. App tự kiểm tra thay đổi mỗi 20 giây và tự gộp
            khi hai máy cùng sửa.
          </p>
          {moved && <div className={moved.rescued ? "note-box" : "ok-box"}>{moveMessage(moved)}</div>}
          <MoveVault
            status={status}
            onMoved={(r) => {
              setMoved(r);
              api.backupsDir().then(setBackups).catch(() => {});
              onMoved(r);
            }}
          />
          <button className="btn subtle-link" onClick={onSwitchVault}>
            Mở một kho khác…
          </button>
        </section>
      </div>
    </div>
  );
}

function AboutUpdates({ settings, onChange }: { settings: Settings; onChange: (s: Settings) => void }) {
  const toast = useToast();
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const [found, setFound] = useState<UpdateInfo | null>(null);

  useEffect(() => {
    api.appVersion().then(setVersion).catch(() => {});
  }, []);

  async function checkNow() {
    setBusy(true);
    try {
      const u = await api.checkUpdate();
      setFound(u?.available ? u : null);
      if (!u) toast("Chưa có bản phát hành nào trên GitHub", "info");
      else if (!u.available) toast(`Bạn đang dùng bản mới nhất (${u.current})`);
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h3>Phiên bản & cập nhật</h3>
      <p className="small">
        <span className="muted">Đang dùng:</span> <strong>pwv {version}</strong>
      </p>
      <label className="check">
        <input type="checkbox" checked={settings.check_updates} onChange={(e) => onChange({ ...settings, check_updates: e.target.checked })} />
        Tự kiểm tra bản mới mỗi ngày
      </label>
      <p className="muted small">
        App chỉ hỏi GitHub xem có bản mới không rồi báo cho bạn; không tự tải hay tự cài. Không có dữ liệu kho nào được gửi đi.
      </p>
      {found && (
        <div className="confirm-box">
          <p className="small">
            Có bản mới <strong>{found.latest}</strong>.
          </p>
          {found.notes && <pre className="notes small">{found.notes}</pre>}
          <button className="btn primary" onClick={() => api.openReleasePage(found.latest).catch((e) => toast(errorText(e), "error"))}>
            Mở trang tải
          </button>
        </div>
      )}
      <button className="btn" disabled={busy} onClick={checkNow}>
        {busy ? "Đang kiểm tra…" : "Kiểm tra ngay"}
      </button>
    </section>
  );
}

function ChangeMaster() {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [next2, setNext2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PasswordChangeView | null>(null);
  const mc = useMasterCheck();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const c = await mc.run(next);
      if (!c?.ok) return;
      const r = await api.changeMaster(cur, next);
      setResult(r);
      setCur("");
      setNext("");
      setNext2("");
      mc.reset();
    } catch (err) {
      // Mọi lỗi ở đây xảy ra TRƯỚC khi đổi (sai mật khẩu, mật khẩu yếu, file kho hỏng / biến mất khi
      // đồng bộ trước…) hoặc khiến lần đổi bị hoàn tác — nói rõ để người dùng không tưởng đã đổi xong.
      setError(`Mật khẩu chính CHƯA được đổi: ${errorText(err)}`);
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <section className="card">
        <h3>Đã đổi mật khẩu chính</h3>
        <p className="small">
          Mật khẩu chính <strong>đã được đổi</strong>: kho trên máy này đã dùng mật khẩu mới. Đã mã hoá lại <strong>{result.backups_reencrypted}</strong> bản
          sao lưu bằng mật khẩu mới.
        </p>
        {result.unverified && (
          <div className="note-box">
            Đã lưu, nhưng chưa kiểm tra lại được file vừa ghi (có thể chương trình đồng bộ hoặc diệt virus đang giữ file). App sẽ tự kiểm tra lại ở lần
            đồng bộ tới. Mật khẩu mới vẫn là mật khẩu đúng từ bây giờ.
          </div>
        )}
        {result.backups_skipped > 0 && (
          <p className="small">
            <strong>{result.backups_skipped}</strong> bản sao lưu được để nguyên, không mã hoá lại: bản không đọc được, hoặc bản được ghi bằng một mật
            khẩu chính cũ hơn nữa (những bản đó vẫn mở được bằng mật khẩu cũ ấy; app cố ý không mã hoá lại chúng vì không chắc chúng là của bạn).
          </p>
        )}
        <div className="warning small">
          <p>
            <strong>Những bản sao đã rời khỏi máy này vẫn mở được bằng mật khẩu CŨ</strong> và chứa dữ liệu tại thời điểm đó: lịch sử phiên bản
            và thùng rác của Google Drive / Dropbox / OneDrive, bản lưu ngoại tuyến trên điện thoại, các máy tính khác chưa đồng bộ.
          </p>
          <p>
            Từ nay <strong>đừng bao giờ gõ lại mật khẩu cũ</strong>. Những gì được ghi bằng mật khẩu cũ (ví dụ trên một thiết bị chưa nhận mật khẩu
            mới) sẽ không được gộp tự động mà hiện thành “bản ghi bằng mật khẩu cũ” trong Sao lưu &amp; khôi phục để bạn xem lại.
          </p>
          <p>
            Nếu mật khẩu cũ có thể đã bị lộ, hãy đổi mật khẩu của các tài khoản quan trọng (ngân hàng, email). Các thiết bị khác sẽ hỏi mật khẩu
            mới ở lần mở tới.
          </p>
        </div>
        <button className="btn" onClick={() => setResult(null)}>
          Đã hiểu
        </button>
      </section>
    );
  }

  return (
    <form className="card" onSubmit={submit}>
      <h3>Đổi mật khẩu chính</h3>
      <label className="field">
        <span>Mật khẩu chính hiện tại</span>
        <input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="off" spellCheck={false} data-secret />
      </label>
      <MasterPasswordField label="Mật khẩu chính mới" value={next} onChange={setNext} mc={mc} />
      <label className="field">
        <span>Nhập lại mật khẩu chính mới</span>
        <input type="password" value={next2} onChange={(e) => setNext2(e.target.value)} autoComplete="off" spellCheck={false} data-secret />
        {next2 && next !== next2 && <small className="error">Chưa khớp.</small>}
      </label>
      {error && <p className="error">{error}</p>}
      <button className="btn primary" disabled={busy || !cur || !next || next !== next2}>
        <Icon name="key" /> {busy ? "Đang đổi…" : "Đổi mật khẩu chính"}
      </button>
    </form>
  );
}

function ImportCsv({ onImported }: { onImported: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ImportView | null>(null);
  const [deleted, setDeleted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setError(null);
    const p = await pickFile({ title: "Chọn file CSV mật khẩu", filters: [{ name: "CSV", extensions: ["csv"] }] });
    if (!p) return;
    setBusy(true);
    try {
      const r = await api.importCsv(p);
      setResult(r);
      setDeleted(false);
      onImported();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function deleteCsv() {
    setBusy(true);
    try {
      await api.deleteImportedCsv();
      setDeleted(true);
      toast("Đã xoá file CSV");
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h3>Nhập mật khẩu từ trình duyệt / app khác</h3>
      <p className="small muted">
        Chrome / Edge: Cài đặt → Mật khẩu → Xuất mật khẩu. Bitwarden: Tools → Export vault (.csv). KeePassXC: Database → Export → CSV.
        Firefox, 1Password, Proton Pass cũng được hỗ trợ.
      </p>
      {result && (
        <div className="confirm-box">
          <p className="small">
            <strong>{result.detected}:</strong> đã nhập <strong>{result.imported}</strong> mục · bỏ qua {result.duplicates} mục trùng hệt mục đã có ·{" "}
            {result.skipped} dòng trống / không dùng được.
          </p>
          {result.similar.length > 0 && (
            <div className="small">
              <p>Đã nhập, nhưng có vẻ trùng với mục khác — hãy rà lại:</p>
              <ul className="name-list">
                {result.similar.map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            </div>
          )}
          {result.bad_totp.length > 0 && (
            <div className="small">
              <p>Mã 2FA không đọc được (giá trị gốc nằm trong ghi chú của mục):</p>
              <ul className="name-list">
                {result.bad_totp.map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="warning small">
            File CSV chứa toàn bộ mật khẩu ở dạng chữ thường, ai mở cũng đọc được. Hãy xoá nó ngay sau khi kiểm tra.
            <br />
            Nếu file nằm trong thư mục đồng bộ (OneDrive / Google Drive / Dropbox), hãy dọn cả <strong>thùng rác trên cloud</strong> sau khi xoá.
          </div>
          <div className="row gap confirm-actions">
            {deleted ? (
              <span className="check-ok small">✓ Đã xoá file CSV trên máy này.</span>
            ) : (
              <button className="btn danger" disabled={busy} onClick={deleteCsv}>
                <Icon name="trash" /> Xoá file CSV ngay
              </button>
            )}
            <button className="btn" onClick={() => setResult(null)}>
              Đóng
            </button>
          </div>
        </div>
      )}
      {error && <p className="error">{error}</p>}
      <button className="btn" disabled={busy} onClick={run}>
        {busy && !result ? "Đang nhập…" : "Chọn file CSV…"}
      </button>
    </section>
  );
}

const KIND_LABEL: Record<BackupKind, string> = {
  auto: "Tự động",
  merged: "Bản xung đột đã gộp",
  damaged: "File hỏng đã cất",
  oldkey: "Bản chưa gộp",
};

/**
 * Bản này chứa nội dung ghi bằng một mật khẩu chính CŨ: hoặc nó chỉ mở được bằng khoá cũ, hoặc nó là
 * bản "oldkey-…" mà app đã cất thay vì gộp. Cả hai có thể không phải do chủ kho ghi (ai biết mật khẩu
 * cũ cũng làm ra được) ⇒ luôn gắn nhãn và cảnh báo trước khi khôi phục.
 */
const writtenWithOldPassword = (b: BackupView) => b.kind === "oldkey" || b.retired_key;

function statusText(e: BackupEntryView): string {
  if (e.status === "changed") return `Khác hiện tại: ${e.changed_fields.join(", ")}`;
  if (e.status === "in_trash") return "Đang trong thùng rác";
  return "Hiện không còn";
}

/** Danh sách bản sao lưu, xem khác biệt và khôi phục từng mục. */
function BackupsPanel({ onRestored }: { onRestored: () => void }) {
  const toast = useToast();
  const [list, setList] = useState<BackupView[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [chosen, setChosen] = useState<BackupView | null>(null);
  const [diff, setDiff] = useState<BackupEntryView[] | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  // Bản ghi bằng mật khẩu cũ: người dùng phải xác nhận một lần trước khi được khôi phục.
  const [oldPwAck, setOldPwAck] = useState(false);

  const load = useCallback(async () => {
    try {
      const l = await api.listBackups();
      setList([...l].sort((a, b) => b.timestamp - a.timestamp));
      setListError(null);
    } catch (e) {
      setListError(errorText(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function choose(b: BackupView) {
    setChosen(b);
    setDiff(null);
    setDiffError(null);
    setPicked(new Set());
    setOldPwAck(false);
    try {
      setDiff(await api.backupDiff(b.name));
    } catch (e) {
      setDiffError(errorText(e));
    }
  }

  async function restore() {
    if (!chosen || picked.size === 0) return;
    setBusy(true);
    try {
      const n = await api.restoreFromBackup(chosen.name, [...picked]);
      toast(`Đã khôi phục ${n} mục từ bản sao lưu`);
      onRestored();
      await choose(chosen);
      load();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const toggle = (id: string) =>
    setPicked((cur) => {
      const n = new Set(cur);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  return (
    <section className="card">
      <h3>Sao lưu & khôi phục</h3>
      <p className="small muted">
        App tự giữ các bản sao lưu của kho. Chọn một bản để xem những mục khác với hiện tại, rồi khôi phục từng mục. Khôi phục là một lần sửa mới:
        mật khẩu hiện tại của mục được giữ trong lịch sử của nó, và thay đổi được đồng bộ tới mọi thiết bị. Bản có nhãn “ghi bằng mật khẩu cũ”
        không bao giờ được gộp tự động — hãy xem kỹ trước khi khôi phục mục nào từ nó.
      </p>
      {listError && <p className="error">{listError}</p>}
      {list && list.length === 0 && <p className="muted small">Chưa có bản sao lưu nào.</p>}
      {list && list.length > 0 && (
        <table className="backup-table">
          <thead>
            <tr>
              <th>Thời điểm</th>
              <th>Loại</th>
              <th>Số mục</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.map((b) => (
              <tr key={b.name} className={chosen?.name === b.name ? "selected" : undefined}>
                <td>{formatDateTime(b.timestamp)}</td>
                <td>
                  {KIND_LABEL[b.kind] ?? b.kind}
                  {writtenWithOldPassword(b) && <span className="badge warn-badge">ghi bằng mật khẩu cũ</span>}
                </td>
                <td>{b.entries ?? <span className="muted">không đọc được</span>}</td>
                <td className="right">
                  <button className="btn link" onClick={() => choose(b)}>
                    Xem khác biệt
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {chosen && (
        <div className="confirm-box">
          <p className="small">
            <strong>Bản sao lưu lúc {formatDateTime(chosen.timestamp)}</strong> ({KIND_LABEL[chosen.kind] ?? chosen.kind})
            {writtenWithOldPassword(chosen) && <span className="badge warn-badge">ghi bằng mật khẩu cũ</span>}
          </p>
          {diffError && <p className="error">{diffError}</p>}
          {diff === null && !diffError && <p className="muted small">Đang so sánh…</p>}
          {diff && diff.length === 0 && <p className="small">Mọi mục trong bản này đều giống hiện tại — không có gì để khôi phục.</p>}
          {diff && diff.length > 0 && (
            <>
              <ul className="diff-list">
                {diff.map((d) => (
                  <li key={d.id}>
                    <label className="check">
                      <input type="checkbox" checked={picked.has(d.id)} onChange={() => toggle(d.id)} />
                      <span className="grow">
                        <strong>{d.title}</strong> <span className="muted small">{d.username}</span>
                        <br />
                        <span className={d.status === "changed" ? "small" : "small warn-text"}>{statusText(d)}</span>
                        <span className="muted small"> · sửa lúc {formatDate(d.updated_at)}</span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
              {writtenWithOldPassword(chosen) && (
                <div className="warning old-pw-warning" role="alert">
                  <p>
                    <strong>Bản này được ghi bằng một mật khẩu chính CŨ.</strong> Nó có thể là của chính bạn — từ một thiết bị chưa nhận mật khẩu mới,
                    hoặc từ trước lần đổi mật khẩu — nhưng cũng có thể do một người khác biết mật khẩu cũ tạo ra. Chỉ khôi phục từ bản này nếu bạn chắc
                    chắn những thay đổi đó là của bạn; sau khi khôi phục, hãy kiểm tra lại địa chỉ trang web và mật khẩu của các mục đó.
                  </p>
                  <label className="check">
                    <input type="checkbox" checked={oldPwAck} onChange={(e) => setOldPwAck(e.target.checked)} />
                    <span>Tôi chắc chắn những thay đổi trong bản này là của tôi</span>
                  </label>
                </div>
              )}
              <div className="row gap confirm-actions">
                <button className="btn primary" disabled={busy || picked.size === 0 || (writtenWithOldPassword(chosen) && !oldPwAck)} onClick={restore}>
                  <Icon name="restore" /> {busy ? "Đang khôi phục…" : `Khôi phục mục đã chọn (${picked.size})`}
                </button>
                <button className="btn" onClick={() => setChosen(null)}>
                  Đóng
                </button>
              </div>
            </>
          )}
          {(diffError || (diff && diff.length === 0)) && (
            <button className="btn" onClick={() => setChosen(null)}>
              Đóng
            </button>
          )}
        </div>
      )}
    </section>
  );
}
