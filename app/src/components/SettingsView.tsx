import { useEffect, useState } from "react";
import { api, errorText, pickFile } from "../api";
import type { Settings, Status, Strength, UpdateInfo } from "../types";
import { Icon, StrengthMeter, useDebounced, useToast } from "./ui";

export function SettingsView({
  status,
  onImported,
  onSwitchVault,
  onMoved,
}: {
  status: Status;
  onImported: () => void;
  onSwitchVault: () => void;
  onMoved: () => void;
}) {
  const toast = useToast();
  const [s, setS] = useState<Settings | null>(null);
  const [backups, setBackups] = useState<string | null>(null);

  useEffect(() => {
    api.getSettings().then(setS);
    api.backupsDir().then(setBackups);
  }, []);

  async function update(next: Settings) {
    setS(next);
    try {
      await api.setSettings(next);
      toast("Đã lưu cài đặt");
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
          <p className="muted small">
            Khoá giải mã {status.memory_locked ? "đang được khoá trong RAM (không bị ghi xuống pagefile)" : "không khoá được trong RAM trên máy này"}.
            Cửa sổ app được chặn chụp màn hình và chia sẻ màn hình. Mật khẩu sao chép không vào lịch sử clipboard (Win+V).
          </p>
        </section>

        {s && <AboutUpdates settings={s} onChange={update} />}

        <ChangeMaster />

        <ImportCsv onImported={onImported} />

        <section className="card">
          <h3>File kho & đồng bộ</h3>
          <p className="small">
            <span className="muted">File kho:</span> <span className="path selectable">{status.vault_path}</span>
          </p>
          <p className="small">
            <span className="muted">Sao lưu tự động (10 bản gần nhất):</span> <span className="path selectable">{backups}</span>
          </p>
          <p className="muted small">
            Đồng bộ: đặt file kho trong thư mục Google Drive, Dropbox hoặc OneDrive trên mỗi máy. App tự kiểm tra thay đổi mỗi 20 giây và tự gộp
            khi hai máy cùng sửa.
          </p>
          <MoveVault
            status={status}
            onMoved={() => {
              api.backupsDir().then(setBackups);
              onMoved();
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
    api.appVersion().then(setVersion);
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
          <button className="btn primary" onClick={() => api.openReleasePage(found.page_url)}>
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

/** Chuyển kho sang thư mục khác (ví dụ từ Documents sang Dropbox), có bước xác nhận. */
function MoveVault({ status, onMoved }: { status: Status; onMoved: () => void }) {
  const toast = useToast();
  const [target, setTarget] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function choose() {
    setError(null);
    const fileName = status.vault_path?.split(/[\\/]/).pop() ?? "vault.pwv";
    const suggestedDir = status.suggested_path.replace(/[\\/][^\\/]*$/, "");
    const p = await pickFile({
      save: true,
      title: "Chọn thư mục mới cho kho",
      defaultPath: `${suggestedDir}${suggestedDir.includes("/") ? "/" : "\\"}${fileName}`,
      filters: [{ name: "Kho pwv", extensions: ["pwv"] }],
    });
    if (p) setTarget(p);
  }

  async function move() {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.moveVault(target);
      toast(r.old_removed ? "Đã chuyển kho sang vị trí mới" : "Đã chuyển kho. File ở vị trí cũ chưa xoá được — bạn có thể tự xoá.", r.old_removed ? "ok" : "info");
      setTarget(null);
      onMoved();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  if (!target) {
    return (
      <>
        <button className="btn" onClick={choose}>
          Chuyển kho sang thư mục khác…
        </button>
        {error && <p className="error">{error}</p>}
      </>
    );
  }
  return (
    <div className="confirm-box">
      <p className="small">
        <strong>Chuyển kho</strong>
        <br />
        <span className="muted">Từ:</span> <span className="path">{status.vault_path}</span>
        <br />
        <span className="muted">Sang:</span> <span className="path">{target}</span>
      </p>
      <ul className="small muted">
        <li>App ghi kho sang chỗ mới, đọc lại để kiểm tra, rồi mới xoá file ở chỗ cũ. Thư mục sao lưu được chuyển theo.</li>
        <li>Trên máy khác, mở app và chọn “Mở kho có sẵn” ở vị trí mới.</li>
      </ul>
      {error && <p className="error">{error}</p>}
      <div className="row gap">
        <button className="btn primary" disabled={busy} onClick={move}>
          {busy ? "Đang chuyển…" : "Chuyển"}
        </button>
        <button className="btn" disabled={busy} onClick={() => setTarget(null)}>
          Huỷ
        </button>
      </div>
    </div>
  );
}

function ChangeMaster() {
  const toast = useToast();
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [next2, setNext2] = useState("");
  const [strength, setStrength] = useState<Strength | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dn = useDebounced(next, 200);

  useEffect(() => {
    if (!dn) return setStrength(null);
    api.strength(dn).then(setStrength);
  }, [dn]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.changeMaster(cur, next);
      toast("Đã đổi master password. Lần sau hãy dùng mật khẩu mới trên mọi máy.");
      setCur("");
      setNext("");
      setNext2("");
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h3>Đổi master password</h3>
      <label className="field">
        <span>Master password hiện tại</span>
        <input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" />
      </label>
      <label className="field">
        <span>Master password mới</span>
        <input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />
        {next && <StrengthMeter strength={strength} />}
      </label>
      <label className="field">
        <span>Nhập lại</span>
        <input type="password" value={next2} onChange={(e) => setNext2(e.target.value)} autoComplete="new-password" />
        {next2 && next !== next2 && <small className="error">Chưa khớp.</small>}
      </label>
      {error && <p className="error">{error}</p>}
      <button className="btn primary" disabled={busy || !cur || !next || next !== next2}>
        <Icon name="key" /> {busy ? "Đang đổi…" : "Đổi master password"}
      </button>
    </form>
  );
}

function ImportCsv({ onImported }: { onImported: () => void }) {
  const toast = useToast();
  const [deleteAfter, setDeleteAfter] = useState(true);
  const [busy, setBusy] = useState(false);

  async function run() {
    const p = await pickFile({ title: "Chọn file CSV mật khẩu", filters: [{ name: "CSV", extensions: ["csv"] }] });
    if (!p) return;
    setBusy(true);
    try {
      const r = await api.importCsv(p, deleteAfter);
      toast(`${r.detected}: đã nhập ${r.imported} mục, bỏ qua ${r.duplicates} mục trùng${r.csv_deleted ? ", đã xoá file CSV" : ""}`);
      onImported();
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
      <label className="check">
        <input type="checkbox" checked={deleteAfter} onChange={(e) => setDeleteAfter(e.target.checked)} />
        Xoá file CSV sau khi nhập (khuyến nghị — file chứa mật khẩu dạng rõ)
      </label>
      <button className="btn" disabled={busy} onClick={run}>
        {busy ? "Đang nhập…" : "Chọn file CSV…"}
      </button>
    </section>
  );
}
