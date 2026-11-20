import { useState } from "react";
import { api, errorText, pickFile } from "../api";
import type { MoveView, Status } from "../types";

const sep = (p: string) => (p.includes("/") && !p.includes("\\") ? "/" : "\\");

/** Ghi kho đang mở sang vị trí mới (có bước xác nhận). Dùng ở Cài đặt và ở cảnh báo file kho có vấn đề. */
export function MoveVault({
  status,
  onMoved,
  label = "Chuyển kho sang thư mục khác…",
  buttonClass = "btn",
  rescue = false,
}: {
  status: Status;
  onMoved: (r: MoveView) => void;
  label?: string;
  buttonClass?: string;
  /** Đang cứu dữ liệu vì file kho có vấn đề: lời giải thích khác đi. */
  rescue?: boolean;
}) {
  const [target, setTarget] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function choose() {
    setError(null);
    try {
      const fileName = status.vault_path?.split(/[\\/]/).pop() ?? "vault.pwv";
      const suggested = await api.suggestPath().catch(() => "");
      const dir = suggested.replace(/[\\/][^\\/]*$/, "");
      const p = await pickFile({
        save: true,
        title: rescue ? "Chọn nơi lưu bản đang mở" : "Chọn thư mục mới cho kho",
        defaultPath: dir ? `${dir}${sep(dir)}${fileName}` : fileName,
        filters: [{ name: "Kho pwv", extensions: ["pwv"] }],
      });
      if (p) setTarget(p);
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function move() {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.moveVault(target);
      setTarget(null);
      onMoved(r);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  if (!target) {
    return (
      <>
        <button className={buttonClass} onClick={choose}>
          {label}
        </button>
        {error && <p className="error">{error}</p>}
      </>
    );
  }
  return (
    <div className="confirm-box">
      <p className="small">
        <strong>{rescue ? "Lưu bản đang mở sang vị trí khác" : "Chuyển kho"}</strong>
        <br />
        <span className="muted">Từ:</span> <span className="path">{status.vault_path}</span>
        <br />
        <span className="muted">Sang:</span> <span className="path">{target}</span>
      </p>
      <ul className="small muted">
        {rescue ? (
          <li>App ghi bản đang mở ra chỗ mới. Mọi thứ ở chỗ cũ được giữ nguyên, không bị xoá.</li>
        ) : (
          <li>App ghi kho sang chỗ mới, đọc lại để kiểm tra, rồi mới xoá file ở chỗ cũ. Thư mục sao lưu được chuyển theo.</li>
        )}
        <li>Trên máy khác, mở app và chọn “Mở file kho có sẵn” ở vị trí mới.</li>
      </ul>
      {error && <p className="error">{error}</p>}
      <div className="row gap">
        <button className="btn primary" disabled={busy} onClick={move}>
          {busy ? "Đang ghi…" : rescue ? "Lưu sang đây" : "Chuyển"}
        </button>
        <button className="btn" disabled={busy} onClick={() => setTarget(null)}>
          Huỷ
        </button>
      </div>
    </div>
  );
}

/** Lời báo sau khi chuyển kho. */
export function moveMessage(r: MoveView): string {
  if (r.rescued) return `Đã ghi một BẢN SAO của kho sang ${r.new_path}. Mọi thứ ở vị trí cũ được giữ nguyên, không bị xoá. Từ giờ app dùng kho ở vị trí mới.`;
  if (!r.old_removed) return `Đã chuyển kho sang ${r.new_path}. File ở vị trí cũ chưa xoá được — bạn có thể tự xoá.`;
  return `Đã chuyển kho sang ${r.new_path}.`;
}
