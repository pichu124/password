import { useState } from "react";
import { api, errorText, pickFile } from "../api";
import type { MoveView, Status } from "../types";

const SAME_FOLDER_TEXT =
  "Hãy chọn một thư mục KHÁC thư mục đang chứa file kho (ví dụ một thư mục con mới bên trong nó): file mới đặt ngay cạnh file kho cũ sẽ bị coi là bản xung đột của nó.";

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
  /** Đang cứu dữ liệu vì file kho có vấn đề: CHỈ ghi một bản sao (không đụng gì ở chỗ cũ), lời giải thích khác đi. */
  rescue?: boolean;
}) {
  const [target, setTarget] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function choose() {
    setError(null);
    try {
      const fileName = status.vault_path?.split(/[\\/]/).pop() ?? "vault.pwv";
      // Cứu dữ liệu: gợi ý một thư mục con MỚI bên trong thư mục đang chứa file kho — vẫn được đồng bộ, mà không phải chính
      // thư mục của file kho (file đặt ngay cạnh sẽ bị coi là bản xung đột).
      let dir: string;
      let prepared = false;
      if (rescue && status.vault_path) {
        const day = new Date().toISOString().slice(0, 10);
        try {
          // Tạo sẵn thư mục con: hộp thoại lưu file của Windows bỏ qua một thư mục chưa có.
          dir = await api.prepareCopyFolder(day);
          prepared = true;
        } catch {
          const vdir = status.vault_path.replace(/[\\/][^\\/]*$/, "");
          dir = vdir && vdir !== status.vault_path ? `${vdir}${sep(vdir)}Ban sao ${day}` : "";
        }
      } else {
        const suggested = await api.suggestPath().catch(() => "");
        dir = suggested.replace(/[\\/][^\\/]*$/, "");
      }
      const p = await pickFile({
        save: true,
        title: rescue ? "Chọn nơi lưu bản đang mở (một thư mục KHÁC thư mục của file kho, nên nằm trong thư mục đồng bộ)" : "Chọn thư mục mới cho kho",
        defaultPath: dir ? `${dir}${sep(dir)}${fileName}` : fileName,
        filters: [{ name: "Kho pwv", extensions: ["pwv"] }],
      });
      const folder = (x: string) => x.replace(/[\\/][^\\/]*$/, "").toLowerCase();
      // Không lưu vào thư mục con vừa tạo (huỷ, hoặc chọn chỗ khác): xoá lại nó nếu vẫn trống.
      if (prepared && (!p || folder(p) !== dir.toLowerCase())) api.discardCopyFolder().catch(() => {});
      if (!p) return;
      if (rescue && status.vault_path && folder(p) === folder(status.vault_path)) {
        setError(SAME_FOLDER_TEXT);
        return;
      }
      setTarget(p);
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function move() {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.moveVault(target, rescue);
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
          <>
            <li>App chỉ ghi một BẢN SAO của bản đang mở ra chỗ mới. Mọi thứ ở chỗ cũ (file kho, thư mục sao lưu) được giữ nguyên, không bị xoá hay ghi đè.</li>
            <li>Từ giờ máy này dùng file ở chỗ mới. Các máy khác vẫn dùng file ở chỗ cũ cho tới khi bạn chọn lại file trên từng máy (“Dùng kho khác” ở màn hình mở khoá).</li>
            <li>
              <strong>Nếu chỗ mới KHÔNG nằm trong thư mục đồng bộ (Google Drive / Dropbox / OneDrive), bản này KHÔNG được đồng bộ với các máy khác cho tới khi bạn chuyển nó vào đó.</strong>
            </li>
          </>
        ) : (
          <>
            <li>App ghi kho sang chỗ mới, đọc lại để kiểm tra, rồi mới xoá file ở chỗ cũ. Thư mục sao lưu được chuyển theo.</li>
            <li>Trên máy khác, app sẽ báo không tìm thấy file kho: bấm “Chọn file kho…” và chọn file ở vị trí mới.</li>
          </>
        )}
      </ul>
      {error && <p className="error">{error}</p>}
      <div className="row gap">
        <button className="btn primary" disabled={busy} onClick={move}>
          {busy ? "Đang ghi…" : rescue ? "Lưu sang đây" : "Chuyển"}
        </button>
        <button
          className="btn"
          disabled={busy}
          onClick={() => {
            setTarget(null);
            if (rescue) api.discardCopyFolder().catch(() => {});
          }}
        >
          Huỷ
        </button>
      </div>
    </div>
  );
}

/** Lời báo sau khi chuyển kho. */
export function moveMessage(r: MoveView): string {
  if (r.rescued)
    return `Đã ghi một BẢN SAO của kho sang ${r.new_path}. Từ giờ máy này dùng file ở vị trí mới. File ở vị trí cũ (${r.old_path}) được giữ nguyên, không bị xoá hay ghi đè — nó có thể còn chứa thay đổi mới hơn từ máy khác. Trên các máy khác, hãy chọn lại file ở vị trí mới (“Dùng kho khác” ở màn hình mở khoá). Nếu chỗ mới KHÔNG nằm trong thư mục đồng bộ (Google Drive / Dropbox / OneDrive), bản này KHÔNG được đồng bộ với các máy khác cho tới khi bạn chuyển nó vào đó.`;
  if (!r.old_removed) return `Đã chuyển kho sang ${r.new_path}. File ở vị trí cũ chưa xoá được — bạn có thể tự xoá.`;
  return `Đã chuyển kho sang ${r.new_path}.`;
}
