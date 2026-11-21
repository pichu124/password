import { useState } from "react";
import { api, errorText, pickFile } from "../api";
import type { ConflictHint } from "../types";
import { Icon } from "./ui";

export const VAULT_FILTER = [{ name: "Kho pwv", extensions: ["pwv"] }];

/**
 * Chọn một file kho CÓ SẴN. Trước khi dùng, hỏi backend (chỉ đọc header) xem file vừa chọn có phải bản xung đột do
 * dịch vụ đồng bộ tạo ra của một file kho khác cùng thư mục không — nếu phải, khuyên dùng file gốc.
 * `onChosen` nhận đường dẫn cuối cùng. Trả về `choose` (mở hộp thoại) và `box` (hộp hỏi, hiện nổi trên màn hình).
 */
export function useVaultChooser(onChosen: (path: string) => Promise<void> | void) {
  const [hint, setHint] = useState<{ picked: string; h: ConflictHint } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function finish(p: string) {
    setHint(null);
    try {
      await onChosen(p);
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function choose() {
    setError(null);
    try {
      const p = await pickFile({ title: "Chọn file kho (.pwv)", filters: VAULT_FILTER });
      if (!p) return;
      const h = await api.checkVaultChoice(p).catch(() => null);
      if (h) setHint({ picked: p, h });
      else await finish(p);
    } catch (e) {
      setError(errorText(e));
    }
  }

  const box = hint ? (
    <div className="modal-backdrop">
      <div className="lock-card wide-card" role="alertdialog" aria-label="Có vẻ là bản xung đột">
        <h1>
          <Icon name="warn" size={22} /> Có vẻ là bản xung đột
        </h1>
        <p className="small">
          Bạn vừa chọn <strong>«{hint.h.picked_name}»</strong> — có vẻ là <strong>BẢN XUNG ĐỘT</strong> do dịch vụ đồng bộ tạo ra của{" "}
          <strong>«{hint.h.original_name}»</strong> (cùng một kho). Nên dùng file gốc nếu nó còn mở được; app sẽ tự gộp bản còn lại.
        </p>
        <div className="choice-col">
          <button className="btn primary wide wrap" onClick={() => finish(hint.h.original_path)}>
            Dùng «{hint.h.original_name}» (nên chọn)
          </button>
          <button className="btn wide wrap" onClick={() => finish(hint.picked)}>
            Vẫn dùng file vừa chọn
          </button>
          <button className="btn subtle-link" onClick={() => setHint(null)}>
            Huỷ
          </button>
        </div>
      </div>
    </div>
  ) : null;

  return { choose, box, error };
}
