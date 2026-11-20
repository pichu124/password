import { useState } from "react";
import { api, errorText } from "../api";
import type { MasterCheck } from "../types";
import { Icon } from "./ui";

/** Có ký tự ngoài bảng ASCII (chữ có dấu, emoji…) — có thể khó gõ trên bàn phím điện thoại. */
export const hasNonAscii = (s: string) => /[^\x20-\x7E]/.test(s);

/**
 * Trạng thái chấm master password. Chỉ chấm khi người dùng rời ô nhập hoặc bấm nút — KHÔNG chấm
 * theo từng phím (mỗi lần gọi để lại một bản sao mật khẩu trong bộ đệm IPC).
 */
export function useMasterCheck() {
  const [check, setCheck] = useState<MasterCheck | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  async function run(pw: string): Promise<MasterCheck | null> {
    if (!pw) {
      setCheck(null);
      return null;
    }
    try {
      const c = await api.masterCheck(pw);
      setCheck(c);
      setCheckError(null);
      return c;
    } catch (e) {
      setCheckError(errorText(e));
      return null;
    }
  }
  return { check, checkError, run, reset: () => setCheck(null) };
}

/**
 * Ô nhập master password (tạo kho / đổi mật khẩu chính): ẩn ký tự, có nút mắt; "Gợi ý" điền một cụm
 * 6 từ ngẫu nhiên và HIỆN ra để người dùng chép ra giấy; sửa tay thì ẩn lại.
 */
export function MasterPasswordField({
  label,
  value,
  onChange,
  mc,
  autoFocus,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  mc: ReturnType<typeof useMasterCheck>;
  autoFocus?: boolean;
}) {
  const [show, setShow] = useState(false);
  const [suggested, setSuggested] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);

  async function suggest() {
    try {
      const g = await api.generate({ mode: "passphrase", words: 6, separator: "-", capitalize: false, add_number: true });
      onChange(g.value);
      setShow(true);
      setSuggested(true);
      setGenError(null);
      mc.run(g.value);
    } catch (e) {
      setGenError(errorText(e));
    }
  }

  return (
    <div className="field">
      <span>{label}</span>
      <div className="row">
        <input
          type={show ? "text" : "password"}
          className="mono"
          value={value}
          onChange={(e) => {
            onChange(e.target.value);
            // Sửa tay ⇒ ẩn lại và bỏ kết quả chấm cũ (sẽ chấm lại khi rời ô).
            setShow(false);
            setSuggested(false);
            mc.reset();
          }}
          onBlur={() => mc.run(value)}
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          data-secret
          autoFocus={autoFocus}
          aria-label={label}
        />
        <button type="button" className="icon-btn" onClick={() => setShow(!show)} title={show ? "Ẩn" : "Hiện"} aria-label={show ? "Ẩn" : "Hiện"}>
          <Icon name={show ? "eyeOff" : "eye"} />
        </button>
        <button type="button" className="btn" onClick={suggest} title="Gợi ý một cụm 6 từ ngẫu nhiên">
          <Icon name="dice" /> Gợi ý
        </button>
      </div>
      {suggested && show && (
        <div className="passphrase-show">
          <div className="mono selectable">{value}</div>
          <small>Hãy chép cụm từ này ra giấy ngay (đúng từng chữ và dấu gạch), cất ở nơi an toàn, rồi nhập lại ở ô bên dưới.</small>
        </div>
      )}
      {mc.check && <small className={mc.check.ok ? "check-ok" : "error"}>{mc.check.ok ? "✓ Đạt yêu cầu" : mc.check.message}</small>}
      {mc.checkError && <small className="error">{mc.checkError}</small>}
      {genError && <small className="error">{genError}</small>}
      {hasNonAscii(value) && (
        <small className="muted">
          Mật khẩu có chữ có dấu hoặc ký tự đặc biệt. Bạn sẽ phải gõ đúng y hệt trên mọi thiết bị (cả bàn phím điện thoại) — nên dùng các từ
          không dấu.
        </small>
      )}
    </div>
  );
}
