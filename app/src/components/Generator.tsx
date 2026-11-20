import { useCallback, useEffect, useState } from "react";
import { api, errorText } from "../api";
import type { Generated, PassphraseOptions, PasswordOptions } from "../types";
import { Icon, StrengthMeter, useToast } from "./ui";

const DEFAULT_PW: PasswordOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  exclude_ambiguous: false,
  require_each: true,
};
const DEFAULT_PP: PassphraseOptions = { words: 6, separator: "-", capitalize: true, add_number: true };

function loadPrefs<T>(key: string, fallback: T): T {
  try {
    return { ...fallback, ...JSON.parse(localStorage.getItem(key) ?? "{}") };
  } catch {
    return fallback;
  }
}
function savePrefs(key: string, v: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {
    /* bỏ qua */
  }
}

/** Bộ tạo mật khẩu. Nếu có `onUse` thì hiện nút "Dùng mật khẩu này". */
export function Generator({ onUse, compact }: { onUse?: (v: string) => void; compact?: boolean }) {
  const toast = useToast();
  const [mode, setMode] = useState<"password" | "passphrase">(() => {
    try {
      return localStorage.getItem("gen.mode") === "passphrase" ? "passphrase" : "password";
    } catch {
      return "password";
    }
  });
  const [pw, setPw] = useState<PasswordOptions>(() => loadPrefs("gen.pw", DEFAULT_PW));
  const [pp, setPp] = useState<PassphraseOptions>(() => loadPrefs("gen.pp", DEFAULT_PP));
  const [out, setOut] = useState<Generated | null>(null);
  const [error, setError] = useState<string | null>(null);

  const regenerate = useCallback(async () => {
    try {
      setError(null);
      setOut(await api.generate(mode === "password" ? { mode, ...pw } : { mode, ...pp }));
    } catch (e) {
      setError(errorText(e));
      setOut(null);
    }
  }, [mode, pw, pp]);

  useEffect(() => {
    regenerate();
    savePrefs("gen.pw", pw);
    savePrefs("gen.pp", pp);
    try {
      localStorage.setItem("gen.mode", mode);
    } catch {
      /* bỏ qua */
    }
  }, [regenerate, mode, pw, pp]);

  async function copy() {
    if (!out) return;
    const secs = await api.copyText(out.value);
    toast(`Đã sao chép — clipboard tự xoá sau ${secs} giây`);
  }

  const check = (key: keyof PasswordOptions, label: string) => (
    <label className="check">
      <input type="checkbox" checked={pw[key] as boolean} onChange={(e) => setPw({ ...pw, [key]: e.target.checked })} />
      {label}
    </label>
  );

  return (
    <div className={compact ? "generator compact" : "generator"}>
      <div className="tabs" role="tablist">
        <button type="button" role="tab" aria-selected={mode === "password"} className={mode === "password" ? "tab active" : "tab"} onClick={() => setMode("password")}>
          Ký tự ngẫu nhiên
        </button>
        <button type="button" role="tab" aria-selected={mode === "passphrase"} className={mode === "passphrase" ? "tab active" : "tab"} onClick={() => setMode("passphrase")}>
          Cụm từ dễ nhớ
        </button>
      </div>

      <div className="gen-output mono" aria-live="polite">
        {out?.value ?? (error ? <span className="error">{error}</span> : "…")}
      </div>
      <StrengthMeter strength={out?.strength ?? null} entropy={out?.entropy_bits} />

      <div className="row gap">
        <button type="button" className="btn" onClick={regenerate}>
          <Icon name="dice" /> Tạo lại
        </button>
        <button type="button" className="btn" onClick={copy} disabled={!out}>
          <Icon name="copy" /> Sao chép
        </button>
        {onUse && (
          <button type="button" className="btn primary" onClick={() => out && onUse(out.value)} disabled={!out}>
            Dùng mật khẩu này
          </button>
        )}
      </div>

      {mode === "password" ? (
        <div className="gen-options">
          <label className="slider">
            <span>Độ dài: <strong>{pw.length}</strong></span>
            <input type="range" min={8} max={64} value={pw.length} onChange={(e) => setPw({ ...pw, length: Number(e.target.value) })} />
          </label>
          <div className="checks">
            {check("uppercase", "Chữ hoa A–Z")}
            {check("lowercase", "Chữ thường a–z")}
            {check("digits", "Số 0–9")}
            {check("symbols", "Ký hiệu !@#$")}
            {check("exclude_ambiguous", "Bỏ ký tự dễ nhầm (0 O l 1 I)")}
          </div>
        </div>
      ) : (
        <div className="gen-options">
          <label className="slider">
            <span>Số từ: <strong>{pp.words}</strong></span>
            <input type="range" min={4} max={10} value={pp.words} onChange={(e) => setPp({ ...pp, words: Number(e.target.value) })} />
          </label>
          <div className="checks">
            <label className="check">
              Ngăn cách
              <select value={pp.separator} onChange={(e) => setPp({ ...pp, separator: e.target.value })}>
                <option value="-">gạch ngang (-)</option>
                <option value=" ">dấu cách</option>
                <option value=".">dấu chấm (.)</option>
                <option value="_">gạch dưới (_)</option>
              </select>
            </label>
            <label className="check">
              <input type="checkbox" checked={pp.capitalize} onChange={(e) => setPp({ ...pp, capitalize: e.target.checked })} />
              Viết hoa chữ đầu
            </label>
            <label className="check">
              <input type="checkbox" checked={pp.add_number} onChange={(e) => setPp({ ...pp, add_number: e.target.checked })} />
              Thêm một chữ số
            </label>
          </div>
          <small className="muted">Cụm từ tiếng Anh từ danh sách EFF (7.776 từ) — dễ nhớ, rất phù hợp làm master password.</small>
        </div>
      )}
    </div>
  );
}
