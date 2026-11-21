import { useCallback, useEffect, useState } from "react";
import { api, errorText } from "../api";
import type { Generated, GeneratedItem, PassphraseOptions, PasswordOptions } from "../types";
import { formatDateTime, Icon, StrengthMeter, useAutoHide, useToast } from "./ui";

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

/**
 * Bộ tạo mật khẩu. Nếu có `onUse` thì hiện nút "Dùng mật khẩu này". Mỗi giá trị rời bộ tạo (sao chép / dùng) được
 * ghi nhớ trong backend (mã hoá bằng khoá kho) để không bao giờ mất một mật khẩu đã kịp đặt trên trang web.
 * `label`: tiêu đề mục đang sửa. `onCopied`: trong form, sao chép cũng là dùng.
 */
export function Generator({
  onUse,
  onCopied,
  compact,
  label,
  recordable = true,
}: {
  onUse?: (v: string) => void;
  onCopied?: (v: string) => void;
  compact?: boolean;
  label?: string;
  /** false trên điện thoại (chỉ đọc — không có nơi ghi nhớ). */
  recordable?: boolean;
}) {
  const toast = useToast();
  const [recentKey, setRecentKey] = useState(0);
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

  async function record(value: string) {
    if (!recordable) return;
    try {
      await api.recordGenerated(value, label?.trim() || null);
      setRecentKey((k) => k + 1);
    } catch {
      /* kho đã khoá / chỉ đọc: không có nơi ghi nhớ */
    }
  }

  async function copy() {
    if (!out) return;
    const value = out.value;
    try {
      const secs = await api.copyText(value);
      await record(value);
      onCopied?.(value);
      toast(onCopied ? `Đã sao chép và điền vào ô mật khẩu — clipboard tự xoá sau ${secs} giây` : `Đã sao chép — clipboard tự xoá sau ${secs} giây`);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  async function use() {
    if (!out || !onUse) return;
    const value = out.value;
    await record(value);
    onUse(value);
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
          <button type="button" className="btn primary" onClick={use} disabled={!out}>
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
      {!compact && recordable && <RecentGenerated refreshKey={recentKey} />}
    </div>
  );
}

/** "Mật khẩu vừa tạo gần đây": chỉ hiện khi có. Giá trị chỉ được gửi sang giao diện khi bấm Hiện (tự ẩn sau 30 giây). */
export function RecentGenerated({ refreshKey }: { refreshKey: number }) {
  const toast = useToast();
  const [items, setItems] = useState<GeneratedItem[]>([]);
  const [shown, setShown] = useState<{ id: string; value: string } | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  useAutoHide(shown, () => setShown(null));

  const load = useCallback(() => {
    api.listGenerated().then(setItems).catch(() => setItems([]));
  }, []);
  useEffect(() => {
    load();
  }, [load, refreshKey]);

  if (items.length === 0) return null;

  async function reveal(id: string) {
    if (shown?.id === id) return setShown(null);
    try {
      setShown({ id, value: await api.revealGenerated(id) });
    } catch (e) {
      toast(errorText(e), "error");
      load();
    }
  }
  async function copy(id: string) {
    try {
      const secs = await api.copyGenerated(id);
      toast(`Đã sao chép — clipboard tự xoá sau ${secs} giây`);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }
  async function clear() {
    try {
      await api.clearGenerated();
      setShown(null);
      setConfirmClear(false);
      load();
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  return (
    <section className="recent-gen">
      <h3>Mật khẩu vừa tạo gần đây</h3>
      <p className="small muted">Chỉ lưu trên máy này (đã mã hoá bằng khoá kho), tự xoá sau 30 ngày.</p>
      <ul className="history">
        {items.map((g) => (
          <li key={g.id}>
            <span className="grow">
              <span className="small">{formatDateTime(g.at)}</span>
              {g.label && <span className="muted small"> · {g.label}</span>}
              {shown?.id === g.id && (
                <span className="mono selectable recent-value" data-secret>
                  {shown.value}
                </span>
              )}
            </span>
            <button type="button" className="btn link" onClick={() => reveal(g.id)}>
              {shown?.id === g.id ? "Ẩn" : "Hiện"}
            </button>
            <button type="button" className="icon-btn" onClick={() => copy(g.id)} title="Sao chép" aria-label="Sao chép mật khẩu vừa tạo">
              <Icon name="copy" />
            </button>
          </li>
        ))}
      </ul>
      {confirmClear ? (
        <div className="row gap">
          <span className="small">Xoá cả danh sách này? Các mật khẩu đã lưu trong các mục không bị ảnh hưởng.</span>
          <button type="button" className="btn danger" onClick={clear}>
            Xoá danh sách
          </button>
          <button type="button" className="btn" onClick={() => setConfirmClear(false)}>
            Không
          </button>
        </div>
      ) : (
        <button type="button" className="btn subtle" onClick={() => setConfirmClear(true)}>
          <Icon name="trash" /> Xoá danh sách
        </button>
      )}
    </section>
  );
}
