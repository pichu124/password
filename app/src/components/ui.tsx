import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import type { Strength } from "../types";

// ------------------------------------------------------------------ Thông báo (toast)

type ToastKind = "ok" | "error" | "info";
interface Toast {
  id: number;
  kind: ToastKind;
  text: string;
}
const ToastCtx = createContext<(text: string, kind?: ToastKind) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);
  const push = useCallback((text: string, kind: ToastKind = "ok") => {
    const id = nextId.current++;
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 6000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

// ------------------------------------------------------------------ Thanh độ mạnh

const STRENGTH_COLORS = ["var(--bad)", "var(--bad)", "var(--warn)", "var(--good)", "var(--good)"];

export function StrengthMeter({ strength, entropy }: { strength: Strength | null; entropy?: number }) {
  const score = strength?.score ?? -1;
  return (
    <div className="strength">
      <div className="strength-bar" aria-hidden>
        {[0, 1, 2, 3].map((i) => (
          <span key={i} style={{ background: score > i || (score === 0 && i === 0 && strength) ? STRENGTH_COLORS[Math.max(score, 0)] : undefined }} />
        ))}
      </div>
      <span className="strength-label">
        {strength ? strength.label : "—"}
        {entropy !== undefined && ` · ≈ ${Math.round(entropy)} bit`}
      </span>
    </div>
  );
}

// ------------------------------------------------------------------ Icon (SVG nội tuyến)

const paths: Record<string, string> = {
  copy: "M8 8h11v11H8zM5 5h11v2H7v9H5z",
  eye: "M12 5C6 5 2 12 2 12s4 7 10 7 10-7 10-7-4-7-10-7zm0 11a4 4 0 110-8 4 4 0 010 8z",
  eyeOff: "M3 4l17 17-1.4 1.4-3.2-3.2A10.6 10.6 0 0112 19C6 19 2 12 2 12a18 18 0 014.3-4.9L1.6 5.4zM12 5c6 0 10 7 10 7a18 18 0 01-3 3.9L8.6 5.5A9.7 9.7 0 0112 5z",
  star: "M12 3l2.7 5.6 6.2.9-4.5 4.4 1 6.1L12 17.1 6.6 20l1-6.1L3.1 9.5l6.2-.9z",
  lock: "M7 10V7a5 5 0 0110 0v3h1v11H6V10zm2 0h6V7a3 3 0 00-6 0z",
  plus: "M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6z",
  dice: "M5 4h14a1 1 0 011 1v14a1 1 0 01-1 1H5a1 1 0 01-1-1V5a1 1 0 011-1zm3 3a1.5 1.5 0 100 3 1.5 1.5 0 000-3zm8 7a1.5 1.5 0 100 3 1.5 1.5 0 000-3zm-4-3.5a1.5 1.5 0 100 3 1.5 1.5 0 000-3z",
  shield: "M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5zm-1 13l6-6-1.4-1.4L11 12.2 8.4 9.6 7 11z",
  gear: "M12 8a4 4 0 110 8 4 4 0 010-8zm8.5 5.5l2-1.5-2-3.5-2.4.8a7 7 0 00-1.6-.9L16 6h-4l-.5 2.4a7 7 0 00-1.6.9l-2.4-.8-2 3.5 2 1.5a7 7 0 000 1.8l-2 1.5 2 3.5 2.4-.8c.5.4 1 .7 1.6.9L12 22h4l.5-2.4c.6-.2 1.1-.5 1.6-.9l2.4.8 2-3.5-2-1.5a7 7 0 000-1.8z",
  sync: "M12 4a8 8 0 017.7 6h-2.1A6 6 0 006.3 8.7L9 11H3V5l1.9 1.9A8 8 0 0112 4zm-7.7 10h2.1a6 6 0 0011.3 1.3L15 13h6v6l-1.9-1.9A8 8 0 014.3 14z",
  trash: "M9 3h6l1 2h4v2H4V5h4zm-3 6h12l-1 12H7z",
  edit: "M4 17.2V20h2.8l8.3-8.3-2.8-2.8zM19.7 7a1 1 0 000-1.4l-1.3-1.3a1 1 0 00-1.4 0l-1.2 1.2 2.8 2.8z",
  link: "M10.6 13.4a1 1 0 001.4 1.4l4.9-4.9a3 3 0 00-4.2-4.2l-1.8 1.8 1.4 1.4 1.8-1.8a1 1 0 011.4 1.4zM13.4 10.6a1 1 0 00-1.4-1.4l-4.9 4.9a3 3 0 004.2 4.2l1.8-1.8-1.4-1.4-1.8 1.8a1 1 0 01-1.4-1.4z",
  back: "M15.4 6L9.4 12l6 6-1.4 1.4L6.6 12 14 4.6z",
  key: "M7 14a3 3 0 110-6 3 3 0 010 6zm5.6-4A6 6 0 101 11a6 6 0 0011.6 1H15v2h2v-2h2v2h2v-4z",
};

export function Icon({ name, size = 18 }: { name: keyof typeof paths | string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden fill="currentColor">
      <path d={paths[name] ?? ""} />
    </svg>
  );
}

// ------------------------------------------------------------------ Tiện ích

export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function formatDate(ms: number): string {
  if (!ms) return "—";
  return new Date(ms).toLocaleString("vi-VN", { dateStyle: "medium", timeStyle: "short" });
}

export function initials(title: string): string {
  const t = title.trim();
  return t ? t[0].toUpperCase() : "?";
}

/** Màu nền avatar ổn định theo tiêu đề. */
export function avatarHue(title: string): number {
  let h = 0;
  for (const c of title) h = (h * 31 + c.charCodeAt(0)) % 360;
  return h;
}
