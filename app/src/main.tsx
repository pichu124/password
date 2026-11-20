import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import MobileApp from "./MobileApp";
import { ToastProvider } from "./components/ui";
import "./styles.css";

// Chặn menu chuột phải mặc định của trình duyệt (Reload/Inspect...) trong app.
if (import.meta.env.PROD) {
  window.addEventListener("contextmenu", (e) => {
    const t = e.target as HTMLElement;
    if (!t.closest("input, textarea, .selectable")) e.preventDefault();
  });
}

// Chặn In (Ctrl+P) và Tải lại trang (F5, Ctrl+R): in ra hoặc nạp lại trang khi đang hiện mật khẩu là
// không mong muốn (app tự nạp lại trang đúng lúc — sau khi khoá).
window.addEventListener(
  "keydown",
  (e) => {
    const k = e.key.toLowerCase();
    const mod = e.ctrlKey || e.metaKey;
    if (e.key === "F5" || (mod && (k === "p" || k === "r"))) {
      e.preventDefault();
      e.stopPropagation();
    }
  },
  { capture: true },
);

// Điện thoại (Android) dùng giao diện chỉ-xem riêng. `?mobile` để xem thử trong trình duyệt.
const IS_PHONE = /Android|iPhone|iPad/i.test(navigator.userAgent) || new URLSearchParams(location.search).has("mobile");

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ToastProvider>{IS_PHONE ? <MobileApp /> : <App />}</ToastProvider>
  </StrictMode>,
);
