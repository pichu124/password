import { useEffect, useState } from "react";
import { api, errorText } from "../api";
import type { HealthView } from "../types";
import { Icon, useToast } from "./ui";

export function Health({ onOpen }: { onOpen: (id: string) => void }) {
  const toast = useToast();
  const [h, setH] = useState<HealthView | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(online: boolean) {
    setBusy(true);
    try {
      const r = await api.health(online);
      setH(r);
      if (r.breach_error) toast(r.breach_error, "error");
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    run(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!h) return <div className="detail empty" />;
  const tone = h.score >= 80 ? "good" : h.score >= 50 ? "warn" : "bad";

  return (
    <div className="detail">
      <header className="detail-head">
        <div className={`score ${tone}`}>{h.score}</div>
        <div className="grow">
          <h2>Sức khoẻ mật khẩu</h2>
          <p className="muted small">
            {h.checked} mục · {h.breached} đã bị lộ · {h.reused} dùng trùng · {h.weak} yếu · {h.old} lâu chưa đổi
          </p>
        </div>
      </header>

      <div className="fields">
        <div className="info-box">
          {h.breach_check_done ? (
            <span>✓ Đã kiểm tra rò rỉ với Have I Been Pwned.</span>
          ) : (
            <span>Chưa kiểm tra rò rỉ dữ liệu.</span>
          )}{" "}
          <span className="muted small">
            Chỉ 5 ký tự đầu của mã băm SHA-1 được gửi đi — mật khẩu của bạn không bao giờ rời khỏi máy.
          </span>
          <div>
            <button className="btn primary" disabled={busy} onClick={() => run(true)}>
              <Icon name="shield" /> {busy ? "Đang kiểm tra…" : "Kiểm tra rò rỉ qua mạng"}
            </button>
          </div>
        </div>

        {h.items.length === 0 ? (
          <p className="ok-big">✅ Không phát hiện vấn đề nào.</p>
        ) : (
          <ul className="health-list">
            {h.items.map((it) => (
              <li key={it.id}>
                <button className="health-item" onClick={() => onOpen(it.id)}>
                  <span className={`dot sev${Math.min(it.severity, 3)}`} />
                  <span className="grow">
                    <strong>{it.title}</strong> <span className="muted small">{it.username}</span>
                    <br />
                    <span className="small">{it.issues.join(" · ")}</span>
                  </span>
                  <span className="muted small">Sửa →</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        <p className="muted small">Mẹo: mở mục, bấm “Sửa” → “Tạo” để thay bằng mật khẩu ngẫu nhiên mạnh, rồi đổi mật khẩu trên trang web tương ứng.</p>
      </div>
    </div>
  );
}
