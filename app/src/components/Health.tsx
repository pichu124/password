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
  // Chưa kiểm tra rò rỉ được thì điểm không thể coi là "tốt".
  const tone = h.score >= 80 && h.breach_check_done ? "good" : h.score >= 50 ? "warn" : "bad";

  return (
    <div className="detail">
      <header className="detail-head">
        <div className={`score ${tone}`}>{h.score}</div>
        <div className="grow">
          <h2>Sức khoẻ mật khẩu</h2>
          <p className="muted small">
            {h.checked} mục · {h.breach_check_done ? `${h.breached} đã bị lộ` : "chưa kiểm tra rò rỉ"} · {h.reused} dùng trùng · {h.weak} yếu · {h.old} lâu chưa đổi
          </p>
        </div>
      </header>

      <div className="fields">
        {h.breach_error && (
          <div className="problem-box">
            <strong>Không kiểm tra được rò rỉ dữ liệu.</strong> {h.breach_error}
            <br />
            <span className="small">Kết quả bên dưới CHƯA gồm phần kiểm tra rò rỉ — đừng coi là an toàn. Hãy kiểm tra lại khi có mạng.</span>
          </div>
        )}
        <div className="info-box">
          {h.breach_check_done ? (
            <span>✓ Đã kiểm tra rò rỉ với Have I Been Pwned.</span>
          ) : h.breach_error ? (
            <span>Kiểm tra rò rỉ chưa thành công.</span>
          ) : (
            <span>Chưa kiểm tra rò rỉ dữ liệu.</span>
          )}{" "}
          <span className="muted small">
            Chỉ 5 ký tự đầu của mã băm SHA-1 được gửi đi — mật khẩu của bạn không bao giờ rời khỏi máy.
          </span>
          <div>
            <button className="btn primary" disabled={busy} onClick={() => run(true)}>
              <Icon name="shield" /> {busy ? "Đang kiểm tra…" : h.breach_error ? "Thử kiểm tra lại" : "Kiểm tra rò rỉ qua mạng"}
            </button>
          </div>
        </div>

        {h.items.length === 0 ? (
          h.breach_check_done ? (
            <p className="ok-big">✅ Không phát hiện vấn đề nào.</p>
          ) : (
            <p className="muted">
              Không thấy mật khẩu yếu, dùng trùng hay quá cũ. <strong>Chưa biết</strong> mật khẩu nào đã bị lộ hay chưa — hãy bấm “Kiểm tra rò rỉ qua
              mạng”.
            </p>
          )
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
        <p className="muted small">Mẹo: mở mục, bấm “Sửa” → “Tạo” để thay bằng mật khẩu ngẫu nhiên mạnh → bấm <strong>“Lưu”</strong>, rồi mới đổi mật khẩu trên trang web tương
          ứng (mật khẩu cũ vẫn nằm trong Lịch sử của mục).</p>
      </div>
    </div>
  );
}
