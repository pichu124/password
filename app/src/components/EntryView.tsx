import { useEffect, useState } from "react";
import { api, errorText } from "../api";
import type { EntryDetail, HistoryView, TotpCode } from "../types";
import { avatarHue, formatDate, Icon, initials, StrengthMeter, useToast } from "./ui";

/** Chi tiết một mục. `readOnly` (điện thoại): ẩn Sửa / Xoá / Yêu thích. */
export function EntryView({
  id,
  onEdit,
  onDeleted,
  onChanged,
  readOnly = false,
}: {
  id: string;
  onEdit?: () => void;
  onDeleted?: () => void;
  onChanged?: () => void;
  readOnly?: boolean;
}) {
  const toast = useToast();
  const [e, setE] = useState<EntryDetail | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [totp, setTotp] = useState<TotpCode | null>(null);
  const [history, setHistory] = useState<HistoryView[] | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    setRevealed(null);
    setHistory(null);
    setConfirmDelete(false);
    setTotp(null);
    api.get(id).then(setE).catch((err) => toast(errorText(err), "error"));
  }, [id, toast]);

  // Mã 2FA cập nhật mỗi giây.
  useEffect(() => {
    if (!e?.has_totp) return;
    let alive = true;
    const tick = () => api.totp(id).then((t) => alive && setTotp(t)).catch(() => {});
    tick();
    const t = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [id, e?.has_totp]);

  // Tự ẩn mật khẩu sau 30 giây.
  useEffect(() => {
    if (revealed === null) return;
    const t = setTimeout(() => setRevealed(null), 30_000);
    return () => clearTimeout(t);
  }, [revealed]);

  if (!e) return <div className="detail empty" />;

  async function copy(field: "password" | "username" | "totp" | "url", label: string) {
    try {
      const secs = await api.copyField(id, field);
      toast(`Đã sao chép ${label} — tự xoá sau ${secs} giây`);
    } catch (err) {
      toast(errorText(err), "error");
    }
  }

  async function toggleReveal() {
    setRevealed(revealed === null ? await api.reveal(id) : null);
  }

  async function del() {
    try {
      await api.remove(id);
      toast(`Đã xoá “${e!.title}”`);
      onDeleted?.();
    } catch (err) {
      toast(errorText(err), "error");
    }
  }

  async function fav() {
    await api.toggleFavorite(id);
    setE({ ...e!, favorite: !e!.favorite });
    onChanged?.();
  }

  return (
    <div className="detail">
      <header className="detail-head">
        <div className="avatar big" style={{ background: `hsl(${avatarHue(e.title)} 45% 45%)` }}>
          {initials(e.title)}
        </div>
        <div className="grow">
          <h2>{e.title}</h2>
          {e.tags.length > 0 && (
            <div className="tags">
              {e.tags.map((t) => (
                <span key={t} className="tag">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
        {readOnly ? (
          e.favorite && <span className="star big-star">★</span>
        ) : (
          <>
            <button className={e.favorite ? "icon-btn fav on" : "icon-btn fav"} onClick={fav} title={e.favorite ? "Bỏ yêu thích" : "Yêu thích"}>
              <Icon name="star" />
            </button>
            <button className="btn" onClick={onEdit}>
              <Icon name="edit" /> Sửa
            </button>
          </>
        )}
      </header>

      <div className="fields">
        {e.username && (
          <div className="kv">
            <label>Tên đăng nhập</label>
            <div className="kv-value">
              <span className="selectable">{e.username}</span>
              <button className="icon-btn" onClick={() => copy("username", "tên đăng nhập")} title="Sao chép">
                <Icon name="copy" />
              </button>
            </div>
          </div>
        )}

        {e.has_password && (
          <div className="kv">
            <label>Mật khẩu</label>
            <div className="kv-value">
              <span className="mono selectable">{revealed ?? "••••••••••••"}</span>
              <button className="icon-btn" onClick={toggleReveal} title={revealed === null ? "Hiện" : "Ẩn"}>
                <Icon name={revealed === null ? "eye" : "eyeOff"} />
              </button>
              <button className="icon-btn" onClick={() => copy("password", "mật khẩu")} title="Sao chép">
                <Icon name="copy" />
              </button>
            </div>
            <StrengthMeter strength={e.strength} />
          </div>
        )}

        {e.has_totp && (
          <div className="kv">
            <label>Mã xác thực 2 bước {e.totp_label && <span className="muted">· {e.totp_label}</span>}</label>
            <div className="kv-value">
              <span className="totp mono">{totp ? `${totp.code.slice(0, 3)} ${totp.code.slice(3)}` : "··· ···"}</span>
              {totp && (
                <span className={totp.remaining <= 5 ? "ring warn" : "ring"} style={{ ["--p" as string]: `${(totp.remaining / totp.period) * 100}%` }}>
                  {totp.remaining}
                </span>
              )}
              <button className="icon-btn" onClick={() => copy("totp", "mã 2FA")} title="Sao chép">
                <Icon name="copy" />
              </button>
            </div>
          </div>
        )}

        {e.urls.map((u) => (
          <div className="kv" key={u}>
            <label>Trang web</label>
            <div className="kv-value">
              <span className="selectable url">{u}</span>
              <button className="icon-btn" onClick={() => copy("url", "địa chỉ")} title="Sao chép">
                <Icon name="copy" />
              </button>
            </div>
          </div>
        ))}

        {e.notes && (
          <div className="kv">
            <label>Ghi chú</label>
            <pre className="notes selectable">{e.notes}</pre>
          </div>
        )}

        {e.history_count > 0 && (
          <div className="kv">
            <label>Lịch sử mật khẩu</label>
            {history === null ? (
              <button className="btn link" onClick={async () => setHistory(await api.history(id))}>
                Xem {e.history_count} mật khẩu cũ
              </button>
            ) : (
              <ul className="history">
                {history.map((h, i) => (
                  <li key={i}>
                    <span className="mono selectable">{h.password}</span>
                    <span className="muted small">đổi lúc {formatDate(h.replaced_at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      <footer className="detail-foot">
        <span className="muted small">
          Tạo {formatDate(e.created_at)} · Sửa {formatDate(e.updated_at)}
        </span>
        {readOnly ? null : confirmDelete ? (
          <span className="row gap">
            <span>Xoá mục này?</span>
            <button className="btn danger" onClick={del}>
              Xoá
            </button>
            <button className="btn" onClick={() => setConfirmDelete(false)}>
              Không
            </button>
          </span>
        ) : (
          <button className="btn subtle" onClick={() => setConfirmDelete(true)}>
            <Icon name="trash" /> Xoá
          </button>
        )}
      </footer>
    </div>
  );
}
