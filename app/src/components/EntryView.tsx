import { useEffect, useState } from "react";
import { api, errorCode, errorText } from "../api";
import type { CopyField, EntryDetail, HistoryView, TotpCode } from "../types";
import { avatarHue, formatDate, Icon, initials, StrengthMeter, useAutoHide, useToast } from "./ui";

/** Chi tiết một mục. `readOnly` (điện thoại): ẩn Sửa / Xoá / Yêu thích. */
export function EntryView({
  id,
  onEdit,
  onDeleted,
  onChanged,
  readOnly = false,
  refreshKey = 0,
}: {
  id: string;
  onEdit?: () => void;
  onDeleted?: () => void;
  onChanged?: () => void;
  readOnly?: boolean;
  /** Đổi giá trị ⇒ tải lại mục (ví dụ vừa đồng bộ về thay đổi từ máy khác, hoặc vừa khôi phục từ sao lưu). */
  refreshKey?: number;
}) {
  const toast = useToast();
  const [e, setE] = useState<EntryDetail | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [notes, setNotes] = useState<string | null>(null);
  const [totpSecret, setTotpSecret] = useState<string | null>(null);
  const [totp, setTotp] = useState<TotpCode | null>(null);
  const [history, setHistory] = useState<HistoryView[] | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  // Tải (lại) mục. Những gì đang hiện (mật khẩu, ghi chú, lịch sử) bị ẩn đi: chúng có thể đã cũ.
  useEffect(() => {
    setRevealed(null);
    setNotes(null);
    setTotpSecret(null);
    setHistory(null);
    setConfirmDelete(false);
    setTotp(null);
    api.get(id).then(setE).catch((err) => toast(errorText(err), "error"));
  }, [id, toast, refreshKey, reloadKey]);

  // Mã 2FA cập nhật mỗi giây (chỉ khi secret đọc được).
  const totpUsable = !!e?.has_totp && !e?.totp_error;
  useEffect(() => {
    if (!totpUsable) return;
    let alive = true;
    const tick = () => api.totp(id).then((t) => alive && setTotp(t)).catch(() => {});
    tick();
    const t = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [id, totpUsable]);

  // Bí mật vừa hiện tự ẩn sau 30 giây.
  useAutoHide(revealed, () => setRevealed(null));
  useAutoHide(notes, () => setNotes(null));
  useAutoHide(totpSecret, () => setTotpSecret(null));
  useAutoHide(history, () => setHistory(null));

  if (!e) return <div className="detail empty" />;

  /**
   * Sao chép ĐÚNG giá trị đang hiện trên màn hình (mật khẩu cũ trong Lịch sử) qua đường clipboard được bảo vệ — không dựa
   * vào chỉ số, vì thời điểm đổi của hai mật khẩu cũ có thể trùng nhau.
   */
  async function copyShown(value: string, label: string) {
    try {
      const secs = await api.copyText(value);
      toast(`Đã sao chép ${label} — tự xoá sau ${secs} giây`);
    } catch (err) {
      toast(errorText(err), "error");
    }
  }

  /** `shown`: dòng đang hiện (địa chỉ của `url:<i>`, `replaced_at` của `history:<i>`) — backend so lại trước khi chép. */
  async function copy(field: CopyField, label: string, shown?: string) {
    try {
      // Gửi kèm thời điểm sửa của mục đang hiện và chính dòng đang hiện: mục vừa đổi thì backend từ chối thay vì chép nhầm.
      const secs = await api.copyField(id, field, e?.updated_at, shown);
      toast(`Đã sao chép ${label} — tự xoá sau ${secs} giây`);
    } catch (err) {
      toast(errorText(err), "error");
      if (errorCode(err) === "entry_changed") setReloadKey((k) => k + 1);
    }
  }

  async function reveal<T>(current: T | null, load: () => Promise<T>, set: (v: T | null) => void) {
    if (current !== null) return set(null);
    try {
      set(await load());
    } catch (err) {
      toast(errorText(err), "error");
    }
  }

  async function del() {
    setBusy(true);
    try {
      await api.remove(id);
      toast("Đã chuyển vào thùng rác");
      onDeleted?.();
    } catch (err) {
      toast(errorText(err), "error");
    } finally {
      setBusy(false);
    }
  }

  async function fav() {
    try {
      await api.toggleFavorite(id);
      const fresh = await api.get(id);
      setE(fresh);
      onChanged?.();
    } catch (err) {
      toast(errorText(err), "error");
    }
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
              <button className="icon-btn" onClick={() => copy("username", "tên đăng nhập")} title="Sao chép" aria-label="Sao chép tên đăng nhập">
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
              <button
                className="icon-btn"
                onClick={() => reveal(revealed, () => api.reveal(id), setRevealed)}
                title={revealed === null ? "Hiện (tự ẩn sau 30 giây)" : "Ẩn"}
                aria-label={revealed === null ? "Hiện mật khẩu" : "Ẩn mật khẩu"}
              >
                <Icon name={revealed === null ? "eye" : "eyeOff"} />
              </button>
              <button className="icon-btn" onClick={() => copy("password", "mật khẩu")} title="Sao chép" aria-label="Sao chép mật khẩu">
                <Icon name="copy" />
              </button>
            </div>
            <StrengthMeter strength={e.strength} />
          </div>
        )}

        {e.has_totp && (
          <div className="kv">
            <label>Mã xác thực 2 bước {e.totp_label && <span className="muted">· {e.totp_label}</span>}</label>
            {e.totp_error ? (
              <div className="problem-box small">
                <p>{e.totp_error}</p>
                <div className="kv-value">
                  <span className="mono selectable">{totpSecret ?? "(giá trị đã lưu đang ẩn)"}</span>
                  <button className="btn link" onClick={() => reveal(totpSecret, () => api.revealTotpSecret(id), setTotpSecret)}>
                    {totpSecret === null ? "Hiện giá trị đã lưu" : "Ẩn"}
                  </button>
                </div>
              </div>
            ) : (
              <div className="kv-value">
                <span className="totp mono">{totp ? `${totp.code.slice(0, 3)} ${totp.code.slice(3)}` : "··· ···"}</span>
                {totp && (
                  <span className={totp.remaining <= 5 ? "ring warn" : "ring"} style={{ ["--p" as string]: `${(totp.remaining / totp.period) * 100}%` }}>
                    {totp.remaining}
                  </span>
                )}
                <button className="icon-btn" onClick={() => copy("totp", "mã 2FA")} title="Sao chép" aria-label="Sao chép mã 2FA">
                  <Icon name="copy" />
                </button>
              </div>
            )}
          </div>
        )}

        {e.urls.map((u, i) => (
          <div className="kv" key={u}>
            <label>Trang web</label>
            <div className="kv-value">
              <span className="selectable url">{u}</span>
              <button className="icon-btn" onClick={() => copy(`url:${i}`, "địa chỉ", u)} title="Sao chép" aria-label="Sao chép địa chỉ">
                <Icon name="copy" />
              </button>
            </div>
          </div>
        ))}

        {e.has_notes && (
          <div className="kv">
            <label>Ghi chú</label>
            {notes === null ? (
              <div className="kv-value">
                <span className="muted">Ghi chú đang ẩn (có thể chứa mã khôi phục, số tài khoản…)</span>
                <button className="btn" onClick={() => reveal(notes, () => api.revealNotes(id), setNotes)}>
                  <Icon name="eye" /> Hiện ghi chú
                </button>
                <button className="icon-btn" onClick={() => copy("notes", "ghi chú")} title="Sao chép ghi chú" aria-label="Sao chép ghi chú">
                  <Icon name="copy" />
                </button>
              </div>
            ) : (
              <>
                <pre className="notes selectable">{notes}</pre>
                <div className="row gap">
                  <button className="btn" onClick={() => setNotes(null)}>
                    <Icon name="eyeOff" /> Ẩn ghi chú
                  </button>
                  <button className="btn" onClick={() => copy("notes", "ghi chú")}>
                    <Icon name="copy" /> Sao chép
                  </button>
                  <span className="muted small">Tự ẩn sau 30 giây.</span>
                </div>
              </>
            )}
          </div>
        )}

        {e.history_count > 0 && (
          <div className="kv">
            <label>Lịch sử mật khẩu</label>
            {history === null ? (
              <button className="btn link" onClick={() => reveal(history, () => api.history(id), setHistory)}>
                Xem {e.history_count} mật khẩu cũ
              </button>
            ) : (
              <>
                <ul className="history">
                  {history.map((h, i) => (
                    <li key={i}>
                      <span className="mono selectable grow">{h.password}</span>
                      <span className="muted small">đổi lúc {formatDate(h.replaced_at)}</span>
                      <button className="icon-btn" onClick={() => copyShown(h.password, "mật khẩu cũ")} title="Sao chép" aria-label="Sao chép mật khẩu cũ">
                        <Icon name="copy" />
                      </button>
                    </li>
                  ))}
                </ul>
                <button className="btn link" onClick={() => setHistory(null)}>
                  Ẩn lịch sử
                </button>
              </>
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
            <span>Chuyển mục này vào thùng rác?</span>
            <button className="btn danger" onClick={del} disabled={busy}>
              Chuyển vào thùng rác
            </button>
            <button className="btn" onClick={() => setConfirmDelete(false)} disabled={busy}>
              Không
            </button>
          </span>
        ) : (
          <button className="btn subtle" onClick={() => setConfirmDelete(true)}>
            <Icon name="trash" /> Chuyển vào thùng rác
          </button>
        )}
      </footer>
    </div>
  );
}
