import { useCallback, useEffect, useState } from "react";
import { api, errorText } from "../api";
import type { TrashItem } from "../types";
import { ConfirmBox, formatDate, Icon, useToast } from "./ui";

/** Thùng rác: mục đã xoá vẫn khôi phục được cho tới khi xoá vĩnh viễn. */
export function Trash({ onChanged }: { onChanged: () => void }) {
  const toast = useToast();
  const [items, setItems] = useState<TrashItem[] | null>(null);
  const [confirm, setConfirm] = useState<{ kind: "purge"; item: TrashItem } | { kind: "empty" } | null>(null);
  const [busy, setBusy] = useState(false);
  // Sau "dọn sạch": số mục mới vào thùng rác trong lúc xác nhận (ví dụ từ máy khác) — chưa bị xoá.
  const [leftOver, setLeftOver] = useState(0);

  const load = useCallback(async () => {
    try {
      setItems(await api.listTrash());
    } catch (e) {
      toast(errorText(e), "error");
      setItems([]);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<unknown>, done: string | null) {
    setBusy(true);
    setLeftOver(0);
    try {
      await fn();
      if (done) toast(done);
      setConfirm(null);
      await load();
      onChanged();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const permanentText = (what: string) => (
    <>
      <strong>Xoá vĩnh viễn {what}?</strong> Mục sẽ bị xoá trên <strong>mọi thiết bị</strong> và không thể lấy lại từ thùng rác nữa — chỉ còn
      cách khôi phục từ một bản sao lưu cũ (Cài đặt → Sao lưu &amp; khôi phục).
    </>
  );

  return (
    <div className="detail">
      <header className="detail-head">
        <Icon name="trash" size={24} />
        <div className="grow">
          <h2>Thùng rác</h2>
          <p className="muted small">Mục đã xoá nằm ở đây cho tới khi bạn xoá vĩnh viễn. Khôi phục thì mục quay lại trên mọi thiết bị.</p>
        </div>
        {items && items.length > 0 && (
          <button className="btn subtle" onClick={() => setConfirm({ kind: "empty" })} disabled={busy}>
            Dọn sạch thùng rác
          </button>
        )}
      </header>
      <div className="fields">
        {leftOver > 0 && (
          <div className="note-box" role="status">
            Trong lúc bạn xác nhận, thùng rác có thêm {leftOver} mục mới (có thể từ máy khác). {leftOver > 1 ? "Các mục đó" : "Mục đó"}{" "}
            <strong>chưa bị xoá</strong> — hãy xem lại bên dưới.
          </div>
        )}
        {confirm?.kind === "empty" && (
          <ConfirmBox
            danger
            busy={busy}
            text={permanentText(`${items?.length ?? 0} mục đang hiện trong thùng rác`)}
            confirmLabel="Dọn sạch thùng rác"
            onConfirm={() =>
              // Gửi đúng danh sách người dùng đang nhìn thấy: mục nào vào thùng rác sau đó không bị xoá.
              act(async () => {
                const r = await api.emptyTrash((items ?? []).map((i) => i.id));
                setLeftOver(r.remaining);
                toast(r.remaining > 0 ? `Đã xoá vĩnh viễn ${r.purged} mục` : "Đã dọn sạch thùng rác");
              }, null)
            }
            onCancel={() => setConfirm(null)}
          />
        )}
        {items === null ? null : items.length === 0 ? (
          <p className="muted">Thùng rác trống.</p>
        ) : (
          <ul className="trash-list">
            {items.map((it) => (
              <li key={it.id}>
                <div className="trash-row">
                  <span className="grow ellipsis">
                    <strong>{it.title}</strong> <span className="muted small">{it.username}</span>
                    <br />
                    <span className="muted small">Xoá lúc {formatDate(it.deleted_at)}</span>
                  </span>
                  <button className="btn" disabled={busy} onClick={() => act(() => api.restoreEntry(it.id), `Đã khôi phục “${it.title}”`)}>
                    <Icon name="restore" /> Khôi phục
                  </button>
                  <button className="btn subtle" disabled={busy} onClick={() => setConfirm({ kind: "purge", item: it })}>
                    Xoá vĩnh viễn
                  </button>
                </div>
                {confirm?.kind === "purge" && confirm.item.id === it.id && (
                  <ConfirmBox
                    danger
                    busy={busy}
                    text={permanentText(`“${it.title}”`)}
                    confirmLabel="Xoá vĩnh viễn"
                    onConfirm={() => act(() => api.purgeEntry(it.id), `Đã xoá vĩnh viễn “${it.title}”`)}
                    onCancel={() => setConfirm(null)}
                  />
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
