# Đặc tả định dạng file kho `.pwv` — phiên bản 2

Tài liệu này đủ để một người viết lại trình giải mã mà không cần đọc mã nguồn.
`tools/pwv_recover.py` là một bản cài đặt độc lập theo đúng đặc tả này (~120 dòng Python); CI chạy
`tools/check_recover.py` để bảo đảm nó đọc được file do app tạo ra.

**Phiên bản.** App từ 0.2.0 GHI định dạng 2 và ĐỌC được cả 1 lẫn 2. Hai phiên bản có cùng khung nhị
phân (mục 1–3); chỉ khác nội dung JSON bên trong phần mã hoá (mục 4). Bản app ≤ 0.1.2 gặp số phiên
bản 2 sẽ báo "hãy cập nhật phần mềm" và không đụng vào file.

> **Quy tắc bắt buộc khi sửa mã:** thêm/bớt/đổi tên bất kỳ trường nào trong mục 4 là thay đổi định
> dạng — phải tăng số phiên bản (để bản app cũ từ chối mở thay vì âm thầm làm mất trường mới khi
> ghi lại file). Test `schema_change_requires_format_version_bump` sẽ đỏ nếu quên.

## 1. Bố cục file

| Offset | Kích thước | Nội dung |
|---|---|---|
| 0 | 4 | Magic `PWV1` (ASCII) |
| 4 | 2 | Phiên bản định dạng, `u16` little-endian = `2` (hoặc `1`) |
| 6 | 4 | `N` = độ dài header, `u32` little-endian (≤ 65 536) |
| 10 | N | Header: JSON UTF-8 (mục 2) |
| 10+N | 24 | `body_nonce` |
| 34+N | còn lại | `body_ciphertext` (gồm tag Poly1305 16 byte ở cuối) |

**AAD của body** = toàn bộ `bytes[0 .. 10+N]` (magic + version + độ dài + header).
⇒ sửa bất kỳ byte nào của header, kể cả số phiên bản hay tham số KDF, đều làm giải mã thất bại.

## 2. Header (không bí mật)

```json
{
  "vault_id": "uuid v4 ngẫu nhiên",
  "kdf": { "m_kib": 262144, "t": 3, "p": 4 },
  "salt": "base64 — 16 byte",
  "key_nonce": "base64 — 24 byte",
  "wrapped_key": "base64 — 48 byte (32 khoá + 16 tag)",
  "key_changed_at": 1795100683998
}
```

Header đọc được mà không cần mật khẩu: nó cho biết file thuộc kho nào (`vault_id`) và lần đổi master
password gần nhất (`key_changed_at`). Không có tên trang web, username hay số lượng mục ở đây.

## 3. Dẫn xuất khoá

```
password'  = NFC(password)                       -- chuẩn hoá Unicode, xem bên dưới
master_key = Argon2id(password', salt, m = m_kib KiB, t, p, version 0x13, output 32 byte)
KEK        = HKDF-SHA256(IKM = master_key, salt = (rỗng), info = "pwv/v1/key-encryption-key", L = 32)
vault_key  = XChaCha20-Poly1305-Decrypt(key = KEK, nonce = key_nonce,
                                         ct = wrapped_key, aad = "pwv/v1/wrap:" || vault_id)
```

- **Chuẩn hoá mật khẩu.** Cùng một chữ tiếng Việt có thể được gõ ra ở dạng dựng sẵn (NFC) hoặc tổ
  hợp (NFD) — nhìn giống hệt nhau nhưng khác byte. Khi tạo kho / đổi mật khẩu, app luôn dùng NFC.
  Khi mở kho, thử lần lượt: NFC → nguyên văn → NFD (kho tạo bởi bản ≤ 0.1.2 dùng nguyên văn).
  Mật khẩu chỉ gồm ASCII thì cả ba trùng nhau.
- **`vault_key`** là 32 byte ngẫu nhiên. **Mỗi lần đổi master password sinh một `vault_key` mới** và
  toàn bộ thân kho được mã hoá lại; khoá cũ được giữ trong `old_keys` *bên trong* phần đã mã hoá
  (mục 4) để còn mở được các bản sao lưu / bản xung đột cũ. Hệ quả: người biết mật khẩu CŨ và giữ một
  bản sao CŨ của file không đọc được dữ liệu ghi sau lần đổi. (Bản ≤ 0.1.2 chỉ gói lại cùng một khoá.)
- Giới hạn được kiểm tra TRƯỚC khi chạy Argon2, cả khi tạo lẫn khi mở: `64 MiB ≤ m_kib ≤ 1 GiB`,
  `2 ≤ t ≤ 16`, `1 ≤ p ≤ 16` (chống file bị sửa để làm treo máy hoặc hạ độ khó). Mặc định 256 MiB / 3 / 4.
- Test vector: `password = "correct horse battery staple"`, `salt = 0x42 × 16`, `m=64, t=2, p=1`
  ⇒ `KEK = 61e7a32834520e64fc1eb471c92714cfd7353adbc49a3d3c22e6f6ba0a863c76`
  (đã đối chiếu với argon2-cffi — bản tham chiếu C).

## 4. Body

```
plaintext = u32_le(L) || JSON(VaultData) [L byte] || 0x00 ... (đệm lên bội số 4096 byte)
body_ciphertext = XChaCha20-Poly1305-Encrypt(vault_key, body_nonce, plaintext, aad = bytes[0..10+N])
```

`body_nonce` sinh ngẫu nhiên mỗi lần lưu (24 byte ⇒ xác suất trùng không đáng kể).
Phần đệm làm tròn kích thước file lên bội số 4 KiB: người ngoài chỉ ước lượng được cỡ của kho theo
từng nấc 4 KiB, không biết chính xác số mục.

### VaultData

```json
{
  "entries":    [ Entry, ... ],
  "trash":      [ Entry, ... ],
  "tombstones": [ { "id": "...", "deleted_at": 1795100689940 } ],
  "modified_at": 1795100689940,
  "old_keys":   [ { "key": "base64 — 32 byte", "retired_at": 1795100689940 } ]
}
```

| Trường | v1 | v2 | Ý nghĩa |
|---|---|---|---|
| `entries` | ✓ | ✓ | Các mục đang dùng |
| `trash` | – | ✓ | Thùng rác: mục đã xoá, còn khôi phục được |
| `tombstones` | ✓ | ✓ | Mục đã xoá VĨNH VIỄN (chỉ còn id) |
| `modified_at` | ✓ | ✓ | Lần sửa nội dung gần nhất; chỉ tăng |
| `old_keys` | – | ✓ | Khoá kho của các lần đổi master password trước (tối đa 16, mới nhất trước) |

### Entry

| Trường | Kiểu | Ghi chú |
|---|---|---|
| `id` | string | UUID |
| `title`, `username`, `password`, `notes` | string | |
| `urls`, `tags` | string[] | |
| `totp` | string \| null | `otpauth://…` hoặc secret base32 |
| `favorite` | bool | |
| `password_history` | `{password, replaced_at}[]` | tối đa 20, mới nhất trước, không chứa mật khẩu hiện tại |
| `created_at` | i64 | |
| `updated_at` | i64 | = giá trị lớn nhất trong `field_times` (không tính `deleted`) |
| `field_times` (v2) | object | thời điểm sửa cuối của TỪNG trường: `title`, `username`, `password`, `urls`, `notes`, `totp`, `tags`, `favorite`, và `deleted` (lần cuối vào/ra thùng rác; 0 = chưa bao giờ) |

Mọi thời gian là mili-giây kể từ 1970-01-01 UTC. Khi đọc file v1 (không có `field_times`), mọi trường
được coi là sửa lúc `updated_at`.

## 5. Gộp hai phiên bản của cùng một kho

Mỗi trường của một mục là một ô "ghi-sau-thắng": cặp *(thời điểm sửa, giá trị)*.

1. **Từng trường:** lấy cặp có thời điểm lớn hơn; nếu bằng nhau thì lấy giá trị lớn hơn theo thứ tự
   từ điển (chỉ để mọi máy chọn giống nhau). Trạng thái "đang trong thùng rác" cũng là một ô như vậy
   (thời điểm = `field_times.deleted`).
2. **Mật khẩu:** bản thua (nếu khác) được đưa vào `password_history` kèm thời điểm nó được đặt.
3. **Tombstone:** một id đã có tombstone thì mục đó bị loại ở mọi nơi, bất kể thời điểm. (Muốn lấy lại
   phải khôi phục từ bản sao lưu — khi đó nó là một mục mới với id mới.)
4. `created_at` lấy giá trị nhỏ nhất, `modified_at` lớn nhất, `old_keys` lấy hợp.
5. Kết quả được đưa về **dạng chuẩn**: mục xếp theo `(created_at, id)`, tombstone theo `id`, lịch sử
   mật khẩu gọn và có thứ tự cố định — hai kho cùng nội dung thì giống nhau từng byte trước khi mã hoá.

Phép gộp có tính giao hoán, kết hợp và luỹ đẳng (kiểm chứng bằng property test trong
`crates/vault-core/tests/merge_props.rs`): các máy gộp theo thứ tự nào cũng ra cùng một kết quả, và
hai máy không bao giờ ghi đè qua lại vô hạn.

Hệ quả thực tế:
- Máy A đổi mật khẩu, máy B (chưa thấy thay đổi đó) sửa ghi chú hoặc bấm ★ ⇒ giữ được cả hai.
- Xoá ở máy này, sửa ở máy kia ⇒ mục nằm trong thùng rác với nội dung mới nhất; không mất gì.

Giả định: đồng hồ các máy lệch nhau không quá vài giây (Windows và Android tự đồng bộ giờ qua
Internet). Đồng hồ sai nhiều có thể làm bản sửa "cũ" thắng bản sửa "mới" của cùng một trường — mật
khẩu thua vẫn nằm trong lịch sử.

## 6. Quy tắc đọc/ghi và đồng bộ

1. Khi mở: ghi nhớ SHA-256 của file.
2. **Mọi thao tác sửa là một giao dịch:** đọc lại file; nếu SHA-256 khác ⇒ máy khác đã ghi ⇒ giải mã
   và gộp (mục 5) TRƯỚC khi sửa; sửa; ghi. Nếu ghi thất bại, thay đổi trong RAM được hoàn tác.
3. Giải mã file của cùng kho: thử `vault_key` hiện tại, rồi các khoá trong `old_keys`.
   - Không khoá nào mở được và `key_changed_at` của file MỚI HƠN ⇒ máy khác đã đổi master password ⇒
     dừng, yêu cầu nhập mật khẩu mới (không ghi gì).
   - Không khoá nào mở được và `key_changed_at` không mới hơn ⇒ file hỏng (đồng bộ dở, bị sửa).
   - Mở được bằng khoá hiện tại nhưng header có `key_changed_at` mới hơn ⇒ bản app ≤ 0.1.2 ở máy khác
     đã đổi mật khẩu theo kiểu cũ ⇒ nhận header đó.
4. **Không bao giờ tự ghi đè** khi file trên đĩa: hỏng, biến mất, thuộc kho khác (`vault_id` khác),
   hoặc có số phiên bản lớn hơn. Mỗi trường hợp là một lỗi riêng; chỉ ghi khi người dùng xác nhận
   (file hỏng được CẤT vào thư mục sao lưu dưới tên `damaged-<ms>-<tên>`, không bị xoá).
5. Ghi nguyên tử: file tạm cùng thư mục → `fsync` → `rename` đè → đọc lại và so từng byte; thử lại khi
   Windows báo file đang bị tiến trình khác giữ.
6. Đồng bộ nền: nạp và gộp file trên đĩa; nếu bản trong RAM có thứ file không có (dịch vụ đồng bộ đã
   thay file bằng bản của máy kia) thì **ghi lại**.
7. Bản xung đột do dịch vụ đồng bộ tạo ra (Google Drive `vault (1).pwv`, Dropbox
   `vault (… conflicted copy …).pwv`, OneDrive `vault-TÊN-MÁY.pwv`…) được nhận diện **theo nội dung**:
   mọi file `.pwv` khác trong cùng thư mục có cùng `vault_id`. Chúng được gộp vào kho và chỉ SAU KHI
   kho đã được ghi thành công mới được chuyển vào thư mục sao lưu (`merged-<ms>-<tên gốc>`).

### Thư mục sao lưu `<tên file kho>.backups/`

- Trước khi ghi đè: chép bản đang nằm trên đĩa nếu nó chưa chắc đã có trong thư mục sao lưu (bản do
  máy khác hoặc bản app cũ ghi; lần ghi đầu của phiên).
- Sau khi ghi: chép luôn bản vừa ghi ⇒ **bản sao lưu mới nhất luôn giống hệt file kho**.
- Tên: `<tên>-<ms>.pwv`. Giữ lại: 10 bản gần nhất + bản cuối của mỗi ngày trong 30 ngày + bản cuối
  của mỗi kỳ 30 ngày trong 12 kỳ. Chỉ xoá file có đúng `vault_id` của kho.
- Khi đổi master password, mọi file trong thư mục này được mã hoá lại bằng khoá mới.

## 7. Hạn chế đã biết

- Dữ liệu được giải mã toàn bộ vào RAM khi mở kho. Khoá và các mục được xoá (`zeroize`) khi khoá kho,
  nhưng bản sao tạm do cấp phát lại bộ nhớ, do thư viện, và trong bộ nhớ của WebView có thể còn sót
  cho tới khi tiến trình kết thúc. Chỉ riêng bản sao của `vault_key` được giữ trong vùng nhớ không bị
  ghi ra pagefile. Hãy bật mã hoá ổ đĩa (BitLocker) để pagefile / file ngủ đông không lộ dữ liệu.
- Bản sao của file kho đã rời khỏi máy (lịch sử phiên bản và thùng rác của dịch vụ đồng bộ, bản lưu
  ngoại tuyến trên điện thoại, máy khác chưa đồng bộ) vẫn mở được bằng master password tại thời điểm
  của bản sao đó. Đổi master password không thu hồi được chúng.
- Kẻ có quyền GHI vào thư mục đồng bộ có thể thay file kho bằng một bản cũ hơn (hợp lệ). App phát
  hiện và cảnh báo nếu file cũ hơn bản mà chính máy đó từng thấy, nhưng không ngăn được.
- Header để lộ `vault_id`, tham số KDF và thời điểm đổi master password gần nhất; kích thước file để
  lộ cỡ của kho theo nấc 4 KiB; thư mục sao lưu để lộ thời điểm của các lần ghi.
