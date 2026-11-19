# Đặc tả định dạng file kho `.pwv` — phiên bản 1

Tài liệu này đủ để một người viết lại trình giải mã mà không cần đọc mã nguồn.
`tools/pwv_recover.py` là một bản cài đặt độc lập theo đúng đặc tả này (~80 dòng Python).

## 1. Bố cục file

| Offset | Kích thước | Nội dung |
|---|---|---|
| 0 | 4 | Magic `PWV1` (ASCII) |
| 4 | 2 | Phiên bản định dạng, `u16` little-endian = `1` |
| 6 | 4 | `N` = độ dài header, `u32` little-endian (≤ 65 536) |
| 10 | N | Header: JSON UTF-8 (mục 2) |
| 10+N | 24 | `body_nonce` |
| 34+N | còn lại | `body_ciphertext` (gồm tag Poly1305 16 byte ở cuối) |

**AAD của body** = toàn bộ `bytes[0 .. 10+N]` (magic + version + độ dài + header).
⇒ sửa bất kỳ byte nào của header, kể cả tham số KDF, đều làm giải mã thất bại.

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

## 3. Dẫn xuất khoá

```
master_key = Argon2id(password, salt, m = m_kib KiB, t, p, version 0x13, output 32 byte)
KEK        = HKDF-SHA256(IKM = master_key, salt = (rỗng), info = "pwv/v1/key-encryption-key", L = 32)
vault_key  = XChaCha20-Poly1305-Decrypt(key = KEK, nonce = key_nonce,
                                         ct = wrapped_key, aad = "pwv/v1/wrap:" || vault_id)
```

- `vault_key` là 32 byte ngẫu nhiên sinh **một lần** khi tạo kho và không bao giờ đổi.
  Đổi master password chỉ sinh `salt`, `key_nonce`, `wrapped_key` mới.
- Giới hạn khi đọc: `m_kib ≤ 4 GiB`, `t ≤ 100`, `1 ≤ p ≤ 64` (chống file độc làm treo máy).
- Giới hạn khi tạo/đổi mật khẩu: `m_kib ≥ 64 MiB`, `t ≥ 2`. Mặc định 256 MiB / 3 / 4.
- Test vector: `password = "correct horse battery staple"`, `salt = 0x42 × 16`, `m=64, t=2, p=1`
  ⇒ `KEK = 61e7a32834520e64fc1eb471c92714cfd7353adbc49a3d3c22e6f6ba0a863c76`
  (đã đối chiếu với argon2-cffi — bản tham chiếu C).

## 4. Body

```
plaintext = u32_le(L) || JSON(VaultData) [L byte] || 0x00 ... (đệm lên bội số 4096 byte)
body_ciphertext = XChaCha20-Poly1305-Encrypt(vault_key, body_nonce, plaintext, aad = bytes[0..10+N])
```

`body_nonce` sinh ngẫu nhiên mỗi lần lưu (24 byte ⇒ xác suất trùng không đáng kể).
Phần đệm giúp kích thước file không tiết lộ số lượng mục.

### VaultData

```json
{
  "entries": [ Entry, ... ],
  "tombstones": [ { "id": "...", "deleted_at": 1795100689940 } ],
  "modified_at": 1795100689940
}
```

### Entry

| Trường | Kiểu | Ghi chú |
|---|---|---|
| `id` | string | UUID v4 |
| `title`, `username`, `password`, `notes` | string | |
| `urls`, `tags` | string[] | |
| `totp` | string \| null | `otpauth://…` |
| `favorite` | bool | |
| `password_history` | `{password, replaced_at}[]` | tối đa 20, mới nhất trước |
| `created_at`, `updated_at` | i64 | mili-giây UTC |

Mọi thời gian là mili-giây kể từ 1970-01-01 UTC.

## 5. Quy tắc đồng bộ (Google Drive)

1. Khi mở: ghi nhớ SHA-256 của file.
2. Khi lưu: đọc lại file; nếu SHA-256 khác ⇒ máy khác đã ghi ⇒ giải mã bằng `vault_key`
   (cùng kho nên cùng khoá, kể cả khi máy kia đã đổi master password) rồi **gộp**:
   - Mục chỉ có một bên ⇒ giữ.
   - Mục có cả hai bên ⇒ `updated_at` lớn hơn thắng; mật khẩu của bên thua (nếu khác)
     được đưa vào `password_history`.
   - Tombstone gộp theo `deleted_at` lớn nhất; mục bị loại nếu `deleted_at ≥ updated_at`.
   - Header có `key_changed_at` lớn hơn được giữ lại.
3. Ghi nguyên tử: file tạm cùng thư mục → `fsync` → sao lưu file cũ vào `<tên>.backups/`
   (giữ 10 bản) → `rename` đè; thử lại khi Windows báo file đang bị khoá.
4. Bản xung đột Drive tạo ra (`vault (1).pwv`) phải có cùng `vault_id`; sau khi gộp được
   chuyển vào thư mục sao lưu.

Giả định: đồng hồ các máy lệch nhau không quá vài giây (Windows tự đồng bộ giờ qua Internet).

## 6. Hạn chế đã biết

- Dữ liệu được giải mã toàn bộ vào RAM khi mở kho. Khoá và các mục được `zeroize` khi đóng,
  nhưng bản sao tạm do cấp phát lại bộ nhớ (Vec/String tăng kích thước) có thể còn sót.
- Trường lạ do phiên bản mới hơn thêm vào sẽ bị bỏ khi phiên bản cũ lưu lại —
  luôn dùng cùng phiên bản app trên các máy.
