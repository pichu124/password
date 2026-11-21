# Đặc tả định dạng file kho `.pwv` — phiên bản 2

Tài liệu này đủ để một người viết lại trình giải mã mà không cần đọc mã nguồn.
`tools/pwv_recover.py` là một bản cài đặt độc lập theo đúng đặc tả này (~200 dòng Python, được đính
kèm mỗi bản phát hành); CI chạy `tools/check_recover.py` để bảo đảm nó đọc được file do app tạo ra
(v2 sau một lần đổi master password, các bản sao lưu mang dấu `pre_change` cạnh nó, và file v1 của
bản 0.1.2). Công cụ in một cảnh báo nổi bật trên stderr khi file mở ra mang dấu `pre_change` (mục 3).

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

**Kích thước.** Lõi không đọc bất kỳ file nào của kho (file kho chính, bản cạnh kho, bản sao lưu, bản
cứu hộ / bản lưu riêng, đọc lại sau khi ghi) lớn hơn **64 MiB**: kiểm tra kích thước trước, rồi đọc tối
đa 64 MiB + 1 byte. File kho chính quá cỡ được coi là **file hỏng**
(mục 6.4: không tự ghi đè; "ghi đè" có xác nhận thì cất nó thành `damaged-…`); bản cạnh kho / bản sao
lưu quá cỡ bị bỏ qua.

## 2. Header (không bí mật)

```json
{
  "vault_id": "uuid v4 ngẫu nhiên",
  "kdf": { "m_kib": 262144, "t": 3, "p": 4 },
  "salt": "base64 — 16 byte",
  "key_nonce": "base64 — 24 byte",
  "wrapped_key": "base64 — 48 byte (32 khoá + 16 tag)",
  "key_changed_at": 1795100683998,
  "pre_change": true
}
```

`pre_change` là trường **tuỳ chọn** (bool, chỉ có từ v2): app chỉ ghi nó khi bằng `true` — tức chỉ trên
các bản sao lưu đã được mã hoá lại lúc đổi master password (mục 3, 6). File kho chính và bản sao lưu
bình thường không có trường này (vắng mặt = `false`).

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
  toàn bộ thân kho được mã hoá lại; khoá cũ ("khoá đã nghỉ") được giữ trong `old_keys` *bên trong*
  phần đã mã hoá (mục 4) để chủ kho còn ĐỌC được các bản sao lưu cũ. (Bản ≤ 0.1.2 chỉ gói lại cùng
  một khoá.) Chính xác thì người biết mật khẩu CŨ và giữ một bản sao CŨ của file:
  - **không đọc được** những gì một máy đã biết lần đổi ghi ra sau đó (file kho, bản sao lưu); các bản
    sao lưu có từ trước, ghi bằng khoá vừa bị thay, được mã hoá lại khi đổi (và mang dấu `pre_change`,
    xem dưới);
  - **vẫn đọc được**: bản sao đó và mọi bản cũ khác nằm ngoài tầm với của app (lịch sử phiên bản /
    thùng rác của dịch vụ đồng bộ, điện thoại hay máy chưa đồng bộ), và những gì một máy CHƯA biết
    lần đổi tiếp tục ghi bằng khoá cũ (file kho, bản sao lưu của chính nó) cho tới khi nó mở khoá
    bằng mật khẩu mới — kể cả khi app đã cất chúng thành `oldkey-…` (bản cất giữ nguyên văn, mục 6.3);
  - **không ghi được vào kho**: file chỉ mở được bằng khoá đã nghỉ không bao giờ được tự gộp (mục 6.3),
    và mọi thứ có từ TRƯỚC lần đổi cũng vậy (dấu `pre_change`). Không có ngoại lệ: cả bản cứu hộ và
    bản lưu riêng trong thư mục RIÊNG của app (mục 6, "Dữ liệu riêng của app") cũng theo quy tắc này.
- **`pre_change`** (trường tuỳ chọn của header, kiểu bool; vắng mặt = `false`): `true` nghĩa là file này
  là một bản sao lưu có từ trước lần đổi master password gần nhất, đã được mã hoá lại bằng khoá mới
  (nên mở được bằng mật khẩu MỚI, và phần thân của nó mang cả các khoá đã nghỉ trong `old_keys`).
  Trước lần đổi, người biết mật khẩu (sắp thành) cũ có đủ khoá để đặt vào thư mục sao lưu một file tự
  làm; nếu lần đổi mật khẩu biến nó thành một bản sao lưu bình thường thì nó được hưởng sự tin cậy của
  khoá mới. Vì vậy **một file chỉ được coi là đáng tin khi nó giải mã được bằng khoá hiện tại VÀ không
  mang dấu này**. Dấu nằm trong header nên được phần thân xác thực — đổi tên hay chuyển chỗ file không
  gỡ được nó. File mang dấu: không mở làm file kho (báo như file hỏng), không tự gộp, không dùng để tự
  dựng lại kho; chủ kho vẫn xem và khôi phục từng mục từ nó được. File kho do app ghi ra không bao giờ
  mang dấu này.
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
| `password_history` | `{password, replaced_at}[]` | không chứa mật khẩu hiện tại hay mật khẩu rỗng; tối đa 20 dòng (21 nếu mật khẩu hiện tại rỗng); xếp theo `(replaced_at, password)` giảm dần — xem mục 5 |
| `created_at` | i64 | lúc tạo mục; 0 = chưa biết |
| `updated_at` | i64 | = max(`created_at`, giá trị lớn nhất trong `field_times` không tính `deleted`); nếu còn trường mang 0 ("chưa biết") thì chỉ lấy giá trị lớn nhất trong `field_times` |
| `field_times` (v2) | object | thời điểm sửa cuối của TỪNG trường: `title`, `username`, `password`, `urls`, `notes`, `totp`, `tags`, `favorite`, và `deleted` (lần cuối vào/ra thùng rác; 0 = chưa bao giờ) |

Mọi thời gian là mili-giây kể từ 1970-01-01 UTC. Quy ước cho `field_times`:

- `0` = chưa biết (file v1 không có `field_times`): khi đọc, được thay bằng max(`updated_at`, các
  trường đã có) — tức là mọi trường được coi là sửa lúc `updated_at`.
- `1` (`IMPORTED_AT`) = giá trị nhập từ file CSV, chưa từng được sửa. Mục nhập từ CSV có id suy ra từ
  nội dung, nên nhập cùng file trên hai máy cho ra cùng một mục; với thời điểm `1`, hai lần nhập giống
  hệt nhau hoà nhau, và mọi lần sửa thật đều thắng (nhập lại trên một máy chưa đồng bộ không đè lên
  thay đổi của máy khác). `created_at` của mục nhập = lúc nhập.
- Mọi lần sửa thật được đóng dấu `≥ 2` (kể cả khi đồng hồ chỉ trước 1970), và luôn lớn hơn thời điểm
  cũ của chính trường đó (`max(now, cũ + 1)`).

`replaced_at` của một dòng lịch sử có hai nguồn: khi sửa mật khẩu trên một máy, đó là thời điểm mật
khẩu bị thay (ghi là 1 ms trước thời điểm của mật khẩu mới); khi mật khẩu thua trong lúc gộp hai lần
sửa đồng thời, đó là thời điểm nó đã được ĐẶT (dùng thời điểm của bên thắng thì kết quả gộp sẽ phụ
thuộc thứ tự gộp). Ứng dụng hiển thị nó như "đổi lúc" — với nguồn thứ hai đó là thời điểm gần đúng.

## 5. Gộp hai phiên bản của cùng một kho

Mỗi trường của một mục là một ô "ghi-sau-thắng": cặp *(thời điểm sửa, giá trị)*.

1. **Từng trường:** lấy cặp có thời điểm lớn hơn; nếu bằng nhau thì lấy giá trị lớn hơn theo thứ tự
   từ điển (chỉ để mọi máy chọn giống nhau). Trạng thái "đang trong thùng rác" cũng là một ô như vậy
   (thời điểm = `field_times.deleted`).
2. **Mật khẩu:** bản thua (nếu khác và không rỗng) được đưa vào `password_history` kèm thời điểm nó
   được đặt.
3. **Tombstone:** một id đã có tombstone thì mục đó bị loại ở mọi nơi, bất kể thời điểm. (Muốn lấy lại
   phải khôi phục từ bản sao lưu — khi đó nó là một mục mới với id mới.)
   **Tombstone của file v1:** bản 0.1.x coi tombstone là tương đối — nó giữ một mục được sửa SAU lần
   xoá, và tombstone vẫn nằm trong file. App áp dụng đúng quy tắc đó (so sánh chặt `deleted_at <
   updated_at`, như 0.1.2) ở hai chỗ:
   - khi giải mã một phần thân **v1** (mở kho, đồng bộ, đọc bản sao lưu, khôi phục), TRƯỚC khi đưa về
     dạng chuẩn: bỏ mọi tombstone mà trong CHÍNH file đó còn một mục sống cùng id được sửa sau lần xoá;
   - khi **gộp** một file v1 vào kho (file kho chính, bản xung đột, bản sao lưu khi khôi phục, chuyển
     kho, điện thoại tải lại, bản lưu riêng / bản cứu hộ): bỏ mọi tombstone của file v1 mà trong kho
     ĐÍCH có một mục (đang dùng hoặc trong thùng rác) cùng id được sửa sau lần xoá. Khi khôi phục, các
     tombstone của mọi file v1 (kể cả gốc) được gom lại và lọc một lần với kết quả gộp cuối cùng, nên
     thứ tự gộp không ảnh hưởng;
   - khi tombstone v1 đã vào RAM (file kho chính v1 lúc mở, một lần gộp v1 trước đó) mà CHƯA được ghi
     vào một file v2: `Vault` nhớ id của chúng (chỉ trong RAM, không bao giờ lưu); ở mỗi lần gộp sau đó
     (file v1 hay v2), tombstone như vậy bị bỏ nếu file đến có mục cùng id (đang dùng hoặc trong thùng
     rác) được sửa sau lần xoá — nên kết quả không phụ thuộc file nào được dịch vụ đồng bộ chọn làm file
     chính, và một phiên mở lâu cho cùng kết quả với một lần mở mới. Danh sách được xoá sau mỗi lần ghi
     file kho chính (v2) đã xác minh; tombstone đến từ file v2 hay lệnh xoá vĩnh viễn trên máy này không
     bao giờ bị bỏ; giao dịch bị hoàn tác thì danh sách cũng được trả về như trước.
   Mục còn sống không bị chuyển vào thùng rác; tombstone còn lại (mục cũ hơn hoặc bằng lần xoá, hay id
   không có trong kho) được giữ và từ đó là tuyệt đối. **Hệ quả còn lại:** khi một tombstone v1 đã được
   ghi vào một file v2 thì nó tuyệt đối — một máy 0.2 đã áp nó lên một bản CŨ của mục sẽ vẫn xoá một lần
   sửa mới hơn đến muộn từ một máy 0.1.x chưa đồng bộ (mục đó vẫn còn trong các bản sao lưu).
4. `created_at` lấy giá trị nhỏ nhất, bỏ qua 0 (= chưa biết); `modified_at` lớn nhất; `old_keys`
   lấy hợp, mỗi khoá giữ `retired_at` lớn nhất, xếp `retired_at` giảm dần, giữ tối đa 16.
5. Kết quả được đưa về **dạng chuẩn**: mục xếp theo `(created_at, id)`, tombstone theo `id`, lịch sử
   mật khẩu gọn và có thứ tự cố định — hai kho cùng nội dung thì giống nhau từng byte trước khi mã hoá.

**Lịch sử mật khẩu ở dạng chuẩn.** Coi trạng thái mật khẩu của một mục là TẬP các cặp
`(password, t)` gồm mật khẩu hiện tại (nếu khác rỗng, `t = field_times.password`) và các dòng lịch sử
(`t = replaced_at`), bỏ mật khẩu rỗng, mỗi mật khẩu một cặp (giữ `t` lớn nhất), so sánh theo MỘT thứ
tự toàn phần `(t, password)` — đúng thứ tự dùng để chọn mật khẩu hiện tại ở bước 1. Dòng nào không
nhỏ hơn mật khẩu hiện tại theo thứ tự đó được hạ xuống ngay dưới nó (`t` = thời điểm của mật khẩu hiện
tại nếu `password` nhỏ hơn theo thứ tự từ điển, ngược lại thời điểm đó − 1), nên mật khẩu hiện tại luôn
là cặp lớn nhất. Dạng chuẩn giữ 21 cặp lớn nhất; `password_history` = các cặp đó trừ mật khẩu hiện tại
(20 dòng, hoặc 21 khi mật khẩu hiện tại rỗng), xếp giảm dần.

Phép gộp có tính giao hoán, kết hợp và luỹ đẳng, kể cả khi lịch sử mật khẩu đã chạm trần (kiểm chứng
bằng property test trong `crates/vault-core/tests/merge_props.rs`, lịch sử tới 26 dòng, ≥ 20 000 ca
mỗi tính chất): các máy gộp theo thứ tự nào cũng ra cùng một kết quả, và hai máy không bao giờ ghi đè
qua lại vô hạn. (Bảo đảm cho dữ liệu do app ghi ra; với thời điểm cực đoan như `i64::MIN`, chỉ có ở dữ
liệu méo, phép "− 1" ở trên bão hoà và không bảo đảm.)

Hệ quả thực tế:
- Máy A đổi mật khẩu, máy B (chưa thấy thay đổi đó) sửa ghi chú hoặc bấm ★ ⇒ giữ được cả hai.
- Xoá ở máy này, sửa ở máy kia ⇒ mục nằm trong thùng rác với nội dung mới nhất; không mất gì.
- **Ngoại lệ khi còn máy chạy 0.1.x:** mục của file v1 không có `field_times`, nên mọi trường của nó
  mang thời điểm `updated_at` (mục 4). Một lần sửa bất kỳ ở máy 0.1.x (ví dụ chỉ sửa ghi chú) khi
  được gộp vào sẽ thay **cả mục**, kể cả các trường máy 0.2 sửa trước đó nhưng sớm hơn lần sửa kia
  (mật khẩu mới thua vẫn nằm trong `password_history`). Xoá vĩnh viễn ở máy 0.1.x không xoá một mục
  được sửa sau lần xoá đó (bước 3), trừ trường hợp còn lại nêu ở bước 3.

Giả định: đồng hồ các máy lệch nhau không quá vài giây (Windows và Android tự đồng bộ giờ qua
Internet). Đồng hồ sai nhiều có thể làm bản sửa "cũ" thắng bản sửa "mới" của cùng một trường — mật
khẩu thua vẫn nằm trong lịch sử.

## 6. Quy tắc đọc/ghi và đồng bộ

1. Khi mở: ghi nhớ SHA-256 của file.
2. **Mọi thao tác sửa là một giao dịch:** đọc lại file; nếu SHA-256 khác ⇒ máy khác đã ghi ⇒ giải mã
   và gộp (mục 5) TRƯỚC khi sửa; sửa; ghi. Nếu ghi thất bại TRƯỚC khi file kho bị thay (không ghi được
   file tạm, không `rename` được, không cất được bản khoá cũ ở bước 3), thay đổi trong RAM được hoàn tác.
3. **Giải mã một file của cùng kho** (`vault_id` trùng): thử `vault_key` hiện tại, rồi các khoá trong
   `old_keys`. Có ba kết quả:
   - **Khoá hiện tại mở được** ⇒ được gộp. Nếu header của file có `key_changed_at` mới hơn ⇒ bản app
     ≤ 0.1.2 ở máy khác đã đổi mật khẩu theo kiểu cũ (cùng khoá) ⇒ nhận header đó (nó đã được xác thực:
     header nằm trong AAD của phần thân).
   - **Chỉ một khoá đã nghỉ mở được**, hoặc khoá hiện tại mở được nhưng header mang dấu `pre_change`
     (mục 3) ("bản khoá cũ") ⇒ **KHÔNG BAO GIỜ tự gộp** (kể cả bản cứu hộ / bản lưu riêng trong thư
     mục riêng của app, xem "Dữ liệu riêng của app" bên dưới) — một máy chưa biết lần đổi mật khẩu ghi ra
     được file như vậy, nhưng người biết mật khẩu cũ và giữ một bản sao cũ cũng làm được. File tìm thấy
     TRONG thư mục đồng bộ (bản cạnh kho, file kho chính) được cất **nguyên văn** (đúng từng byte) vào
     thư mục sao lưu dưới tên `oldkey-<ms>-<tên gốc>` — các byte đó vốn đã nằm trong thư mục đồng bộ;
     chủ kho xem lại và lấy từng mục ra bằng chức năng khôi phục từ bản sao lưu. Nếu mã hoá lại một file
     như vậy bằng khoá hiện tại mà KHÔNG có dấu xác thực, thì chỉ còn TÊN FILE phân biệt nó với một bản
     đáng tin, mà ai có quyền ghi vào thư mục cũng đổi tên / chuyển chỗ file được (chuyển ra cạnh file
     kho ⇒ bị gộp như bản xung đột; đổi tên thành bản tự động ⇒ bị gộp khi khôi phục). Mã hoá lại chỉ an
     toàn khi đi kèm dấu `pre_change` (nằm trong header, được phần thân xác thực): đó là cách dùng cho bản
     cứu hộ / bản lưu riêng trong thư mục RIÊNG của app — chúng thường chứa đúng những gì chưa từng lên
     thư mục đồng bộ, nên không được cất nguyên văn (mật khẩu cũ sẽ đọc được chúng ở đó); xem "Dữ liệu
     riêng của app". Nếu đó là file kho chính: nó được cất
     TRƯỚC khi file kho bị ghi đè (không cất được ⇒ không ghi, báo lỗi đọc/ghi), rồi file kho được ghi
     lại từ RAM; cùng những byte đó không bị xét lại ở lần đọc sau. Trên điện thoại (chỉ đọc) bản khoá
     cũ bị bỏ qua.
   - **Không khoá nào mở được**: nếu `key_changed_at` của file MỚI HƠN ⇒ với **file kho chính**: máy
     khác đã đổi master password ⇒ dừng, yêu cầu nhập mật khẩu mới (không ghi gì). Với **bản cạnh kho**
     (header chưa được xác thực — ai có quyền ghi vào thư mục cũng ghi được một con số lớn): chỉ báo
     "bản này dùng mật khẩu chính khác", để nguyên file và đồng bộ tiếp. Nếu không mới hơn ⇒ file hỏng
     (đồng bộ dở, bị sửa).
4. **Không bao giờ tự ghi đè** khi file trên đĩa: hỏng, biến mất, thuộc kho khác (`vault_id` khác),
   hoặc có số phiên bản lớn hơn. Mỗi trường hợp là một lỗi riêng; chỉ ghi khi người dùng xác nhận
   (file hỏng được CẤT vào thư mục sao lưu dưới tên `damaged-<ms>-<tên>`, không bị xoá; file biến mất
   được tạo lại sau khi đã chép bản trong RAM vào thư mục sao lưu, rồi đọc lại kiểm tra).
5. Ghi nguyên tử: file tạm cùng thư mục → `fsync` → `rename` đè → đọc lại và so từng byte; thử lại khi
   Windows báo file đang bị tiến trình khác giữ. Đọc lại sai/lỗi ⇒ chờ ~0,2 giây đọc lại; vẫn sai ⇒ ghi
   lại một lần nữa rồi kiểm tra (trừ khi ở BẤT KỲ lần đọc lại nào thứ đọc được là một file hợp lệ của
   kho này do máy khác vừa ghi — không đè lên nó). Vẫn không xác minh được ⇒ coi là **đã ghi nhưng chưa xác minh**: KHÔNG hoàn
   tác RAM (với đổi mật khẩu, hoàn tác sẽ để RAM ở khoá cũ trong khi đĩa dùng khoá mới), báo cho người
   dùng, quên SHA-256 của đĩa để lần đọc sau đọc lại thật, và đánh dấu cần ghi lại.
6. Đồng bộ nền: nạp và gộp file trên đĩa; nếu bản trong RAM có thứ file không có (dịch vụ đồng bộ đã
   thay file bằng bản của máy kia) thì **ghi lại**.
7. **Bản cạnh kho** (bản xung đột do dịch vụ đồng bộ tạo: Google Drive `vault (1).pwv`, Dropbox
   `vault (… conflicted copy …).pwv`, OneDrive `vault-TÊN-MÁY.pwv`…) được nhận diện **theo nội dung**:
   các file khác trong cùng thư mục có cùng phần mở rộng với file kho (không phân biệt hoa/thường),
   không phải file ẩn (tên bắt đầu bằng `.`), ≤ 64 MiB, và có cùng `vault_id` trong header — lọc theo
   header TRƯỚC, rồi mới lấy tối đa 32 file đầu tiên theo thứ tự tên (file `.pwv` rác KHÔNG mang
   `vault_id` của kho, dù nhiều bao nhiêu, không chiếm chỗ). File rác mang ĐÚNG `vault_id` của kho (header
   chép từ file thật) thì VẪN chiếm được 32 chỗ: khi đó bản xung đột thật xếp sau không được xét ở lần
   đồng bộ đó (nó được để nguyên, không bị xoá), và các file rác hiện ra như 32 bản không mở được ở mọi
   lần đồng bộ. Ít hơn 32 file như vậy thì bản thật vẫn được gộp. Xử lý theo mục 6.3: bản khoá hiện tại được gộp, rồi chỉ SAU KHI kho đã được ghi
   thành công, và chỉ nếu file vẫn giống từng byte với bản đã gộp, mới được chuyển vào thư mục sao lưu
   (`merged-<ms>-<tên gốc>`; nếu đã đổi thì để lần đồng bộ sau). Bản khoá cũ được chuyển nguyên văn
   vào thư mục sao lưu (`oldkey-…`) — chỉ nếu nó không đổi từ lúc đọc.
8. **Mở khoá** bằng mật khẩu `pw`:
   - `pw` mở được file chính ⇒ thử thêm `pw` trên tối đa 2 bản cạnh kho (mới nhất trước) có header khác
     file chính, `key_changed_at` mới hơn, và tham số Argon2 không vượt file chính ở chiều nào (`m`, `t`,
     `p`). Bản nào mở được là một lần đổi mật khẩu ở máy khác (có thể hai máy cùng đổi sang một mật khẩu
     mới khi chưa đồng bộ): hai khoá đều được `pw` xác thực ⇒ gộp hai bên, nhận header + khoá của bản
     mới hơn làm hiện tại, khoá cũ vào `old_keys`; lần đồng bộ sau ghi lại file chính và cất bản kia
     (`merged-…`).
   - `pw` không mở được file chính ⇒ thử `pw` trên các bản khác của cùng kho có **gói khoá khác** file
     chính (cùng gói khoá thì chắc chắn cũng không mở được — bỏ qua, không tốn Argon2), `key_changed_at`
     **không cũ hơn** file chính, và tham số Argon2 không vượt max(tham số của file chính, mặc định
     256 MiB / 3 / 4): tối đa 2 bản cạnh kho (`key_changed_at` tự khai mới nhất trước), rồi các bản sao
     lưu tự động / bản xung đột đã gộp (cũng theo `key_changed_at` tự khai mới nhất trước) — tổng cộng
     tối đa **2 lượt Argon2**, mỗi "gói khoá" (cùng muối + khoá đã gói) một lượt. Bản mang dấu
     `pre_change` bị bỏ qua. Một bản chỉ được dùng khi mở được TRỌN VẸN (gói khoá + phần thân, nên header
     của nó được xác thực); khi đó xét file chính bằng khoá của bản đó (mục 6.3): cùng khoá ⇒ gộp; khoá
     cũ ⇒ cất `oldkey-…` ở lần ghi sau (đây là trường hợp một máy chưa biết mật khẩu mới đã ghi đè file
     kho: mật khẩu hiện tại vẫn mở ra kho thật từ bản sao lưu mới nhất); không giải mã được ⇒ KHÔNG mở
     từ bản đó. Ai biết mật khẩu cũ và có quyền ghi tự làm được một "bản mới hơn" mở bằng mật khẩu cũ
     với khoá do họ chọn; đòi khoá đó mở được file chính (họ không có khoá hiện tại) là thứ ngăn chủ kho
     lỡ gõ mật khẩu cũ rồi bị đưa sang kho của họ.
   - **Header của file chính bị hỏng / bị sửa ⇒ "file hỏng", không phải "sai mật khẩu".** Nếu bản vừa mở
     trọn vẹn không mở được file chính, app vẫn kiểm tra xem có CHỨNG MINH được file chính là file thật
     của kho với header bị đổi hay không: (a) phần thân của file chính xác thực được bằng khoá của bản
     đó khi dùng prefix + header CỦA BẢN ĐÓ làm AAD (từ lần đổi mật khẩu gần nhất, mọi bản sao lưu có
     cùng header với file chính lúc nó được ghi, nên điều này đúng khi chỉ các byte header bị đổi), hoặc
     (b) phần thân xác thực được bằng chính AAD của nó nhưng JSON bên trong hỏng. Chứng minh được ⇒ lỗi
     **`VaultFileDamaged`** (app mời "Khôi phục từ bản sao lưu"; kho KHÔNG được mở từ bản kia — chủ kho
     đi qua bước khôi phục với các kiểm tra mật khẩu cũ / quay lui). Không chứng minh được ⇒ vẫn là sai
     mật khẩu (`Decrypt`): người chỉ có mật khẩu cũ không làm ra được chứng minh (a) vì không có khoá
     hiện tại. Chi phí: gõ nhầm trên một kho nguyên vẹn chỉ tốn **1** lượt Argon2 (các bản sao lưu thật
     cùng gói khoá với file chính nên bị bỏ qua, kể cả khi có file cài sẵn cùng gói khoá tự khai số
     mới hơn); header file chính bị sửa gói khoá ⇒ 1 + tối đa 2 lượt. Bỏ sót: khi header gốc của file
     chính không còn khớp bản sao lưu nào (ví dụ bản sao lưu của lần ghi đổi mật khẩu bị lỗi ghi) thì vẫn
     báo sai mật khẩu; sửa `kdf` sai giới hạn, số phiên bản hay `header_len` cho lỗi riêng của chúng
     (tham số KDF không hợp lệ / định dạng mới hơn / file hỏng), không đi qua đường này.
9. **Đổi master password**: trước hết đồng bộ đầy đủ (gộp các bản xung đột còn dùng khoá hiện tại, vì
   sau đó chúng chỉ còn là bản khoá cũ); lỗi ⇒ không đổi. Hệ quả: mọi thứ người biết mật khẩu hiện tại
   (sắp thành cũ) ghi vào file kho / bản cạnh kho TRƯỚC lần đổi đều đã được gộp và đi theo sang kho
   mới — đổi mật khẩu không gỡ chúng ra; chủ kho nghi bị lộ nên xem lại các mục vừa đổi gần đây. Đổi
   sang đúng mật khẩu đang dùng được chấp nhận và vẫn sinh `vault_key` mới (app và CLI không áp chính
   sách mật khẩu khi đó, chỉ cảnh báo nếu mật khẩu không còn đạt).
10. **Chuyển kho sang thư mục khác**: đồng bộ ở chỗ cũ → ghi chỗ mới → đọc lại, giải mã thử → chuyển
    thư mục sao lưu → xoá file cũ chỉ khi nó vẫn đúng là bản đã đồng bộ (máy khác ghi vào giữa chừng
    ⇒ gộp nó vào chỗ mới trước, không gộp được ⇒ để nguyên). Chỉ khi file ở chỗ cũ hỏng / biến mất /
    thuộc kho khác / do bản app mới hơn ghi thì mới "cứu" bản đang mở sang chỗ mới và để nguyên chỗ cũ;
    lỗi khác (đọc/ghi tạm thời, đĩa đầy, mật khẩu đã đổi) ⇒ huỷ chuyển.
    **"Lưu sang chỗ khác" (chỉ chép, `Vault::copy_to`)** — nút trên dải báo lỗi file kho của app: chỉ
    ĐỌC chỗ cũ (gộp nếu đọc được; lỗi đọc khác bỏ qua), ghi bản trong RAM ra chỗ mới (không ghi đè file
    đã có), đọc lại kiểm tra rồi dùng chỗ mới. Nếu file ở chỗ cũ cho thấy master password đã được đổi ở
    máy khác ⇒ từ chối, không ghi gì (bản mới sẽ là một kho tách riêng dùng mật khẩu CŨ). App còn từ chối
    chỗ mới nằm trong chính thư mục của file kho (file mới sẽ bị coi là bản xung đột của nó). Không bao giờ ghi, xoá hay chuyển gì ở chỗ cũ (file kho,
    bản xung đột, thư mục sao lưu); file ở chỗ cũ có thể còn giữ thay đổi mới hơn của máy khác.

### Thư mục sao lưu `<tên file kho>.backups/`

- Trước khi ghi đè: chép bản đang nằm trên đĩa nếu nó chưa chắc đã có trong thư mục sao lưu (bản do
  máy khác hoặc bản app cũ ghi; lần ghi đầu của phiên) — trừ bản khoá cũ (đã được cất nguyên văn dưới
  tên `oldkey-…`, mục 6.3).
- Sau khi ghi: chép luôn bản vừa ghi ⇒ sau mỗi lần ghi bình thường (lưu, đồng bộ, đổi mật khẩu, ghi
  đè file hỏng, tạo lại file biến mất), nếu chép được, **bản sao lưu mới nhất giống hệt file kho**.
  KHÔNG đúng: ngay sau khi tạo kho (chưa có bản sao lưu nào), sau khi chuyển kho (file ở chỗ mới được
  ghi riêng; bản sao lưu mới nhất có cùng nội dung nhưng khác byte), và khi lần ghi "chưa xác minh"
  (mục 6.5) — bản sao lưu được lấy từ bản trong RAM, còn đĩa thì chưa chắc.
- Tên: `<tên>-<ms>.pwv` (tự động), `merged-<ms>-<tên>` (bản xung đột đã gộp), `damaged-<ms>-<tên>`
  (file hỏng đã thay), `oldkey-<ms>-<tên>` (bản khoá cũ, chưa gộp, nguyên văn).
- **Giữ lại** bản tự động theo một quy tắc chỉ phụ thuộc vào thời điểm trong tên file — KHÔNG phụ thuộc
  đồng hồ của máy đang dọn (một máy sai giờ dọn theo đồng hồ của nó sẽ xoá lịch sử trên mọi máy): bỏ
  trùng, xếp mới → cũ; giữ 10 bản mới nhất; bản mới nhất của mỗi ngày UTC trong 30 ngày gần nhất CÓ
  bản sao lưu; bản mới nhất của mỗi kỳ 30 ngày (`floor(ngày / 30)`, tính từ 1970) trong 12 kỳ gần nhất
  CÓ bản sao lưu; xoá phần còn lại. `merged-`, `damaged-`, `oldkey-`: mỗi loại giữ 20 bản mới nhất.
  Chỉ xoá file có đúng `vault_id` của kho.
- Khi đổi master password, các file trong thư mục này mở được bằng **khoá vừa bị thay** (khoá hiện tại
  cho tới lúc đổi) được mã hoá lại tại chỗ bằng khoá mới **và gắn dấu `pre_change`** (mục 3): từ đó
  chúng là "lịch sử để xem", không bao giờ được tự dùng. Phần thân của mỗi bản được mã hoá lại nhận
  thêm MỌI khoá trong `old_keys` của kho (kể cả khoá vừa bị thay), để một kho dựng lại chỉ từ các bản
  này vẫn đọc được file của thời khoá cũ. File nào không ĐỌC được hoặc không GHI lại được được thử lại
  một lần ở cuối; vẫn lỗi ⇒ tên nó được báo cho chủ kho (app và `pwv passwd`): file đó có thể VẪN mở
  được bằng mật khẩu vừa bị thay, nên xoá đi nếu mật khẩu cũ có thể đã lộ (file không đọc được thì không
  phân loại được, nên có thể cả một bản đã dùng mật khẩu mới cũng bị nêu tên). File không phải file kho,
  file quá 64 MiB (không được đọc) và file chỉ mở được bằng một khoá cũ hơn nữa được để nguyên và chỉ
  được đếm; file của kho khác (khác `vault_id`) bị bỏ qua, không đếm.
  `damaged-…` bị bỏ qua mà không đọc. File chỉ mở được bằng một khoá đã nghỉ từ
  TRƯỚC đó thì để nguyên và không bao giờ được mã hoá lại ở bất cứ đâu: thư mục sao lưu nằm trong thư
  mục đồng bộ, nên người biết một mật khẩu cũ có thể đặt vào đó file do họ tự mã hoá bằng khoá cũ; mã
  hoá lại file ấy bằng khoá hiện tại là biến nó thành "bản sao lưu đáng tin". Hệ quả: nếu lần đổi mật
  khẩu bị ngắt trước khi mã hoá lại xong, các bản sao lưu còn dở vẫn mở được bằng mật khẩu cũ (chúng
  chỉ chứa dữ liệu từ trước lần đổi); chủ kho vẫn xem / khôi phục từng mục từ chúng được.
- Bản sao lưu chỉ mở được bằng khoá đã nghỉ, hoặc mang dấu `pre_change` (dù tên thuộc loại nào), được
  app đánh dấu "ghi bằng mật khẩu cũ" trong danh sách khôi phục (`Vault::read_backup_checked`), vì nó
  có thể không phải do chủ kho ghi. Hệ quả: sau một lần đổi master password, MỌI bản sao lưu có từ
  trước lần đổi đều mang nhãn này.
- **Khôi phục khi file kho chính hỏng/mất**: các bản sao lưu (trừ `damaged-` và `oldkey-`) được nhóm
  theo **gói khoá** (`vault_id` + tham số KDF + muối + khoá đã gói; `key_changed_at` KHÔNG thuộc gói
  khoá và chưa được xác thực — ai cũng chép được một header thật rồi sửa con số đó). File > 64 MiB bị
  bỏ qua. Thử mật khẩu trên từng gói (mỗi gói một lượt Argon2) — gói cùng `vault_id` với file kho
  chính (nếu header của nó còn đọc được) trước, rồi `key_changed_at` tự khai mới nhất trước — tối đa 5
  gói. **Gốc** là bản mới nhất của gói đầu tiên mở được mà PHẦN THÂN giải mã được bằng khoá vừa mở và
  KHÔNG mang dấu `pre_change` (không giới hạn số file xét trong gói: file rác mang tên "mới nhất" không
  đẩy được bản thật ra): phần thân nhận header làm dữ liệu xác thực, nên header của kho dựng lại (kể
  cả `key_changed_at`) là header thật. Sau đó gộp thêm các bản giải mã được bằng ĐÚNG khoá của gốc và
  không mang dấu: MỌI bản như vậy đều được gộp (không còn giới hạn số bản gộp hay số file xét), bỏ qua
  bản trùng từng byte (SHA-256) với bản đã gộp; số "bản đã dùng" báo cho chủ kho chỉ tính bản THÊM được
  gì đó (gốc tính là một). Những gì còn bị chặn: tối đa 5 gói khoá (5 lượt Argon2), mỗi file ≤ 64 MiB, và
  thời điểm "bản mới nhất được dùng" không vượt đồng hồ của máy (tên file "tương lai" bị cắt về hiện
  tại). Bản chỉ mở được bằng khoá khác (khoá đã nghỉ) không bao giờ được gộp. Nếu có bản của cùng kho,
  dùng gói khoá KHÁC, tự khai `key_changed_at` mới hơn gốc (rất có thể mật khẩu vừa nhập là mật khẩu
  CŨ; con số này không xác thực được nên đây chỉ là lý do để dừng và hỏi lại) ⇒ lỗi "mật khẩu cũ" —
  kiểm tra này đi TRƯỚC: nếu gói khoá mở được mà chỉ còn các bản mang dấu `pre_change` và có gói khác
  tự khai mới hơn thì cũng là lỗi "mật khẩu cũ"; chỉ khi không có gói nào như thế mới là lỗi riêng "chỉ
  còn các bản có từ trước lần đổi mật khẩu" (mọi bản ghi sau lần đổi đã mất). Cả hai chỉ được vượt khi
  chủ kho chọn rõ ràng (khi đó kho quay về mật khẩu đó / được dựng từ các bản mang dấu — bản đầu tiên
  giải mã được luôn được tính, để cả một kho rỗng cũng dựng lại được; kho ghi ra là file kho bình
  thường, không mang dấu). Không có bản nào dùng được ⇒ lỗi riêng ("không có bản sao lưu nào dùng
  được").
- **Sau bước của lõi** (chỉ trong RAM, chưa ghi gì), app và `pwv recover` còn so kho vừa dựng với mốc
  "đã thấy" của chính máy đó (mục dưới): máy này đã biết một lần đổi mật khẩu mới hơn hoặc một khoá mà
  kho dựng lại không biết ⇒ lỗi "mật khẩu cũ"; kho dựng lại có `modified_at` CŨ HƠN mốc ⇒ dừng và hỏi
  (app: lỗi `older_than_seen` kèm hai mốc thời gian, nút "Vẫn khôi phục bản cũ hơn này"; CLI: hỏi trực
  tiếp, `-y` không bỏ qua được, không có cửa sổ dòng lệnh ⇒ từ chối). App gộp bản lưu riêng và các bản
  cứu hộ của máy này (mục dưới) TRƯỚC lần so `modified_at` này. Không có bản sao lưu nào dùng được ⇒ app
  thử dựng lại từ bản lưu riêng, rồi từ các bản cứu hộ (mới nhất trước), với cùng các kiểm tra, và
  không bao giờ thay một file kho chính thuộc kho khác / ghi lần đổi mật khẩu mới hơn / có định dạng
  mới hơn (trừ khi chủ kho chọn rõ). Chỉ khi qua hết mới cất file hỏng (`damaged-…`) và ghi.

### Mốc "đã thấy" của từng máy (`config.json`, ngoài thư mục đồng bộ)

Mỗi máy ghi nhớ cho từng kho (`seen.<vault_id>`): `modified_at` lớn nhất đã thấy, `key_changed_at` lớn
nhất đã thấy, và một **dấu khoá** 64 bit (`key_tag`) của khoá kho nó dùng gần nhất:
`SHA-256("pwv/v1/key-tag\0" || vault_id || 0x00 || vault_key)`, lấy 8 byte đầu (little-endian), bật
bit thấp nhất. Dấu này không phải bí mật và không suy ngược ra khoá được.

Hai trường phụ (không bí mật, vắng mặt = mặc định):
- `seen.<vault_id>.wrap_scan` (u64, 0 = chưa quét): dấu khoá mà lần quét "bản sao lưu mở được khoá hiện
  tại bằng một master password KHÁC" gần nhất không thấy gì (`Vault::backups_under_other_password`:
  tối đa 300 bản tự động / bản xung đột đã gộp mới nhất, cùng `vault_id`, gói khoá khác header hiện tại,
  không mang dấu `pre_change`, phần thân giải mã được bằng khoá HIỆN TẠI; không chạy Argon2). Kết quả > 0
  là dấu hiệu kho từng đổi mật khẩu bằng 0.1.x (đổi mật khẩu mà giữ khoá) ⇒ app hiện lời mời đổi master
  password một lần. Lọc theo `vault_id` TRƯỚC giới hạn 300. Lần quét **không trọn vẹn** (có file của kho
  không đọc được hay quá 64 MiB, hoặc chạm giới hạn 300) mà không thấy gì ⇒ báo lỗi chứ không báo
  "sạch", và app không ghi nhớ gì (sẽ quét lại lần sau). App chỉ quét lại khi dấu khoá đổi (tức sau một
  lần đổi mật khẩu); `pwv backups` quét mỗi lần chạy và không dùng trường này.
- `last_vault_id` (cấp cao nhất, chuỗi hoặc vắng): `vault_id` của kho ở đường dẫn đang cấu hình
  (`vault`), ghi khi kho ở ĐÚNG đường dẫn đó được mở / được chấp nhận làm mốc; xoá khi đường dẫn đổi
  sang file khác. Dùng để tìm bản lưu riêng của kho khi file kho chính đã mất (mục dưới).

Bản 0.1.x không biết các trường này và cả `seen`: nếu nó ghi lại `config.json` (CLI 0.1.x, app 0.1.x mở
kho lần đầu…) thì mọi mốc "đã thấy" bị xoá, và máy đó bắt đầu lại như chưa từng thấy kho.

Khi mở kho, app cảnh báo nếu: `modified_at` của file nhỏ hơn mốc (file bị thay bằng bản cũ);
`key_changed_at` nhỏ hơn mốc (file dùng mật khẩu chính cũ hơn); hoặc kho vừa mở **không biết** khoá
mang dấu đã ghi nhận — tức khoá đó không phải khoá hiện tại và cũng không nằm trong `old_keys` của
kho. Điều kiện cuối bắt được trường hợp hai điều kiện đầu bỏ sót: người biết mật khẩu CŨ thay file kho
bằng file tự làm (họ ghi được mọi mốc thời gian, nhưng không có khoá mà máy này dùng lần trước) rồi
chủ kho lỡ gõ mật khẩu cũ. Đổi mật khẩu hợp lệ thì không cảnh báo: kho mới chứa khoá cũ trong
`old_keys`. Mốc chỉ tăng; dấu khoá chỉ được thay khi kho mới nối tiếp kho cũ, hoặc khi chủ kho bấm
chấp nhận cảnh báo / vừa khôi phục từ sao lưu. (Giới hạn: sau hơn 16 lần đổi mật khẩu mà một máy
không hề mở kho, khoá cũ của máy đó đã rơi khỏi `old_keys` ⇒ cảnh báo nhầm một lần.)

### Dữ liệu riêng của app trên máy này (ngoài thư mục đồng bộ)

App máy tính giữ một thư mục riêng, **không đồng bộ**: `<app_local_data_dir>/rescue` — trên Windows
`%LOCALAPPDATA%\vn.pwv.vault\rescue`. Kho chỉ đọc (điện thoại) không ghi bản lưu riêng hay bản nháp.

| File | Nội dung | Khi nào ghi | Dùng thế nào |
|---|---|---|---|
| `<vault_id>-<ms>.pwv` | **Bản cứu hộ**: toàn bộ kho trong RAM, định dạng `.pwv` bình thường (mục 1–4), mã hoá như file kho | Khi phải khoá (hết giờ, đóng cửa sổ) mà còn thay đổi chưa ghi được ra file kho | Gộp ở lần mở khoá sau (và khi khôi phục); bản gộp được chỉ bị xoá sau khi kho đã ghi thành công; bản ghi bằng khoá đã nghỉ bị xoá ngay sau khi đã cất (hoặc không có gì mới) |
| `last-<vault_id>.pwv` | **Bản lưu riêng**: bản sao toàn bộ kho, định dạng `.pwv` bình thường | Sau mỗi lần đọc/ghi thành công và khi khoá — khi một trong (`vault_id`, SHA-256 của file kho trên đĩa, dấu khoá, `modified_at`, số mục, số mục trong thùng rác) đổi, và luôn khi còn thay đổi chưa ghi hoặc lần ghi gần nhất chưa xác minh | Gộp ở mỗi lần mở khoá (trước bản cứu hộ); khôi phục khi không còn bản sao lưu nào dùng được hoặc chỉ còn bản `pre_change`; nút "Tạo lại file kho từ bản lưu riêng" khi file kho mất |
| `stash-<vault_id>.bin` | Khối niêm phong `"stash"`: bản nháp form đang sửa dở + danh sách "mật khẩu vừa tạo gần đây" (tối đa 20, mỗi dòng giữ tối đa 30 ngày) | Bản nháp: ~0,4 giây sau mỗi thay đổi trong form, khi cửa sổ bị ẩn / mất tiêu điểm, trước khi bấm khoá; xoá khi lưu hoặc bỏ thay đổi. Mật khẩu vừa tạo: khi bấm sao chép / "Dùng mật khẩu này" trong bộ tạo | Mở lại form sau khi mở khoá; mục "Mật khẩu vừa tạo gần đây" |

- Chỉ **app máy tính** ghi các file này. Công cụ dòng lệnh `pwv.exe` không ghi bản lưu riêng, bản cứu
  hộ, bản nháp hay danh sách mật khẩu vừa tạo; thay đổi làm bằng CLI chỉ nằm trong file kho (và thư mục
  sao lưu).
- **Gộp bản cứu hộ / bản lưu riêng** (`Vault::merge_local_file`), cùng quy tắc tin cậy với mục 6.3:
  - giải mã được bằng **khoá hiện tại** và không mang `pre_change` ⇒ gộp (phép hợp của mục 5: không làm
    sống lại mục đã xoá vĩnh viễn, không đè lên thay đổi mới hơn);
  - chỉ mở được bằng **khoá đã nghỉ**, hoặc mang `pre_change` ⇒ **không bao giờ gộp**. Lõi thử gộp
    trong RAM: nếu nó có thêm gì so với kho, nội dung của nó được **mã hoá lại bằng khoá HIỆN TẠI** với
    dấu `pre_change` (kèm `old_keys` của kho — đúng dạng các bản sao lưu được mã hoá lại lúc đổi mật
    khẩu) và cất vào thư mục sao lưu thành `oldkey-<ms>-<tên file>` (nhãn "ghi bằng mật khẩu cũ", giữ lại
    như các bản `oldkey-` khác); app báo cho chủ kho. KHÔNG cất nguyên văn: bản cứu hộ thường chứa đúng
    những gì chưa lên được thư mục đồng bộ, cất nguyên văn vào đó sẽ để mật khẩu cũ đọc được. Nội dung
    trùng với một bản `oldkey-` đã có thì không cất thêm (trả về bản đã có). Nếu không có gì mới thì
    không cất gì. Cất không được ⇒ lỗi (file được giữ). Bản ghi bằng khoá đã nghỉ (đã cất, hoặc không có
    gì mới) được app xoá khỏi thư mục riêng ngay, không chờ kho ghi xong.
    (File ghi bằng khoá đã nghỉ tìm thấy TRONG thư mục đồng bộ — bản xung đột, file kho chính — vẫn được
    cất nguyên văn như mục 6.3: các byte đó vốn đã ở đó.)
  (Bản 0.2.0 trước đợt soát fix3 từng gộp cả nội dung dưới khoá đã nghỉ từ thư mục này; đã bỏ: ai dùng
  được tài khoản Windows và biết một mật khẩu cũ đặt được file vào đó.)
- Bản **không mở được** (khoá mà kho hiện tại không biết — ví dụ ghi bằng một master password MỚI HƠN
  hoặc khác hẳn, như khi kho vừa được dựng lại bằng một mật khẩu cũ; khoá đã rơi khỏi `old_keys` sau
  hơn 16 lần đổi; file hỏng) **không bị xoá**: app báo "N bản cứu hộ chưa gộp được" và thử lại ở lần mở
  khoá sau. Bản lưu riêng không gộp được được đổi tên thành tên bản cứu hộ (`<vault_id>-<ms>.pwv`) để vào
  cùng luồng đó; bản lưu riêng có sẵn mà phiên này chưa gộp / kiểm tra cũng được đổi tên như vậy thay vì
  bị ghi đè. Trong app không có nút mở riêng các bản này; mở bằng `tools/pwv_recover.py` với master
  password của thời điểm bản đó được ghi.
- **Khối niêm phong** (`Vault::seal_local` / `open_local`):
  ```
  subkey = HKDF-SHA256(IKM = vault_key, salt = (rỗng), info = "pwv/v1/local\0" || purpose, L = 32)
  aad    = "pwv/v1/local\0" || purpose || 0x00 || vault_id
  blob   = "PWL1" || nonce (24 byte ngẫu nhiên) || XChaCha20-Poly1305(subkey, nonce, plaintext, aad)
  ```
  Mở: thử khoá hiện tại rồi từng khoá trong `old_keys` (khối niêm phong trước một lần đổi mật khẩu vẫn
  mở được); sai `purpose`, của kho khác, bị sửa, cụt ⇒ không mở (không lỗi). App chỉ dùng
  `purpose = "stash"`; nội dung (JSON) là chi tiết của app, không thuộc đặc tả này. Không mở được ⇒ app
  bỏ qua và giữ nguyên file; trước lần ghi đầu, file cũ được đổi tên `stash-<id>.unreadable-<ms>.bin`.

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
- Thư mục sao lưu cũng nằm trong thư mục đồng bộ. Một file mở được bằng khoá đã nghỉ mà ai đó (biết
  mật khẩu cũ, có quyền ghi) đặt vào ĐÓ — hoặc bản sao lưu do một máy chưa biết lần đổi mật khẩu ghi —
  không bao giờ được tự gộp hay mã hoá lại, nhưng vẫn HIỆN trong danh sách khôi phục (có nhãn "ghi bằng
  mật khẩu cũ") và chiếm chỗ trong quy tắc giữ lại như một bản tự động. Chủ kho chỉ nên khôi phục mục
  từ bản mang nhãn đó khi biết chắc nó là của mình.
- Tên và header của file trong thư mục sao lưu chưa được xác thực: kẻ có quyền ghi có thể đặt vào hàng
  chục file mang thời điểm "tương lai" để quy tắc giữ lại xoá dần các bản thật (họ cũng có thể xoá
  thẳng các bản đó). Lịch sử phiên bản / thùng rác của dịch vụ đồng bộ là lớp dự phòng cho trường hợp này.
- Hai lần đổi mật khẩu (sang cùng một mật khẩu mới) trên hai máy chưa đồng bộ chỉ được nối lại khi
  file kho CHÍNH trong thư mục là nhánh đổi TRƯỚC và bản cạnh kho là nhánh đổi sau (mục 6.8). Nếu ngược
  lại, nhánh kia hiện là "bản hỏng" và các thay đổi trên nó không được gộp tự động. Đổi sang hai mật
  khẩu KHÁC nhau thì không bao giờ được nối tự động.
- Kẻ biết mật khẩu cũ và có quyền ghi có thể thay file kho chính bằng file tự làm, mở được bằng mật
  khẩu CŨ: nếu chủ kho lỡ gõ mật khẩu cũ, kho mở ra là kho của họ. Gõ mật khẩu HIỆN TẠI thì app mở kho
  thật từ bản sao lưu mới nhất còn mở được (mục 6.8), file kia được cất `oldkey-…`; nếu không còn bản
  nào như vậy thì báo sai mật khẩu (dùng "Khôi phục từ bản sao lưu" / `pwv recover`). App không ngăn
  được việc mở kho giả bằng mật khẩu cũ nhưng CẢNH BÁO trên máy đã từng mở kho thật (dấu khoá, xem "Mốc
  đã thấy" ở mục 6); máy mới cài thì không có gì để so. Quy tắc cho chủ kho: sau khi đổi master
  password, đừng bao giờ gõ lại mật khẩu cũ.
- Header của bản cạnh kho / bản sao lưu chưa được xác thực: kẻ có quyền ghi (không cần khoá) có thể
  làm mỗi lần mở khoá tốn thêm tối đa 2 lượt Argon2 (mỗi lượt tối đa 3 cách viết Unicode của mật khẩu;
  tham số bị chặn như mục 6.8), và làm việc khôi phục từ sao lưu báo nhầm "mật khẩu cũ" hoặc đẩy nhóm
  thật ra khỏi 5 lượt thử (họ cũng có thể xoá thẳng các file đó).
- **Từ chối dịch vụ ở bước mở khoá qua bản mới hơn (mục 6.8, còn để ngỏ):** các ứng viên được xếp theo
  `key_changed_at` TỰ KHAI. Hai file đặt vào thư mục sao lưu / cạnh kho với hai gói khoá giả khác nhau
  và một con số rất lớn dùng hết 2 lượt Argon2, nên bản sao lưu thật không bao giờ được thử: khi một
  máy chưa biết mật khẩu mới đã ghi đè file kho, mật khẩu HIỆN TẠI bị báo SAI, và "khôi phục từ sao
  lưu" sau đó lại báo "mật khẩu cũ" (vì file giả tự khai mới hơn) — chủ kho phải chọn rõ "vẫn khôi phục
  bằng mật khẩu này". Cũng vậy, hai file như thế làm trường hợp "header file chính bị sửa" quay về báo
  sai mật khẩu thay vì "file hỏng". Không mất dữ liệu (không có gì được ghi), nhưng chủ kho có thể bị
  đẩy về phía gõ mật khẩu cũ hay bỏ cuộc.
- Một máy còn đang mở khoá khi master password được đổi ở máy khác vẫn dùng khoá cũ cho tới khi nó biết
  về lần đổi: trong lúc đó các file ghi bằng mật khẩu cũ vẫn là "khoá hiện tại" đối với nó và được gộp.
  Vì vậy chủ kho nên khoá / đóng app trên các máy khác TRƯỚC khi đổi master password.
- Khi còn máy chạy 0.1.x: mục v1 không có thời điểm từng trường (mục 5), nên một lần sửa ở máy đó thay
  được cả mục khi file của nó được gộp vào; và một tombstone v1 đã được ghi vào file v2 là tuyệt đối
  (mục 5, bước 3), nên một lần sửa muộn ở máy 0.1.x có thể vẫn mất (còn trong bản sao lưu). Bản 0.1.x còn dọn thư mục sao lưu theo TÊN (`<tên>-*`, giữ 10 bản mới
  nhất, không xét `vault_id` hay định dạng): nếu một file v1 quay lại làm file kho chính (dịch vụ đồng
  bộ chọn bản của máy 0.1.x, hoặc chép tay) thì mỗi lần lưu ở máy 0.1.x xoá dần các bản sao lưu của 0.2.
  Kho từng đổi mật khẩu bằng 0.1.x (đổi mật khẩu mà giữ khoá) thì mật khẩu cũ vẫn mở ra khoá hiện tại từ
  các bản sao lưu cũ cho tới khi đổi mật khẩu một lần ở 0.2 (app tự phát hiện và nhắc, xem "Mốc đã
  thấy"). Không dùng 0.1.x nữa khi đã có một máy chạy 0.2.
- Header để lộ `vault_id`, tham số KDF và thời điểm đổi master password gần nhất; kích thước file để
  lộ cỡ của kho theo nấc 4 KiB; thư mục sao lưu để lộ thời điểm của các lần ghi.
