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
    và mọi thứ có từ TRƯỚC lần đổi cũng vậy (dấu `pre_change`).
- **`pre_change`** (trường tuỳ chọn của header, kiểu bool; vắng mặt = `false`): `true` nghĩa là file này
  là một bản sao lưu có từ trước lần đổi master password gần nhất, đã được mã hoá lại bằng khoá mới.
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
     (mục 3) ("bản khoá cũ") ⇒ **KHÔNG BAO GIỜ tự gộp** — một máy chưa biết lần đổi mật khẩu ghi ra
     được file như vậy, nhưng người biết mật khẩu cũ và giữ một bản sao cũ cũng làm được. File được cất **nguyên văn** (đúng từng byte) vào thư mục sao lưu dưới tên
     `oldkey-<ms>-<tên gốc>`; chủ kho xem lại và lấy từng mục ra bằng chức năng khôi phục từ bản sao
     lưu. KHÔNG được mã hoá lại nó bằng khoá hiện tại: khi đó chỉ còn TÊN FILE phân biệt nó với một bản
     đáng tin, mà ai có quyền ghi vào thư mục cũng đổi tên / chuyển chỗ file được (chuyển ra cạnh file
     kho ⇒ bị gộp như bản xung đột; đổi tên thành bản tự động ⇒ bị gộp khi khôi phục). Giữ nguyên văn
     thì ở đâu, mang tên gì nó cũng chỉ mở được bằng khoá đã nghỉ. Nếu đó là file kho chính: nó được cất
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
   không phải file ẩn (tên bắt đầu bằng `.`), ≤ 64 MiB, tối đa 32 file đầu tiên theo thứ tự tên, và có
   cùng `vault_id`. Xử lý theo mục 6.3: bản khoá hiện tại được gộp, rồi chỉ SAU KHI kho đã được ghi
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
   - `pw` không mở được file chính ⇒ thử `pw` trên các bản khác của cùng kho có `key_changed_at` mới
     hơn và tham số Argon2 không vượt max(tham số của file chính, mặc định 256 MiB / 3 / 4): tối đa 2
     bản cạnh kho (mới nhất trước), rồi các bản sao lưu tự động / bản xung đột đã gộp (mới nhất trước) —
     tổng cộng tối đa 2 lượt Argon2, mỗi "gói khoá" (cùng muối + khoá đã gói) một lượt. Bản nào có phần
     thân giải mã được ⇒ xét file chính bằng khoá của bản đó (mục 6.3): cùng khoá ⇒ gộp; khoá cũ ⇒ cất
     `oldkey-…` ở lần ghi sau (đây là trường hợp một máy chưa biết mật khẩu mới đã ghi đè file kho: mật
     khẩu hiện tại vẫn mở ra kho thật từ bản sao lưu mới nhất); không giải mã được ⇒ KHÔNG mở từ bản đó
     (báo sai mật khẩu). Ai biết mật khẩu cũ và có quyền ghi tự làm được một "bản mới hơn" mở bằng mật
     khẩu cũ với khoá do họ chọn; đòi khoá đó mở được file chính (họ không có khoá hiện tại) là thứ
     ngăn chủ kho lỡ gõ mật khẩu cũ rồi bị đưa sang kho của họ.
9. **Đổi master password**: trước hết đồng bộ đầy đủ (gộp các bản xung đột còn dùng khoá hiện tại, vì
   sau đó chúng chỉ còn là bản khoá cũ); lỗi ⇒ không đổi.
10. **Chuyển kho sang thư mục khác**: đồng bộ ở chỗ cũ → ghi chỗ mới → đọc lại, giải mã thử → chuyển
    thư mục sao lưu → xoá file cũ chỉ khi nó vẫn đúng là bản đã đồng bộ (máy khác ghi vào giữa chừng
    ⇒ gộp nó vào chỗ mới trước, không gộp được ⇒ để nguyên). Chỉ khi file ở chỗ cũ hỏng / biến mất /
    thuộc kho khác / do bản app mới hơn ghi thì mới "cứu" bản đang mở sang chỗ mới và để nguyên chỗ cũ;
    lỗi khác (đọc/ghi tạm thời, đĩa đầy, mật khẩu đã đổi) ⇒ huỷ chuyển.

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
  chúng là "lịch sử để xem", không bao giờ được tự dùng. File chỉ mở được bằng một khoá đã nghỉ từ
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
  khoá và chưa được xác thực — ai cũng chép được một header thật rồi sửa con số đó). Thử mật khẩu trên
  từng gói (mỗi gói một lượt Argon2) — gói cùng `vault_id` với file kho chính (nếu header của nó còn
  đọc được) trước, rồi `key_changed_at` tự khai mới nhất trước — tối đa 5 gói. **Gốc** là bản mới nhất
  của gói đầu tiên mở được mà PHẦN THÂN giải mã được bằng khoá vừa mở và KHÔNG mang dấu `pre_change`:
  phần thân nhận header làm dữ liệu xác thực, nên header của kho dựng lại (kể cả `key_changed_at`) là
  header thật. Sau đó chỉ gộp các bản giải mã được bằng ĐÚNG khoá của gốc và không mang dấu (tối đa 40
  bản gộp được, xét tối đa 500 file — file rác không giải mã được không chiếm chỗ của bản thật). Bản
  chỉ mở được bằng khoá khác (khoá đã nghỉ) không bao giờ được gộp. Nếu gói khoá mở được mà chỉ còn
  các bản mang dấu `pre_change` (mọi bản ghi sau lần đổi mật khẩu đã mất) ⇒ lỗi riêng; chỉ khi chủ kho
  chọn rõ ràng thì mới dựng lại từ các bản đó (kho ghi ra là file kho bình thường, không mang dấu). Nếu có bản của cùng kho, dùng gói khoá KHÁC, tự khai `key_changed_at` mới hơn
  gốc (rất có thể mật khẩu vừa nhập là mật khẩu CŨ; con số này không xác thực được nên đây chỉ là lý
  do để dừng và hỏi lại) ⇒ từ chối, trừ khi chủ kho chọn rõ "khôi phục từ các bản cũ" (khi đó kho
  quay về mật khẩu đó và chỉ có dữ liệu của các bản đó). App còn so kho vừa dựng với mốc "đã thấy" của
  chính máy đó (mục dưới) trước khi ghi. Không có bản nào dùng được ⇒ lỗi riêng ("không có bản sao lưu
  nào dùng được").

### Mốc "đã thấy" của từng máy (`config.json`, ngoài thư mục đồng bộ)

Mỗi máy ghi nhớ cho từng kho: `modified_at` lớn nhất đã thấy, `key_changed_at` lớn nhất đã thấy, và
một **dấu khoá** 64 bit của khoá kho nó dùng gần nhất:
`SHA-256("pwv/v1/key-tag\0" || vault_id || 0x00 || vault_key)`, lấy 8 byte đầu (little-endian), bật
bit thấp nhất. Dấu này không phải bí mật và không suy ngược ra khoá được.

Khi mở kho, app cảnh báo nếu: `modified_at` của file nhỏ hơn mốc (file bị thay bằng bản cũ);
`key_changed_at` nhỏ hơn mốc (file dùng mật khẩu chính cũ hơn); hoặc kho vừa mở **không biết** khoá
mang dấu đã ghi nhận — tức khoá đó không phải khoá hiện tại và cũng không nằm trong `old_keys` của
kho. Điều kiện cuối bắt được trường hợp hai điều kiện đầu bỏ sót: người biết mật khẩu CŨ thay file kho
bằng file tự làm (họ ghi được mọi mốc thời gian, nhưng không có khoá mà máy này dùng lần trước) rồi
chủ kho lỡ gõ mật khẩu cũ. Đổi mật khẩu hợp lệ thì không cảnh báo: kho mới chứa khoá cũ trong
`old_keys`. Mốc chỉ tăng; dấu khoá chỉ được thay khi kho mới nối tiếp kho cũ, hoặc khi chủ kho bấm
chấp nhận cảnh báo / vừa khôi phục từ sao lưu. (Giới hạn: sau hơn 16 lần đổi mật khẩu mà một máy
không hề mở kho, khoá cũ của máy đó đã rơi khỏi `old_keys` ⇒ cảnh báo nhầm một lần.)

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
  khẩu CŨ: nếu chủ kho lỡ gõ mật khẩu cũ, kho mở ra là kho của họ (gõ mật khẩu hiện tại thì không mở
  được / báo hỏng). App không ngăn được việc này nhưng CẢNH BÁO trên máy đã từng mở kho thật (dấu
  khoá, xem "Mốc đã thấy" ở mục 6); máy mới cài thì không có gì để so. Dữ liệu thật vẫn còn trong thư
  mục sao lưu. Quy tắc cho chủ kho: sau khi đổi master password, đừng bao giờ gõ lại mật khẩu cũ.
- Header của bản cạnh kho / bản sao lưu chưa được xác thực: kẻ có quyền ghi có thể làm mỗi lần mở khoá
  tốn thêm tối đa 2 lượt Argon2 (mỗi lượt tối đa 3 cách viết Unicode của mật khẩu; tham số bị chặn như
  mục 6.8), làm việc khôi phục từ sao lưu báo nhầm
  "mật khẩu cũ" hoặc đẩy nhóm thật ra khỏi 5 lượt thử (họ cũng có thể xoá thẳng các file đó).
- Header để lộ `vault_id`, tham số KDF và thời điểm đổi master password gần nhất; kích thước file để
  lộ cỡ của kho theo nấc 4 KiB; thư mục sao lưu để lộ thời điểm của các lần ghi.
