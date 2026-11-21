# Kế hoạch: Phần mềm tạo & lưu trữ mật khẩu bảo mật

> Mục tiêu: một ứng dụng **tạo mật khẩu mạnh** và **lưu giữ chúng trong một kho (vault) được mã hoá**, dùng cho các tài khoản quan trọng (ngân hàng, email, ví crypto, tài khoản công việc).
> Nguyên tắc số 1: **zero-knowledge** — chỉ người biết mật khẩu chính (master password) mới giải mã được dữ liệu. Không ai khác, kể cả chính phần mềm hay máy chủ, đọc được.

---

## 1. Các phần mềm nổi tiếng và bài học rút ra

| Phần mềm | Mô hình | Điểm mạnh nên học | Điểm yếu / bài học |
|---|---|---|---|
| **Bitwarden** | Mã nguồn mở, đồng bộ cloud (có thể tự host bằng Vaultwarden) | Mã hoá đầu-cuối AES-256 + HMAC, KDF **Argon2id** (mặc định 64 MB, 3 vòng, 4 luồng) hoặc PBKDF2; master password không bao giờ rời máy; được audit độc lập | Giá gói Premium tăng năm 2026; giao diện kém mượt hơn 1Password |
| **1Password** | Đóng mã nguồn, cloud | **Two-Secret Key Derivation (2SKD)**: master password + *Secret Key* 128-bit nằm trên thiết bị → dù server bị lộ dữ liệu, kẻ tấn công vẫn không brute-force được; dùng **SRP** để đăng nhập mà không gửi mật khẩu | Không có gói miễn phí, phụ thuộc nhà cung cấp |
| **KeePassXC** | Mã nguồn mở, **chỉ lưu cục bộ** (file `.kdbx`) | Định dạng KDBX 4 mở, công khai: **Argon2** + AES-256/ChaCha20; người dùng tự kiểm soát file; đã có audit bảo mật | Không có đồng bộ tích hợp (phải tự dùng Dropbox/Syncthing…); passkey còn thử nghiệm |
| **Proton Pass** | Mã nguồn mở, cloud | Mã hoá **cả metadata** (URL, username, ghi chú), không chỉ mật khẩu; email alias | Hệ sinh thái mới hơn |
| **LastPass** | Đóng, cloud | — | **Vụ rò rỉ 2022**: URL đã lưu **không được mã hoá** → lộ thông tin cá nhân, giúp phishing có chủ đích; dùng PBKDF2 với số vòng thấp ở tài khoản cũ → kẻ trộm crack được master password, gây ra nhiều vụ mất tiền crypto đến 2025 |

### Bài học áp dụng cho dự án
1. **Mã hoá TẤT CẢ** — kể cả tên mục, URL, username, ghi chú, tag (bài học LastPass).
2. **KDF hiện đại, chậm, tốn bộ nhớ**: Argon2id, tham số cao hơn mức tối thiểu OWASP (19 MiB/t=2/p=1).
3. **Định dạng file mở, có tài liệu** (như KDBX) → dễ audit, dễ backup, không bị khoá vào phần mềm.
4. **Local-first** trước, đồng bộ sau (như KeePassXC) → giảm bề mặt tấn công ở giai đoạn đầu.
5. Khi làm đồng bộ cloud: thêm **Secret Key** kiểu 1Password để dữ liệu trên server vô dụng nếu bị trộm.
6. **Không tự viết thuật toán mã hoá** — chỉ dùng thư viện đã được kiểm định.

---

## 2. Phạm vi sản phẩm

### MVP (bản dùng được đầu tiên)
- Tạo kho mới với master password; mở khoá / khoá kho.
- **Tự khoá** sau N phút không dùng và ngay khi máy vừa ngủ dậy. (Khoá TRƯỚC khi máy ngủ / khi khoá màn hình Windows: chưa làm — xem mục 9.)
- Thêm / sửa / xoá / tìm kiếm mục: tiêu đề, username, mật khẩu, URL, ghi chú, tag, mục yêu thích.
- **Bộ tạo mật khẩu**:
  - Ngẫu nhiên: độ dài 8–128, chọn nhóm ký tự (hoa, thường, số, ký hiệu), loại ký tự dễ nhầm (`0 O l 1 I`).
  - **Passphrase** kiểu Diceware (danh sách từ EFF 7.776 từ, ~12,9 bit/từ), ví dụ `ngựa-pin-kẹp-đúng-7`.
  - Hiển thị **entropy (bit)** và độ mạnh ước tính (zxcvbn).
- Sao chép vào clipboard và **tự xoá clipboard sau 20–30 giây**.
- Lịch sử mật khẩu của từng mục (để khôi phục khi đổi nhầm).
- Sao lưu tự động có phiên bản (theo ngày/tháng), thùng rác, khôi phục từng mục ngay trong app.

### Bản 1.x
- **Kiểm tra sức khoẻ mật khẩu**: yếu, trùng lặp, cũ; kiểm tra rò rỉ qua **Have I Been Pwned** bằng k-anonymity (chỉ gửi 5 ký tự đầu của SHA-1, không gửi mật khẩu).
- **TOTP** (mã 2FA 6 số) lưu trong kho.
- Import từ CSV của Chrome / Bitwarden / KeePass; export CSV (có cảnh báo).
- Mở khoá bằng sinh trắc học (Windows Hello / Touch ID) qua keychain của hệ điều hành.
- File đính kèm mã hoá (ảnh CCCD, mã khôi phục…).

### Bản 2.x (khi phần lõi đã ổn định & được review)
- Tiện ích trình duyệt (autofill) qua *native messaging*.
- Đồng bộ: (a) qua thư mục do người dùng chọn (Google Drive/Dropbox/Syncthing) — đơn giản, an toàn; hoặc (b) server zero-knowledge riêng + Secret Key + SRP/OPAQUE.
- App di động, passkey (WebAuthn), chia sẻ kho cho gia đình, “Emergency Kit” in ra giấy.

### Ngoài phạm vi (nói rõ để không hứa quá)
- Không chống được **mã độc/keylogger** đang chạy trên máy khi kho đang mở khoá — không password manager nào chống được hoàn toàn.
- **Quên master password = mất dữ liệu** (đó là cái giá của zero-knowledge). Giải pháp: Emergency Kit / recovery key in ra giấy.

---

## 3. Mô hình mối đe doạ (Threat model)

| Kịch bản | Có chống được? | Cách chống |
|---|---|---|
| Kẻ trộm lấy được file kho (từ ổ cứng, cloud, backup) | ✅ | AEAD + Argon2id; brute-force phải tốn rất nhiều RAM/CPU cho mỗi lần thử |
| Mất laptop khi kho đang khoá | ✅ | Như trên; khoá ở trạng thái nghỉ |
| Mất laptop khi kho đang mở | ⚠️ một phần | Tự khoá theo thời gian / khi khoá màn hình |
| Ai đó sửa/hoán đổi file kho | ✅ | Mã hoá có xác thực (AEAD) + header được xác thực → phát hiện ngay |
| Rò rỉ qua clipboard | ⚠️ một phần | Tự xoá clipboard, đánh dấu “sensitive” để clipboard history của OS bỏ qua |
| Nhìn trộm màn hình | ⚠️ một phần | Ẩn mật khẩu mặc định, chặn chụp màn hình (nơi OS hỗ trợ) |
| Mã độc trên máy đang mở kho | ❌ | Ngoài phạm vi |

---

## 4. Thiết kế mật mã (phần quan trọng nhất)

```
master password ──┐
salt (16 byte ngẫu nhiên) ──► Argon2id (m=256 MiB, t=3, p=4 — hiệu chỉnh ~0,5–1 giây)
                               │
                               ▼
                       Master Key (32 byte)
                               │ HKDF-SHA256
                               ▼
                 Key Encryption Key (KEK, 32 byte)
                               │ mở gói (unwrap)
                               ▼
         Vault Key (32 byte, NGẪU NHIÊN, sinh 1 lần khi tạo kho)
                               │
                               ▼
    Mỗi mục được mã hoá riêng bằng XChaCha20-Poly1305
    (nonce 24 byte ngẫu nhiên, AAD = id mục + phiên bản định dạng)
```

Lý do thiết kế:
- **Vault Key ngẫu nhiên, được “gói” bởi KEK**: đổi master password chỉ cần gói lại 32 byte, không phải mã hoá lại toàn bộ kho; sau này dễ thêm cách mở khoá khác (sinh trắc học, recovery key) — mỗi cách là một “gói” riêng.
- **XChaCha20-Poly1305**: AEAD (vừa mã hoá vừa chống sửa đổi), nonce 24 byte đủ lớn để sinh ngẫu nhiên không lo trùng, nhanh trên mọi CPU. (AES-256-GCM cũng chấp nhận được.)
- **Argon2id**: chống tấn công bằng GPU/ASIC; tham số lưu trong header để sau này tăng dần mà vẫn mở được kho cũ.
- **Header (version, tham số KDF, salt) là AAD** → không ai hạ cấp tham số KDF được.
- **Bảo vệ bộ nhớ**: xoá khoá khỏi RAM khi khoá kho (`zeroize`), không ghi log dữ liệu nhạy cảm, không để khoá vào swap nếu được (`mlock`).
- **Nguồn ngẫu nhiên**: chỉ dùng CSPRNG của hệ điều hành (`getrandom`/`OsRng`). Khi tạo mật khẩu dùng **rejection sampling** để tránh *modulo bias* (không dùng `random() % n`).

### Định dạng file kho (`.vault`) — dự kiến
```
magic      "PWV1"            4 byte
version    u16
kdf        { alg: argon2id, m_kib, t, p, salt[16] }
wrapped_vault_key { nonce[24], ciphertext[32+16] }   // gói bởi KEK
body       { nonce[24], ciphertext(JSON/CBOR toàn bộ các mục) }
```
- Ghi file **nguyên tử**: ghi ra file tạm → `fsync` → `rename` (không bao giờ hỏng kho khi mất điện).
- Giữ N bản sao lưu gần nhất (`.vault.bak1..N`).
- Viết tài liệu đặc tả định dạng trong `docs/FORMAT.md` + test vectors.

### Mô hình dữ liệu một mục (trước khi mã hoá)
```json
{
  "id": "uuid-v4",
  "type": "login",
  "title": "Vietcombank",
  "username": "...",
  "password": "...",
  "urls": ["https://vcbdigibank.vietcombank.com.vn"],
  "notes": "...",
  "totp": "otpauth://...",
  "tags": ["ngân hàng"],
  "favorite": true,
  "password_history": [{ "value": "...", "changed_at": "..." }],
  "created_at": "...",
  "updated_at": "..."
}
```

---

## 5. Công nghệ đề xuất

**Khuyến nghị: Rust (lõi) + Tauri 2 (ứng dụng desktop) + React/TypeScript (giao diện).**

| Thành phần | Lựa chọn | Lý do |
|---|---|---|
| Lõi mật mã & kho | **Rust** | An toàn bộ nhớ, crate mật mã chất lượng; lõi dùng lại được cho CLI, desktop, mobile |
| Thư viện mã hoá | `argon2`, `chacha20poly1305`, `hkdf`, `sha2` (RustCrypto), `zeroize`, `secrecy`, `rand`/`getrandom` | Đã được dùng rộng rãi; một số đã audit |
| Ứng dụng desktop | **Tauri 2** | Nhẹ hơn Electron nhiều, Windows/macOS/Linux, sau này có iOS/Android; khoá giải mã chỉ nằm phía Rust, không lộ sang JavaScript |
| Giao diện | React + TypeScript + Tailwind | Phổ biến, dễ tìm tài liệu |
| Ước tính độ mạnh | `zxcvbn` (bản Rust) | Chuẩn de-facto |
| Kiểm thử | `cargo test`, `proptest`, `cargo-fuzz` (fuzz bộ đọc file), Playwright (UI) | |
| Bảo mật chuỗi cung ứng | `cargo audit`, `cargo deny`, Dependabot, ký bản phát hành | |

*Phương án đơn giản hơn nếu muốn học/làm nhanh:* Python + `cryptography` + `argon2-cffi` cho bản CLI, rồi giao diện bằng PySide6. Dễ hơn nhưng khó kiểm soát bộ nhớ (không xoá được chuỗi khỏi RAM) và đóng gói kém gọn hơn.

### Cấu trúc thư mục dự kiến
```
password/
├── PLAN.md
├── docs/
│   ├── FORMAT.md          # đặc tả định dạng file kho
│   └── THREAT_MODEL.md
├── crates/
│   ├── vault-core/        # mật mã, định dạng file, mô hình dữ liệu (không phụ thuộc UI)
│   ├── generator/         # tạo mật khẩu & passphrase, tính entropy
│   └── cli/               # công cụ dòng lệnh `pwv` (dùng để test lõi sớm)
└── app/                   # Tauri 2 + React
    ├── src-tauri/         # lệnh Tauri gọi vào vault-core
    └── src/               # giao diện
```

---

## 6. Lộ trình (ước tính cho 1 người, bán thời gian)

| Giai đoạn | Thời gian | Kết quả | Tiêu chí hoàn thành |
|---|---|---|---|
| **0. Chuẩn bị** | 2–3 ngày | Repo, CI (build + test + `cargo audit`), `THREAT_MODEL.md`, `FORMAT.md` bản nháp | CI xanh |
| **1. Bộ tạo mật khẩu** | 1 tuần | Crate `generator`: ngẫu nhiên, passphrase EFF, entropy | Test thống kê phân bố đều; không modulo bias |
| **2. Lõi kho** | 2–3 tuần | Crate `vault-core`: tạo/mở/lưu kho, Argon2id, XChaCha20-Poly1305, gói khoá, ghi nguyên tử, backup | Test: sai mật khẩu → lỗi; sửa 1 byte file → lỗi; đổi master password giữ nguyên dữ liệu; fuzz bộ đọc 1 giờ không crash |
| **3. CLI** | 1 tuần | `pwv init / add / get / list / gen / passwd` | Dùng được thật hằng ngày ở dạng dòng lệnh |
| **4. App desktop (MVP)** | 3–4 tuần | Tauri: màn hình mở khoá, danh sách, chi tiết, tìm kiếm, bộ tạo, clipboard tự xoá, tự khoá | Chạy trên Windows + macOS/Linux; checklist MVP ở mục 2 hoàn tất |
| **5. Sức khoẻ & tiện ích** | 2 tuần | HIBP k-anonymity, mật khẩu trùng/yếu, TOTP, import CSV | |
| **6. Gia cố & review** | liên tục, ≥ 2 tuần | Rà soát mã, fuzzing, kiểm tra rò rỉ bộ nhớ/log, đóng gói & ký bản phát hành | Có review độc lập phần mật mã trước khi dùng cho tài khoản thật |
| **7. Mở rộng** | sau | Tiện ích trình duyệt, đồng bộ, mobile, passkey | |

➡ **Khoảng 3 tháng** để có bản desktop MVP dùng được.

---

## 7. Checklist bảo mật bắt buộc trước khi dùng cho tài khoản thật
Trạng thái tại bản 0.2.0 (sau đợt rà soát ở mục 9):
- [x] Không có thuật toán mật mã tự viết; chỉ dùng thư viện đã kiểm định (RustCrypto).
- [x] Toàn bộ metadata được mã hoá; file kho không chứa chuỗi đọc được nào ngoài header (có test).
- [x] Tham số Argon2id ≥ 64 MiB, kiểm tra cả khi mở; header được xác thực (AAD).
- [x] Khoá và các mục được `zeroize` khi khoá kho; kiểu dữ liệu chứa bí mật không in ra log/Debug (có test).
      *Giới hạn:* bản sao tạm trong bộ nhớ của WebView và của thư viện không xoá được — xem README.
- [x] Clipboard tự xoá (kể cả khi đóng/khoá app); tự khoá khi rảnh và khi máy vừa ngủ dậy.
      *Chưa có:* khoá ngay khi khoá màn hình Windows / trước khi máy ngủ.
- [x] Ghi file nguyên tử + đọc lại kiểm tra + sao lưu trước và sau mỗi lần ghi; thao tác sửa là giao dịch có hoàn tác.
- [x] Fuzz bộ đọc file; file mẫu của bản 0.1.2 nằm trong repo và được test ở mỗi lần build; công cụ giải mã độc lập bằng Python được kiểm tra chéo trong CI.
- [x] `cargo audit` cho cả lõi lẫn app + `npm audit`, chạy hằng tuần.
- [ ] Bản phát hành được **ký số** (Authenticode cho Windows, khoá cố định cho APK) — chưa.
- [x] Người dùng được cảnh báo rõ "quên master password = mất dữ liệu"; chính sách master password chặn mật khẩu dễ đoán.
- [ ] Một **tổ chức/người độc lập** có chuyên môn review phần `vault-core` — chưa (mới có đợt rà soát nội bộ ở mục 9).
- [ ] Các bước kiểm tra trên thiết bị thật trong README (Windows + Android) — người dùng tự làm.

> ⚠️ **Khuyến nghị thực tế:** làm xong các bước kiểm tra trên thiết bị thật với một kho thử trước khi đưa tài khoản ngân hàng vào, và luôn giữ được đường lui (thư mục sao lưu + `tools/pwv_recover.py`).

---

## 8. Quyết định đã chốt (19/11/2026)
1. **Nền tảng**: Windows trước (Windows 10/11, 64-bit).
2. **Đồng bộ**: qua **Google Drive for Desktop** — file kho nằm trong thư mục Drive (ví dụ `G:\My Drive\Passwords\vault.pwv`). Drive chỉ thấy dữ liệu đã mã hoá.
   - Trước mỗi lần sửa, app kiểm tra file trên đĩa có bị máy khác thay đổi không (so SHA-256). Nếu có → tự **gộp (merge)** theo **từng trường** của từng mục (trường nào sửa sau thì thắng); xoá = vào thùng rác; xoá vĩnh viễn để lại "bia mộ" (tombstone). *(Bản 0.1.x gộp theo cả mục — đã thay ở 0.2.0.)*
   - Bản xung đột do dịch vụ đồng bộ tạo ra được nhận diện theo `vault_id`, tự gộp, rồi cất vào thư mục sao lưu.
   - Ghi file nguyên tử + thử lại khi Drive/antivirus đang khoá file; sao lưu theo tầng (10 bản gần nhất + theo ngày + theo tháng) trong `vault.pwv.backups/`.
   - Từ 0.1.1 hỗ trợ cả Dropbox và OneDrive; từ 0.1.2 có app Android chỉ đọc.
3. **Công nghệ**: Rust + Tauri 2 + React/TypeScript (theo đề xuất).
4. **Người dùng**: chỉ dùng cá nhân → không cần server, không cần chia sẻ, không phát hành công khai. Vẫn giữ checklist bảo mật ở mục 7.

### Điều chỉnh thiết kế so với bản nháp
- Toàn bộ phần thân kho (mọi mục) được mã hoá **một lần** bằng XChaCha20-Poly1305, có **đệm (padding) lên bội số 4 KiB** để không lộ số lượng mục qua kích thước file. Header là AAD. Chi tiết trong `docs/FORMAT.md`.

---

## 9. Đợt rà soát bảo mật 11/2026 và bản 0.2.0

Trước khi dùng cho tài khoản ngân hàng, toàn bộ mã nguồn bản 0.1.2 được rà soát theo 17 mảng (thiết kế
mật mã, mất dữ liệu khi đồng bộ, bí mật trong bộ nhớ, khoá phiên, ghi file, WebView, nhập CSV/TOTP/HIBP,
bộ tạo mật khẩu, Windows, Android, chuỗi cung ứng, …); mỗi phát hiện từ mức trung bình trở lên được một
người rà soát thứ hai kiểm chứng độc lập (đa số bằng thử nghiệm chạy thật).

**Không có lỗi làm lộ dữ liệu cho người chỉ có file kho.** Các lỗi đã sửa ở 0.2.0:

| Nhóm | Lỗi của 0.1.2 | Cách sửa |
|---|---|---|
| Mất dữ liệu | Chuyển kho vào chính thư mục sao lưu của nó ⇒ xoá sạch kho và sao lưu | Từ chối; không bao giờ xoá đệ quy |
| Mất dữ liệu | Máy chưa đồng bộ bấm ★/sửa ghi chú ⇒ đè mất mật khẩu mới của máy kia | Gộp theo từng trường; form chỉ gửi trường đã đổi; gộp trước khi sửa |
| Mất dữ liệu | Đồng bộ nền gộp vào RAM nhưng không ghi lại | Ghi lại khi bản đang mở có thứ file thiếu |
| Mất dữ liệu | File trên đĩa hỏng ⇒ mọi lần lưu lỗi "sai mật khẩu", thay đổi mất khi tự khoá | Giao dịch có hoàn tác; lỗi riêng từng loại; ghi đè có xác nhận; bản cứu hộ khi khoá |
| Mất dữ liệu | File biến mất ⇒ âm thầm tạo lại (kho bị tách đôi) | Báo lỗi, chờ người dùng chọn |
| Mất dữ liệu | Chỉ giữ 10 bản sao lưu gần nhất; không có thùng rác | Sao lưu theo ngày/tháng; thùng rác; khôi phục trong app |
| Mất dữ liệu | Nhập CSV bỏ các ghi chú bảo mật và tài khoản dùng chung mật khẩu vì coi là "trùng" | Chỉ bỏ dòng giống hệt mọi trường; không tự xoá CSV |
| Bảo mật | Đổi master password không đổi khoá kho | Sinh khoá mới, mã hoá lại kho và các bản sao lưu |
| Bảo mật | Chính sách master password để lọt "tên + năm sinh" | Ngưỡng 10^14 lần đoán |
| Bảo mật | Clipboard không được xoá nếu đóng app trong 20 giây | Xoá khi đóng/khoá; Ctrl+C ở CLI cũng xoá |
| Bảo mật | Kiểm tra rò rỉ treo app vô hạn khi mạng treo; trang chặn mạng bị hiểu là "an toàn" | Giới hạn thời gian, gọi mạng ngoài khoá phiên, kiểm tra dạng phản hồi |
| Bảo mật | Android: mật khẩu hiện trong khung xem trước clipboard, cho chụp màn hình, dữ liệu app vào Google backup | `write_secret`, `FLAG_SECURE`, tắt sao lưu và tự điền |
| Khác | Mật khẩu có dấu gõ bằng bàn phím khác bị báo sai; tham số Argon2 không được kiểm tra khi mở; … | Xem lịch sử commit |

**Còn để ngỏ (đã ghi rõ trong README):**
- Bộ cài Windows chưa ký số; APK cần khoá ký cố định (người dùng phải tạo một lần).
- Khoá kho ngay khi khoá màn hình Windows / trước khi máy ngủ (hiện chỉ khoá khi máy vừa thức dậy).
- Bí mật còn sót trong bộ nhớ tiến trình cho tới khi app thoát ⇒ cần mã hoá ổ đĩa.
- Các action của GitHub chưa được ghim theo mã commit.
- Chưa có kiểm định của bên thứ ba.

### 9.1. Lượt rà soát thứ hai (11/2026, trước khi phát hành 0.2.0)

Lượt này nhắm vào những gì lượt đầu chưa đặt câu hỏi: **người biết một master password CŨ** (và có
quyền ghi vào thư mục đồng bộ) làm được gì sau khi chủ kho đã đổi mật khẩu; máy sai giờ; ghi file bị
phần mềm khác giữ; và các đường "cứu hộ" (khôi phục từ sao lưu, bản cứu hộ). Đặc tả mới nằm ở
[docs/FORMAT.md](docs/FORMAT.md) mục 3, 5, 6, 7.

| Nhóm | Vấn đề tìm thấy | Cách sửa |
|---|---|---|
| Lõi | Nội dung chỉ mở được bằng khoá CŨ (bản cạnh kho, file kho bị thay, bản sao lưu) vẫn được tự gộp ⇒ người biết mật khẩu cũ ghi được vào kho sau khi chủ kho đã đổi mật khẩu | Khoá cũ chỉ để ĐỌC: bản như vậy không bao giờ được tự gộp; nó được mã hoá lại bằng khoá hiện tại và cất vào thư mục sao lưu (`oldkey-…`) để chủ kho tự xem; app báo, đánh dấu "ghi bằng mật khẩu cũ" và đòi xác nhận trước khi khôi phục mục nào từ đó |
| Lõi | Một bản cạnh kho ghi "đã đổi mật khẩu" (header chưa xác thực) làm app dừng đồng bộ / khoá chủ kho ra ngoài | Chỉ file kho CHÍNH mới khoá được app; bản cạnh kho không mở được chỉ bị báo ("dùng mật khẩu chính khác") và để nguyên |
| Lõi | Hai máy cùng đổi sang một mật khẩu mới khi chưa đồng bộ ⇒ hai nhánh không bao giờ nối lại | Lúc mở khoá thử mật khẩu trên tối đa 2 bản cạnh kho mới hơn; hai khoá đều được mật khẩu xác thực ⇒ gộp. (Chỉ nối được theo một chiều — xem "còn để ngỏ") |
| Lõi | Khôi phục từ sao lưu bằng mật khẩu CŨ âm thầm đưa kho về mật khẩu cũ và mất mọi thay đổi sau đó; vài chục file rác làm hỏng việc khôi phục; bản sao lưu cài sẵn bằng khoá cũ được mã hoá lại thành "bản tin cậy" | Mật khẩu cũ ⇒ lỗi riêng, chỉ khôi phục từ các bản cũ khi chủ kho chọn rõ ràng; giới hạn tính theo số bản GỘP ĐƯỢC; chỉ gộp bản dùng đúng khoá gốc; không bao giờ mã hoá lại bản chỉ mở được bằng khoá cũ hơn; "không có bản nào dùng được" là lỗi riêng kèm chỉ dẫn nơi khác để tìm |
| Lõi | Ghi xong nhưng đọc lại lỗi (diệt virus / đồng bộ giữ file) ⇒ hoàn tác RAM; với đổi mật khẩu thì RAM ở khoá cũ còn đĩa ở khoá mới | "Đã ghi, chưa xác minh": giữ RAM, báo người dùng, lần đồng bộ sau đọc lại thật |
| Lõi | Quy tắc giữ bản sao lưu theo đồng hồ của máy đang dọn ⇒ một máy sai giờ xoá lịch sử trên mọi máy | Chỉ dựa vào thời điểm trong tên file: 10 bản mới nhất + bản cuối của 30 ngày gần nhất CÓ sao lưu + bản cuối của 12 kỳ 30 ngày gần nhất CÓ sao lưu |
| Lõi | Nhập lại cùng file CSV trên một máy chưa đồng bộ đè lên thay đổi thật của máy khác | Mục nhập mang thời điểm cố định 1 ms: luôn thua mọi lần sửa thật (giao diện hiện "—" cho thời điểm này) |
| Lõi | Phép gộp mất tính kết hợp khi lịch sử mật khẩu chạm trần 20 dòng ⇒ các máy có thể ghi đè qua lại | Dạng chuẩn mới của lịch sử; property test ≥ 20 000 ca mỗi tính chất, lịch sử tới 26 dòng |
| Lõi | Nhiều khoá dùng chung một trang RAM bị khoá ⇒ mở khoá trang khi giải phóng một khoá làm lộ khoá kia ra pagefile | Mỗi khoá một trang riêng |
| Lõi | Chuyển kho / ghi đè file hỏng có thể xoá file cũ khi máy khác vừa ghi vào giữa chừng, hoặc ghi thẳng vào tên cuối | Chỉ xoá file cũ khi nó vẫn đúng là bản đã đồng bộ; chép bản trong RAM vào thư mục sao lưu trước khi tạo lại file; đọc lại kiểm tra |
| Lõi | Gõ mật khẩu cũ trên một máy đã từng mở kho thật, khi file kho đã bị thay bằng file do người biết mật khẩu cũ làm ra ⇒ mở ra kho giả mà không cảnh báo | Mỗi máy nhớ một "dấu khoá" của khoá kho dùng lần trước; kho không biết khoá đó ⇒ cảnh báo mạnh ("không nối tiếp từ kho máy này dùng lần trước", nút chính là *Khoá lại*) |
| App | Dọn thùng rác xoá cả mục mà máy khác vừa chuyển vào sau khi chủ kho xem danh sách | Gửi đúng danh sách đã thấy; chỉ xoá các mục đó; báo số mục còn lại |
| App | Sau một lần đồng bộ sạch, MỌI bản cứu hộ bị xoá — kể cả bản không gộp được (bản duy nhất còn giữ dữ liệu chưa lưu) | Chỉ xoá bản đã gộp; bản còn lại được giữ, báo cho chủ kho và thử lại ở lần mở khoá sau |
| App | App đang mở ghi đè thay đổi config.json do CLI làm (vị trí kho, cài đặt, mốc "đã thấy") | Mỗi lần ghi: đọc lại file → áp đúng một thay đổi → ghi; mốc "đã thấy" chỉ ghi khi thật sự đổi |
| App | Bản phát hành `panic = "abort"`: một panic giết tiến trình trước khi kịp xoá clipboard | Panic hook cố xoá clipboard (chỉ khi nó vẫn giữ đúng bí mật app đã chép, không chờ khoá) rồi mới thoát |
| App | Đổi master password không đồng bộ trước ⇒ bản xung đột còn dùng khoá hiện tại trở thành "bản khoá cũ" | Đồng bộ đầy đủ trước khi đổi; lỗi ⇒ chưa đổi gì, giao diện nói rõ "CHƯA được đổi" |
| CLI | Ghi chú dán nhiều dòng bị cắt / lẫn vào lệnh sau; thao tác xoá vĩnh viễn, ghi đè, khôi phục từ bản cũ chưa hỏi xác nhận; cảnh báo "file cũ hơn" không có cách xác nhận; dọn thùng rác cùng lỗi như app | Sửa trong `crates/cli` song song với lượt này (xem commit tương ứng) |
| Phát hành | Khoá ký APK dùng chung job với mã build; bản phát hành có thể ra từ commit chưa qua CI; công cụ cứu hộ ghi sai dấu tiếng Việt trên Windows khi chuyển hướng đầu ra | Ký trong job riêng không chạy mã build; Release từ chối nếu CI của commit chưa xanh; `pwv_recover.py -o FILE` ghi UTF-8 và CI chạy đúng lệnh trong README |

**Vẫn chưa che được (đã ghi trong README, mục "Giới hạn", và FORMAT.md mục 7):**
- Bản sao đã rời khỏi máy (lịch sử phiên bản / thùng rác của dịch vụ đồng bộ, điện thoại, máy chưa đồng
  bộ) vẫn mở được bằng mật khẩu của thời điểm đó; đổi mật khẩu không thu hồi được chúng.
- Thư mục sao lưu nằm trong thư mục đồng bộ: kẻ có quyền ghi xoá được các bản sao lưu, đặt được bản
  "tương lai" để quy tắc giữ lại đẩy bản thật ra, hoặc đặt bản làm bằng khoá cũ (không bao giờ được tự
  gộp nhưng vẫn hiện trong danh sách khôi phục, có nhãn). Tên và header của file sao lưu chưa được xác thực.
- Hai lần đổi mật khẩu trên hai máy chưa đồng bộ chỉ nối lại được khi file kho chính là nhánh đổi
  trước; đổi sang hai mật khẩu khác nhau thì không bao giờ tự nối.
- Máy mới cài (và điện thoại — đường chỉ đọc không tính "dấu khoá") không phát hiện được kho giả làm
  bằng mật khẩu cũ. Quy tắc cho chủ kho: sau khi đổi master password, không bao giờ gõ lại mật khẩu cũ.
- Header của bản cạnh kho có thể làm mỗi lần mở khoá tốn thêm tối đa 2 lượt Argon2.
- Panic hook không che được tiến trình chết ngoài panic của Rust (WebView sập, bị diệt, mất điện).
- Ghi "chưa xác minh" mới chỉ được kiểm bằng test của lõi; chưa có test giả lập được tình huống này ở
  tầng app.
- Mọi điểm "còn để ngỏ" của lượt đầu (ký số, khoá khi khoá màn hình, ghim action theo commit, kiểm
  định độc lập) vẫn còn nguyên.

## Nguồn tham khảo
- Bitwarden Security Whitepaper — https://bitwarden.com/help/bitwarden-security-white-paper/
- 1Password Security Design — https://agilebits.github.io/security-design/1Password_Security_Design.pdf
- 1Password: How we use SRP — https://1password.com/blog/developers-how-we-use-srp-and-you-can-too
- KeePass KDBX 4 — https://keepass.info/help/kb/kdbx_4.html
- Proton: Lessons from LastPass — https://proton.me/blog/lessons-from-lastpass
- OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Have I Been Pwned API v3 (Pwned Passwords range) — https://haveibeenpwned.com/API/v3
- So sánh password manager 2026 — https://simeononsecurity.com/articles/bitwarden-and-keepassxc-vs-the-rest/ , https://ghost.thenewoil.org/the-best-password-managers-in-2026/
