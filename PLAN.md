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
- **Tự khoá** sau N phút không dùng, khi máy sleep/lock màn hình.
- Thêm / sửa / xoá / tìm kiếm mục: tiêu đề, username, mật khẩu, URL, ghi chú, tag, mục yêu thích.
- **Bộ tạo mật khẩu**:
  - Ngẫu nhiên: độ dài 8–128, chọn nhóm ký tự (hoa, thường, số, ký hiệu), loại ký tự dễ nhầm (`0 O l 1 I`).
  - **Passphrase** kiểu Diceware (danh sách từ EFF 7.776 từ, ~12,9 bit/từ), ví dụ `ngựa-pin-kẹp-đúng-7`.
  - Hiển thị **entropy (bit)** và độ mạnh ước tính (zxcvbn).
- Sao chép vào clipboard và **tự xoá clipboard sau 20–30 giây**.
- Lịch sử mật khẩu của từng mục (để khôi phục khi đổi nhầm).
- Sao lưu tự động có phiên bản; xuất file mã hoá.

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
- [ ] Không có thuật toán mật mã tự viết; chỉ dùng thư viện đã kiểm định.
- [ ] Toàn bộ metadata được mã hoá; file kho không chứa chuỗi đọc được nào ngoài header.
- [ ] Tham số Argon2id ≥ 64 MiB; header được xác thực (AAD).
- [ ] Khoá được `zeroize` khi khoá kho; không log dữ liệu nhạy cảm (có test kiểm tra).
- [ ] Clipboard tự xoá; tự khoá khi rảnh / khoá màn hình.
- [ ] Ghi file nguyên tử + backup; đã thử rút điện/kill tiến trình giữa lúc lưu.
- [ ] Fuzz bộ đọc file; test vectors cố định cho định dạng.
- [ ] `cargo audit` sạch; bản phát hành được ký.
- [ ] Có Emergency Kit / recovery key; người dùng được cảnh báo rõ “quên master password = mất dữ liệu”.
- [ ] Một người có chuyên môn bảo mật đã review phần `vault-core`.

> ⚠️ **Khuyến nghị thực tế:** trong lúc phát triển, **tiếp tục dùng song song** một phần mềm đã được audit (Bitwarden hoặc KeePassXC) cho các tài khoản quan trọng, và luôn giữ bản export dự phòng. Chỉ chuyển hẳn sang phần mềm tự làm khi đã qua checklist trên.

---

## 8. Quyết định đã chốt (19/11/2026)
1. **Nền tảng**: Windows trước (Windows 10/11, 64-bit).
2. **Đồng bộ**: qua **Google Drive for Desktop** — file kho nằm trong thư mục Drive (ví dụ `G:\My Drive\Passwords\vault.pwv`). Drive chỉ thấy dữ liệu đã mã hoá.
   - Trước khi lưu, app kiểm tra file trên đĩa có bị máy khác thay đổi không (so SHA-256 lúc mở). Nếu có → tự **gộp (merge)** theo từng mục: bản nào `updated_at` mới hơn thì thắng, mục đã xoá được ghi “bia mộ” (tombstone) để không sống lại.
   - Nếu Drive tạo bản xung đột (`vault (1).pwv`), lệnh `pwv merge` / nút trong app sẽ gộp vào kho chính.
   - Ghi file nguyên tử + thử lại khi Drive/antivirus đang khoá file; giữ 10 bản sao lưu trong thư mục `vault.pwv.backups/`.
3. **Công nghệ**: Rust + Tauri 2 + React/TypeScript (theo đề xuất).
4. **Người dùng**: chỉ dùng cá nhân → không cần server, không cần chia sẻ, không phát hành công khai. Vẫn giữ checklist bảo mật ở mục 7.

### Điều chỉnh thiết kế so với bản nháp
- Toàn bộ phần thân kho (mọi mục) được mã hoá **một lần** bằng XChaCha20-Poly1305, có **đệm (padding) lên bội số 4 KiB** để không lộ số lượng mục qua kích thước file. Header là AAD. Chi tiết trong `docs/FORMAT.md`.

## Nguồn tham khảo
- Bitwarden Security Whitepaper — https://bitwarden.com/help/bitwarden-security-white-paper/
- 1Password Security Design — https://agilebits.github.io/security-design/1Password_Security_Design.pdf
- 1Password: How we use SRP — https://1password.com/blog/developers-how-we-use-srp-and-you-can-too
- KeePass KDBX 4 — https://keepass.info/help/kb/kdbx_4.html
- Proton: Lessons from LastPass — https://proton.me/blog/lessons-from-lastpass
- OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Have I Been Pwned API v3 (Pwned Passwords range) — https://haveibeenpwned.com/API/v3
- So sánh password manager 2026 — https://simeononsecurity.com/articles/bitwarden-and-keepassxc-vs-the-rest/ , https://ghost.thenewoil.org/the-best-password-managers-in-2026/
