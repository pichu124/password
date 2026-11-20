# pwv — Kho mật khẩu cá nhân

Phần mềm tạo mật khẩu mạnh và lưu chúng trong một file được mã hoá, đồng bộ giữa các máy
Windows qua Google Drive. Chỉ người biết **master password** mới mở được.

- Mã hoá: **Argon2id** (256 MiB) → HKDF-SHA256 → **XChaCha20-Poly1305**. Mọi thứ đều được
  mã hoá, kể cả tên trang web và username.
- Đồng bộ: đặt file `vault.pwv` trong thư mục Google Drive. App tự gộp khi hai máy cùng sửa.
- Có công cụ cứu hộ độc lập (`tools/pwv_recover.py`) để lấy lại dữ liệu nếu app gặp sự cố.

Kế hoạch tổng thể: [PLAN.md](PLAN.md) · Đặc tả file: [docs/FORMAT.md](docs/FORMAT.md)

## Trạng thái

| Giai đoạn | Trạng thái |
|---|---|
| 0. Chuẩn bị, CI Windows | ✅ |
| 1. Bộ tạo mật khẩu / passphrase | ✅ |
| 2. Lõi kho (mã hoá, đồng bộ, sao lưu) | ✅ |
| 3. CLI `pwv.exe` | ✅ |
| 3b. Mã 2FA (TOTP), kiểm tra sức khoẻ + HIBP, import CSV | ✅ |
| 4. App giao diện Windows (Tauri) — bộ cài `.exe` / `.msi` | ✅ |
| 6. Gia cố: fuzz test, khoá RAM chứa khoá giải mã | ✅ |

## Cài đặt trên Windows

### App có giao diện (khuyên dùng)
Vào tab *Actions* của repo → lần chạy mới nhất có dấu ✓ → tải artifact **`pwv-app-windows-installer`**
→ giải nén → chạy `pwv_x.y.z_x64-setup.exe` (cài cho riêng tài khoản của bạn, không cần quyền admin).

Windows có thể hiện cảnh báo SmartScreen vì bộ cài chưa được ký số: bấm **More info → Run anyway**.

Tính năng của app:
- Tạo kho mới (tự gợi ý thư mục Google Drive) hoặc mở kho có sẵn từ máy khác.
- Danh sách + tìm kiếm (Ctrl+F), thêm (Ctrl+N), khoá (Ctrl+L), yêu thích, nhóm/tag.
- Bộ tạo mật khẩu / cụm từ, thanh độ mạnh, lịch sử mật khẩu cũ.
- Mã 2FA (TOTP) đếm ngược theo thời gian thực.
- Kiểm tra sức khoẻ mật khẩu + rò rỉ (Have I Been Pwned), nhập CSV từ Chrome/Bitwarden/KeePass.
- Tự khoá khi không dùng (mặc định 5 phút), tự xoá clipboard (20 giây), tự đồng bộ với Google Drive mỗi 20 giây.
- Bảo mật: mật khẩu được sao chép trực tiếp từ Rust, không đi qua phần giao diện web; cửa sổ chặn chụp/chia sẻ
  màn hình; chỉ cho chạy một cửa sổ app để tránh hai tiến trình cùng ghi file.

### Công cụ dòng lệnh `pwv.exe`

**Tải bản build sẵn:** vào tab *Actions* của repo → lần chạy mới nhất →
tải artifact `pwv-windows` → giải nén `pwv.exe` vào một thư mục, ví dụ `C:\Tools\`.

**Tự build:**
1. Cài Rust: <https://rustup.rs> (chọn mặc định, cần “Visual Studio C++ Build Tools”).
2. Trong PowerShell:
   ```powershell
   git clone https://github.com/pichu124/password
   cd password
   cargo build --release
   # file chạy: target\release\pwv.exe
   ```

## Sử dụng nhanh

```powershell
pwv init                       # tạo kho; tự gợi ý đặt trong G:\My Drive\Passwords\vault.pwv
pwv gen -p -w 6                # tạo passphrase 6 từ (dùng làm master password rất tốt)
pwv add "Vietcombank" -u nguyenvana --url https://vcbdigibank.vietcombank.com.vn -g -l 24
pwv add "Gmail" -u toi@gmail.com       # tự nhập mật khẩu (để trống = tự tạo)
pwv list                       # liệt kê
pwv list ngân                  # tìm kiếm
pwv copy gmail                 # chép mật khẩu, tự xoá clipboard sau 20 giây
pwv show gmail --reveal        # xem chi tiết
pwv edit gmail -g              # đổi sang mật khẩu ngẫu nhiên mới (mật khẩu cũ vào lịch sử)
pwv delete gmail
pwv passwd                     # đổi master password
pwv sync                       # nạp thay đổi từ máy khác + gộp bản xung đột của Drive
pwv totp google -c             # mã 2FA 6 số (lưu secret bằng --totp khi add/edit)
pwv health                     # mật khẩu yếu / dùng trùng / lâu chưa đổi / đã bị lộ (HIBP)
pwv import chrome.csv --delete-csv   # nhập từ Chrome, Edge, Firefox, Bitwarden, KeePass...
```

### Chuyển mật khẩu từ trình duyệt sang
- **Chrome/Edge**: Cài đặt → Mật khẩu (Password Manager) → Xuất mật khẩu → lưu `.csv`.
- **Bitwarden**: Tools → Export vault → định dạng `.csv`.
- **KeePassXC**: Database → Export → CSV.

Sau đó chạy `pwv import <file.csv> --delete-csv`, rồi **xoá mật khẩu trong trình duyệt** để không còn
lưu ở hai nơi, và dọn Thùng rác.

Trên Windows, mật khẩu khi copy sẽ **không** lưu vào lịch sử clipboard (Win+V) và không đồng bộ
lên cloud clipboard.

## Đồng bộ qua Google Drive / Dropbox / OneDrive

1. Cài **Google Drive for Desktop** trên mỗi máy.
2. Máy đầu tiên: `pwv init` và chọn vị trí trong thư mục Drive (ví dụ `G:\My Drive\Passwords\vault.pwv`).
3. Máy thứ hai: đợi Drive tải file về rồi chạy `pwv config "G:\My Drive\Passwords\vault.pwv"`.
4. Nếu Drive tạo file `vault (1).pwv` vì hai máy sửa cùng lúc, chạy `pwv sync` để gộp.

Nên bật chế độ **“Mirror files”** (lưu bản sao trên máy) cho thư mục chứa kho để vẫn dùng được khi mất mạng.


**Dropbox / OneDrive** dùng y hệt: đặt `vault.pwv` trong thư mục `Dropbox` hoặc `OneDrive` thay cho thư mục Drive.
App tự nhận ra bản xung đột của cả ba dịch vụ (`vault (1).pwv`, `vault (… conflicted copy …).pwv`,
`vault-TÊN-MÁY.pwv`) và gộp lại. Với Dropbox, bấm chuột phải thư mục chứa kho → **Make available offline**;
với OneDrive chọn **Always keep on this device**.

## Cứu hộ dữ liệu

```powershell
pip install pynacl argon2-cffi
python tools\pwv_recover.py "G:\My Drive\Passwords\vault.pwv" > backup.json
```
⚠ `backup.json` chứa toàn bộ mật khẩu ở dạng rõ — xoá ngay sau khi dùng.
Các bản sao lưu tự động nằm trong `vault.pwv.backups\` (10 bản gần nhất).

## Lưu ý an toàn

- **Quên master password = mất dữ liệu.** Viết master password ra giấy và cất ở nơi an toàn.
- Phần mềm chưa được kiểm định bảo mật độc lập. Trong thời gian đầu hãy giữ song song một
  password manager đã được audit (Bitwarden/KeePassXC) cho các tài khoản quan trọng nhất.
- Không chống được mã độc/keylogger đang chạy trên máy khi bạn mở kho.

## Phát hành bản mới

1. Nâng phiên bản (cập nhật cả 4 file cấu hình cùng lúc):
   ```bash
   python tools/set_version.py 0.1.3
   ```
2. Commit và push.
3. Vào tab **Actions → Release → Run workflow**. Workflow chạy test, build bộ cài + `pwv-cli.exe`,
   rồi tạo bản phát hành `v0.1.3` trên GitHub Releases kèm `SHA256SUMS.txt`.
4. App đang cài trên các máy sẽ tự hiện thông báo “Có phiên bản mới” trong vòng 24 giờ
   (hoặc vào **Cài đặt → Kiểm tra ngay**).

## Phát triển

```bash
cargo test --workspace                          # lõi + CLI
cargo clippy --workspace --all-targets -- -D warnings
cd app && npm ci && npm run build               # giao diện
cd src-tauri && cargo test                      # backend của app
cd .. && npx tauri dev                          # chạy app ở chế độ phát triển
npx vite --mode mock                            # xem giao diện trong trình duyệt với dữ liệu giả
                                                # (mật khẩu demo: demo-demo-demo-demo)
```

Cấu trúc:
```
crates/generator   tạo mật khẩu, passphrase EFF, zxcvbn
crates/vault-core  mật mã, định dạng file, đồng bộ, TOTP, import CSV, cấu hình
crates/health      kiểm tra yếu/trùng/cũ + Have I Been Pwned
crates/cli         pwv.exe
app/               app Tauri 2 (src-tauri = Rust, src = React/TypeScript)
tools/             công cụ cứu hộ Python độc lập
```
