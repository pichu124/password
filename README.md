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
| 4. App giao diện Windows (Tauri) | ⏳ tiếp theo |

## Cài đặt trên Windows

**Cách 1 — tải bản build sẵn:** vào tab *Actions* của repo → lần chạy mới nhất →
tải artifact `pwv-windows` → giải nén `pwv.exe` vào một thư mục, ví dụ `C:\Tools\`.

**Cách 2 — tự build:**
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
```

Trên Windows, mật khẩu khi copy sẽ **không** lưu vào lịch sử clipboard (Win+V) và không đồng bộ
lên cloud clipboard.

## Đồng bộ qua Google Drive

1. Cài **Google Drive for Desktop** trên mỗi máy.
2. Máy đầu tiên: `pwv init` và chọn vị trí trong thư mục Drive (ví dụ `G:\My Drive\Passwords\vault.pwv`).
3. Máy thứ hai: đợi Drive tải file về rồi chạy `pwv config "G:\My Drive\Passwords\vault.pwv"`.
4. Nếu Drive tạo file `vault (1).pwv` vì hai máy sửa cùng lúc, chạy `pwv sync` để gộp.

Nên bật chế độ **“Mirror files”** (lưu bản sao trên máy) cho thư mục chứa kho để vẫn dùng được khi mất mạng.

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

## Phát triển

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
