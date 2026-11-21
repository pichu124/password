# pwv — Kho mật khẩu cá nhân

> ⚠ **Đang cập nhật lớn (bản 0.2.0, chưa phát hành).** Mã nguồn trên nhánh này đang được sửa sau đợt
> rà soát bảo mật. Chỉ cài app từ trang
> [Releases](https://github.com/pichu124/password/releases) — **không** tải các file `dev-build-…` trong tab Actions.

Phần mềm tạo mật khẩu mạnh và lưu chúng trong **một file được mã hoá**, đồng bộ giữa các máy Windows
và điện thoại Android qua thư mục Google Drive / Dropbox / OneDrive. Chỉ người biết **master
password** mới mở được.

- Mã hoá: **Argon2id** (256 MiB) → HKDF-SHA256 → **XChaCha20-Poly1305**. Mọi thứ đều được mã hoá,
  kể cả tên trang web và username.
- Đồng bộ: đặt file `vault.pwv` trong thư mục đồng bộ. Hai máy cùng sửa thì app **gộp theo từng
  trường** (máy này đổi mật khẩu, máy kia sửa ghi chú ⇒ giữ được cả hai).
- An toàn dữ liệu: thùng rác, lịch sử mật khẩu, sao lưu tự động theo ngày/tháng, khôi phục ngay
  trong app, và một công cụ cứu hộ độc lập (`tools/pwv_recover.py`).

Kế hoạch tổng thể: [PLAN.md](PLAN.md) · Đặc tả file: [docs/FORMAT.md](docs/FORMAT.md)

## Cài đặt

Chỉ tải từ trang **[Releases](https://github.com/pichu124/password/releases)** của repo này.

### Windows
1. Tải `pwv_x.y.z_x64-setup.exe` → chạy (cài cho riêng tài khoản của bạn, không cần quyền admin).
2. Windows hiện cảnh báo SmartScreen vì bộ cài chưa được ký số: **More info → Run anyway**.
   Chỉ làm vậy với file tải từ đúng trang Releases ở trên.
3. Cập nhật: tải bản mới và cài đè, không cần gỡ. Kho mật khẩu không bị ảnh hưởng.

### Android (chỉ xem + sao chép)
1. Tải `pwv_x.y.z_android-arm64.apk` trên điện thoại → mở để cài (cho phép "cài từ nguồn này").
2. Mở pwv → **Chọn file kho** → chọn Google Drive / Dropbox / OneDrive → chọn `vault.pwv`.
3. Nhập master password.

Ghi chú của bản phát hành cho biết APK được ký bằng khoá nào. Nếu là **khoá tạm** thì muốn cài bản
mới phải gỡ bản cũ trước (kho trên Drive/Dropbox không bị ảnh hưởng; chỉ mất bản xem ngoại tuyến).
Xem mục *Phát hành* để tạo khoá ký cố định.

> **Khi nâng cấp lên 0.2.0, hãy cập nhật MỌI thiết bị.** File kho chuyển sang định dạng mới mà bản
> cũ không đọc/ghi được. Làm theo thứ tự:
> 1. **Khoá hoặc đóng pwv trên tất cả các máy** (bản cũ đang mở sẽ không lưu được nữa — những gì bạn
>    thêm/sửa trên máy còn chạy bản cũ sau thời điểm này sẽ mất).
> 2. Cài 0.2.0 lần lượt trên từng máy tính và điện thoại, mở kho bình thường.
> 3. Máy nào chưa cập nhật sẽ báo "hãy cập nhật phần mềm" thay vì mở file — dữ liệu trong file không
>    bị ảnh hưởng, chỉ cần cài bản mới.

## Dùng app

- **Tạo kho / mở kho có sẵn.** Ở máy thứ hai: chờ dịch vụ đồng bộ tải file về rồi chọn *Mở kho có
  sẵn* — đừng tạo kho mới trùng tên.
- **Master password:** tối thiểu 12 ký tự và phải thật khó đoán. Tên + năm sinh, số điện thoại, tên
  ngân hàng… bị từ chối. Cách tốt nhất: bấm **Gợi ý** để lấy cụm 6 từ ngẫu nhiên, **viết ra giấy** và
  cất nơi an toàn. **Quên master password = mất toàn bộ dữ liệu**, không ai khôi phục được.
- **Danh sách + tìm kiếm** (Ctrl+F), thêm (Ctrl+N), khoá (Ctrl+L), yêu thích, nhóm.
- **Bộ tạo mật khẩu / cụm từ**, thanh độ mạnh, **lịch sử mật khẩu** của từng mục (20 bản gần nhất).
- **Mã 2FA (TOTP)** đếm ngược theo thời gian thực.
- **Thùng rác:** xoá một mục là chuyển vào thùng rác; khôi phục được bất cứ lúc nào. *Xoá vĩnh viễn*
  có hiệu lực trên mọi thiết bị.
- **Sao lưu & khôi phục** (Cài đặt): app giữ 10 bản gần nhất + bản cuối của mỗi ngày trong 30 ngày +
  mỗi tháng trong 12 tháng, ở thư mục `vault.pwv.backups` cạnh file kho. Chọn một bản, xem mục nào
  khác hiện tại, khôi phục từng mục. Khôi phục là "một lần sửa mới": mật khẩu hiện tại được giữ
  trong lịch sử của mục, và thay đổi lan sang mọi thiết bị.
- **Kiểm tra sức khoẻ mật khẩu** + rò rỉ (Have I Been Pwned: chỉ gửi 5 ký tự đầu của mã băm).
- **Nhập CSV** từ Chrome/Edge, Firefox, Bitwarden, KeePass 2/KeePassXC, 1Password, Proton Pass,
  LastPass, Dashlane, Safari. Không dòng nào bị bỏ trừ khi trống hoặc giống hệt mục đã có. Sau khi
  nhập, hãy xoá file CSV (app có nút) **và dọn thùng rác**, kể cả thùng rác trên cloud nếu file nằm
  trong thư mục đồng bộ; rồi xoá mật khẩu đã lưu trong trình duyệt.
- **Tự khoá** khi không dùng (mặc định 5 phút), khi máy vừa ngủ dậy và khi đóng cửa sổ. **Tự xoá
  clipboard** sau 20 giây — kể cả khi bạn đã khoá hoặc đóng app trong lúc đó (app chạy ẩn cho tới
  khi xoá xong rồi mới thoát hẳn). Trên Windows, thứ bạn sao chép từ app không vào lịch sử clipboard
  (Win+V) và không đồng bộ lên cloud clipboard.
- Cửa sổ app được loại khỏi ảnh chụp / quay màn hình (Windows 10 2004 trở lên; Android chặn chụp màn hình).

### Đổi master password
Đổi mật khẩu cũng **đổi luôn khoá mã hoá** của kho và mã hoá lại các bản sao lưu trên máy. Các thiết
bị khác sẽ hỏi mật khẩu mới. Lưu ý: những bản sao **đã rời khỏi máy** (lịch sử phiên bản / thùng rác
của Drive-Dropbox-OneDrive, bản xem ngoại tuyến trên điện thoại, máy khác chưa đồng bộ) vẫn mở được
bằng mật khẩu CŨ và chứa dữ liệu tại thời điểm đó. Nếu nghi mật khẩu cũ bị lộ: đổi cả mật khẩu của
các tài khoản quan trọng (ngân hàng, email).

## Đồng bộ qua Google Drive / Dropbox / OneDrive

1. Cài ứng dụng đồng bộ trên mỗi máy (Google Drive for Desktop / Dropbox / OneDrive).
2. Máy đầu tiên: tạo kho trong thư mục đồng bộ (ví dụ `G:\My Drive\Passwords\vault.pwv`).
3. Máy thứ hai: đợi file tải về rồi chọn **Mở kho có sẵn**.
4. Giữ file luôn có trên máy: Drive chọn **Mirror files**; Dropbox bấm chuột phải thư mục →
   **Make available offline**; OneDrive → **Always keep on this device**.

- App tự nạp thay đổi của máy khác mỗi 20 giây, tự gộp các "bản xung đột" mà dịch vụ đồng bộ tạo ra
  (`vault (1).pwv`, `vault (… conflicted copy …).pwv`, `vault-TÊN-MÁY.pwv`…) rồi cất chúng vào thư
  mục sao lưu.
- **Đừng để bản sao khác của kho trong cùng thư mục** (ví dụ `vault - Copy.pwv`): app sẽ coi đó là
  bản xung đột, gộp vào và cất đi.
- Chuyển kho sang thư mục khác: dùng nút **Chuyển kho** trong Cài đặt trên MỘT máy; ở máy còn lại
  app sẽ báo "không tìm thấy file kho" — chọn *Chọn file kho…* và trỏ tới vị trí mới.

### Khi app báo có vấn đề

| App báo | Nghĩa là | Việc cần làm |
|---|---|---|
| Mật khẩu chính đã được đổi trên thiết bị khác | Máy kia đã đổi master password | Nhập mật khẩu mới |
| File kho trên đĩa đang hỏng hoặc chưa đồng bộ xong | Dịch vụ đồng bộ đang tải dở, hoặc file bị hỏng | Chờ rồi bấm *Thử lại*. Nếu vẫn vậy: *Ghi đè bằng bản đang mở* (file hỏng được cất vào thư mục sao lưu, không bị xoá) |
| Không còn thấy file kho | File bị chuyển/xoá, hoặc chưa đồng bộ về | *Chọn file kho…* nếu đã chuyển chỗ; *Tạo lại file ở đây* nếu bị xoá nhầm |
| File kho cũ hơn bản máy này từng thấy | Dịch vụ đồng bộ khôi phục bản cũ, hoặc có người chép đè | Kiểm tra các mục mới thêm gần đây; dùng *Sao lưu & khôi phục* nếu thiếu |
| Hãy cập nhật phần mềm | File do bản app mới hơn ghi | Cài bản mới nhất trên máy này |
| Không mở được kho (file hỏng) khi đang khoá | File kho hỏng hẳn | *Khôi phục từ bản sao lưu* ngay trên màn hình mở khoá |

App không bao giờ tự ghi đè file kho khi nó hỏng, biến mất, thuộc kho khác hay do bản mới hơn ghi.

Nếu app phải khoá (hết giờ, đóng cửa sổ) trong lúc file kho đang có vấn đề và còn thay đổi chưa ghi
được, nó để lại một **bản cứu hộ** (đã mã hoá bằng master password của bạn) trong
`%LOCALAPPDATA%\vn.pwv.vault\rescue` và tự gộp lại ở lần mở khoá sau — bạn không phải làm gì.

## Công cụ dòng lệnh `pwv.exe` (tuỳ chọn)

Tải `pwv-cli.exe` ở trang Releases, hoặc tự build (`cargo build --release -p pwv-cli`).

```powershell
pwv init                       # tạo kho; gợi ý đặt trong thư mục đồng bộ
pwv gen -p -w 6                # tạo cụm 6 từ (dùng làm master password rất tốt)
pwv add "Vietcombank" -u nguyenvana --url https://vcbdigibank.vietcombank.com.vn -g -l 24
pwv add "Gmail" -u toi@gmail.com --totp --notes   # mật khẩu, secret 2FA, ghi chú được HỎI sau khi chạy lệnh
pwv list ngân                  # tìm kiếm
pwv copy gmail                 # chép mật khẩu, tự xoá clipboard sau 20 giây
pwv show gmail --reveal        # xem chi tiết (mật khẩu và ghi chú chỉ hiện khi có --reveal)
pwv edit gmail -g              # đổi sang mật khẩu ngẫu nhiên mới (mật khẩu cũ vào lịch sử)
pwv delete gmail               # chuyển vào thùng rác
pwv trash                      # xem thùng rác;  pwv trash restore gmail | purge gmail | empty
pwv passwd                     # đổi master password (đổi luôn khoá mã hoá)
pwv sync                       # nạp thay đổi từ máy khác + gộp bản xung đột
pwv totp google -c             # mã 2FA 6 số
pwv health                     # mật khẩu yếu / dùng trùng / lâu chưa đổi / đã bị lộ
pwv import chrome.csv --delete-csv
pwv backups                    # liệt kê bản sao lưu
pwv restore --from 3 gmail     # lấy lại mục "gmail" từ bản sao lưu số 3  (hoặc --all)
pwv recover                    # file kho hỏng/mất: dựng lại từ thư mục sao lưu
pwv move "D:\Dropbox\Passwords\vault.pwv"
```

Mật khẩu, secret 2FA và ghi chú không bao giờ nhận qua tham số dòng lệnh (chúng sẽ nằm lại trong lịch
sử lệnh của PowerShell).

## Cứu hộ dữ liệu không cần app

```powershell
pip install pynacl argon2-cffi
python tools\pwv_recover.py "G:\My Drive\Passwords\vault.pwv" > backup.json
```
⚠ `backup.json` chứa toàn bộ mật khẩu ở dạng rõ — xoá ngay sau khi dùng. Công cụ này được viết độc
lập với app (chỉ dựa trên [docs/FORMAT.md](docs/FORMAT.md)) và đọc được cả file trong thư mục sao lưu.

## Giới hạn — những gì phần mềm KHÔNG bảo vệ được

- **Mã độc / keylogger đang chạy trên máy** khi bạn mở kho: không phần mềm quản lý mật khẩu nào chống được.
- **Máy đang mở khoá kho mà bị người khác dùng.** Hãy khoá app (Ctrl+L) khi rời máy; đừng tắt tự khoá.
- **Ổ đĩa không mã hoá:** khi kho đang mở, hệ điều hành có thể ghi một phần bộ nhớ xuống đĩa (pagefile,
  file ngủ đông). Hãy bật **mã hoá ổ đĩa** (BitLocker / "Device encryption" trên Windows; điện thoại
  Android đời mới đã bật sẵn).
- **Bản sao cũ của file kho** trong lịch sử phiên bản của dịch vụ đồng bộ vẫn mở được bằng master
  password của thời điểm đó (xem *Đổi master password*).
- **Clipboard khi app bị tắt đột ngột:** nếu app bị buộc dừng (Task Manager) hoặc gặp sự cố trong
  20 giây sau khi sao chép, mật khẩu vừa chép nằm lại trong clipboard cho tới khi bạn chép thứ khác
  hoặc đăng xuất / tắt máy.
- **Master password yếu.** Ai lấy được file kho đều có thể thử mật khẩu ngoại tuyến; Argon2id chỉ
  làm việc đó chậm đi. Cụm 6 từ ngẫu nhiên là đủ an toàn; tên + năm sinh thì không.
- Phần mềm đã qua một đợt rà soát mã nguồn kỹ nhưng **chưa được một tổ chức kiểm định độc lập**, và
  bộ cài chưa được ký số. Hãy làm các bước kiểm tra dưới đây trước khi đưa tài khoản ngân hàng vào.

## Kiểm tra trên thiết bị thật trước khi tin dùng

App được kiểm thử tự động trên Windows (CI), nhưng một số thứ chỉ kiểm tra được trên máy của bạn.
Hãy làm với một kho thử (vài mục giả) trước:

**Windows**
1. Tạo kho trong thư mục đồng bộ, thêm vài mục, khoá, mở lại.
2. Sao chép một mật khẩu → dán thử → bấm **Win+V**: mật khẩu KHÔNG nằm trong lịch sử. Chờ 20 giây →
   dán lại: đã trống. Sao chép rồi **đóng app ngay** → trong 20 giây vẫn dán được, sau đó dán lại:
   phải trống, và trong Task Manager không còn `pwv` (app chạy ẩn tới khi xoá xong rồi tự thoát).
3. Bấm **Win+Shift+S** chụp cửa sổ app: cửa sổ pwv không được hiện trong ảnh chụp (chỗ đó trống,
   đen, hoặc chỉ thấy thứ nằm phía sau nó).
4. Gập máy (Sleep) khi kho đang mở → mở máy: app phải đang khoá.
5. Trên hai máy: sửa ở máy A → trong 1 phút thấy ở máy B. Tắt mạng máy B, sửa GHI CHÚ một mục ở B và
   đổi MẬT KHẨU mục đó ở A → bật mạng lại: mục đó phải có cả hai thay đổi.
6. Đổi master password ở máy A → máy B phải hỏi mật khẩu mới.
7. Xoá một mục → lấy lại từ Thùng rác. Sửa một mục → lấy lại bản cũ ở *Sao lưu & khôi phục*.

**Android**
1. Cài APK, chọn file kho từ Drive/Dropbox/OneDrive, mở khoá (mất 1–3 giây; nếu app báo không đủ bộ
   nhớ hoặc tự thoát thì điện thoại không đủ RAM cho bước dẫn xuất khoá 256 MiB).
2. Thử chụp màn hình khi đang xem một mục: phải bị chặn; trong màn hình "Ứng dụng gần đây" nội dung
   phải bị che.
3. Sao chép mật khẩu: khung xem trước clipboard không hiện mật khẩu; sau 20 giây dán ra trống.
4. Bật chế độ máy bay → mở app: vẫn xem được bằng bản đã lưu, có ghi chú cho biết.
5. Sửa một mục trên máy tính → trên điện thoại bấm ⟳: thấy thay đổi, dòng "Dữ liệu cập nhật lúc…" đổi.
6. Để app ở nền hơn 1 phút → quay lại: app phải đang khoá.

## Phát hành bản mới (dành cho người bảo trì)

1. Nâng phiên bản (cập nhật cả 4 file cấu hình và các file khoá):
   ```bash
   python tools/set_version.py 0.2.1
   ```
2. Commit và push; chờ CI xanh.
3. Tab **Actions → Release → Run workflow** (chỉ chạy được trên nhánh mặc định). Workflow chạy test,
   build bộ cài Windows + `pwv-cli.exe` + APK Android, rồi tạo bản phát hành `v0.2.1` kèm `SHA256SUMS.txt`.
4. App đang cài trên các máy sẽ hiện "Có phiên bản mới" trong vòng 24 giờ.

**Khoá ký APK cố định** (để cài đè được, không phải gỡ app): tạo một keystore có alias `pwv`
(`keytool -genkeypair -keystore release.jks -alias pwv -keyalg RSA -keysize 3072 -validity 10000`),
lưu vào Secrets của repo: `ANDROID_KEYSTORE_BASE64` (nội dung file mã hoá base64) và
`ANDROID_KEYSTORE_PASSWORD`. **Giữ một bản sao của keystore ở nơi an toàn** — mất nó là quay lại cảnh
phải gỡ app để cập nhật. Không bao giờ đổi tên tài khoản GitHub chứa repo này: app kiểm tra bản mới
theo đúng tên đó.

`SHA256SUMS.txt` nằm cùng chỗ với file cài nên chỉ giúp phát hiện file tải bị lỗi, không chứng minh
được nguồn gốc.

## Phát triển

```bash
cargo test --workspace                          # lõi + CLI (có property test cho thuật toán gộp)
cargo clippy --workspace --all-targets -- -D warnings
cd app && npm ci && npm run build               # giao diện
cd src-tauri && cargo test                      # backend của app
cd .. && npx tauri dev                          # chạy app ở chế độ phát triển
npx vite --mode mock                            # xem giao diện trong trình duyệt với dữ liệu giả
```

Cấu trúc:
```
crates/generator   tạo mật khẩu, passphrase EFF, zxcvbn, chính sách master password
crates/vault-core  mật mã, định dạng file, gộp/đồng bộ, sao lưu, TOTP, import CSV, cấu hình
crates/health      kiểm tra yếu/trùng/cũ + Have I Been Pwned
crates/cli         pwv.exe
app/               app Tauri 2 (src-tauri = Rust, src = React/TypeScript)
tools/             công cụ cứu hộ Python độc lập + script kiểm tra chéo
docs/FORMAT.md     đặc tả định dạng file
```

## Giấy phép

GPL-3.0-or-later — xem [LICENSE](LICENSE). Danh sách từ dùng cho cụm mật khẩu là
[EFF Large Wordlist](https://www.eff.org/dice) của Electronic Frontier Foundation, phát hành theo
giấy phép Creative Commons Attribution 3.0 US.
