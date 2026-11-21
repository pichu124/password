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
  có hiệu lực trên mọi thiết bị. *Dọn sạch thùng rác* chỉ xoá đúng những mục bạn đang thấy lúc bấm
  xác nhận; nếu trong lúc đó máy khác vừa chuyển thêm mục vào thùng rác, mục đó được giữ lại và app
  báo cho bạn.
- **Sao lưu & khôi phục** (Cài đặt): app tự giữ các bản sao lưu ở thư mục `vault.pwv.backups` cạnh
  file kho: **10 bản mới nhất**, cộng **bản cuối cùng của mỗi ngày** trong 30 ngày gần nhất *có lưu
  kho*, cộng **bản cuối cùng của mỗi đợt 30 ngày** trong 12 đợt gần nhất *có lưu kho*. ("Ngày có lưu
  kho" nghĩa là: nếu bạn không mở kho cả tháng, các bản cũ không bị xoá vì thời gian trôi qua — chỉ
  bị thay dần khi có bản mới. Việc dọn cũng không phụ thuộc đồng hồ của máy.) Chọn một bản, xem mục
  nào khác hiện tại, khôi phục từng mục. Khôi phục là "một lần sửa mới": mật khẩu hiện tại được giữ
  trong lịch sử của mục, và thay đổi lan sang mọi thiết bị. Bản có nhãn **"ghi bằng mật khẩu cũ"**
  thì app không bao giờ tự gộp — xem *Đổi master password* bên dưới.
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
Đổi mật khẩu cũng **đổi luôn khoá mã hoá** của kho và mã hoá lại các bản sao lưu trên máy. Trước khi
đổi, app đồng bộ một lần; nếu file kho đang có vấn đề (hỏng, chưa tải xong…) thì app báo lỗi và
**chưa đổi gì**. Các thiết bị khác sẽ hỏi mật khẩu mới ở lần mở tới.

**Đổi mật khẩu bảo vệ được gì:**
- Người chỉ biết mật khẩu CŨ không đọc được những gì app ghi ra sau lần đổi (file kho, bản sao lưu) —
  trừ những gì một thiết bị *chưa nhận mật khẩu mới* tiếp tục ghi bằng mật khẩu cũ (kể cả khi app đã
  cất chúng thành bản "ghi bằng mật khẩu cũ": bản cất được giữ nguyên văn, nên vẫn mở được bằng mật
  khẩu cũ).
- Từ đó về sau, **mọi thứ được ghi bằng mật khẩu cũ không bao giờ được gộp tự động vào kho.** Nếu app
  gặp một bản như vậy (ví dụ một máy chưa nhận mật khẩu mới vẫn tiếp tục lưu, hoặc dịch vụ đồng bộ đặt
  lại một bản cũ), nó cất bản đó vào *Cài đặt → Sao lưu & khôi phục* với nhãn **"ghi bằng mật khẩu
  cũ"** và báo cho bạn. Ở đó bạn xem được mục nào khác với kho hiện tại và lấy lại từng mục — **chỉ làm
  vậy khi bạn biết chắc những thay đổi đó là của mình**, vì ai biết mật khẩu cũ cũng làm ra được một
  bản như thế. Nếu chính file kho bị một thiết bị chưa nhận mật khẩu mới ghi đè, mật khẩu HIỆN TẠI vẫn
  mở được kho (từ bản sao lưu mới nhất); file bị ghi đè được cất như trên.
- Hệ quả: những gì bạn sửa trên một thiết bị **chưa nhận mật khẩu mới** phải được lấy lại bằng tay từ
  bản "ghi bằng mật khẩu cũ" đó. Cách dễ nhất để tránh: trước khi đổi, mở và đồng bộ kho trên mọi
  thiết bị; ngay sau khi đổi, mở kho bằng mật khẩu mới trên từng thiết bị.

**Đổi mật khẩu KHÔNG bảo vệ được:** những bản sao **đã rời khỏi máy** (lịch sử phiên bản / thùng rác
của Drive-Dropbox-OneDrive, bản xem ngoại tuyến trên điện thoại, máy khác chưa đồng bộ) vẫn mở được
bằng mật khẩu CŨ và chứa dữ liệu tại thời điểm đó.

**Sau khi đổi, đừng bao giờ gõ lại mật khẩu cũ** — ở bất kỳ máy nào. Nếu ai đó biết mật khẩu cũ và có
quyền ghi vào thư mục đồng bộ, họ có thể đặt vào đó một "kho" mở được bằng mật khẩu cũ; gõ mật khẩu cũ
là mở đúng kho của họ. (Máy đã từng mở kho thật sẽ cảnh báo "kho này không nối tiếp từ kho máy này
dùng lần trước" — xem bảng bên dưới.)

**Nếu mật khẩu cũ có thể đã bị lộ**, làm theo đúng thứ tự:
1. **Đổi mật khẩu tài khoản cloud** (Google / Dropbox / Microsoft) và **đăng xuất mọi phiên đăng nhập
   khác** của tài khoản đó — để người kia không còn đọc/ghi được thư mục đồng bộ.
2. **Đổi master password** trong pwv.
3. **Đổi mật khẩu của các tài khoản quan trọng** (ngân hàng, email): người kia có thể đã đọc được bản
   cũ của kho.

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
| Tìm thấy bản của kho được ghi bằng mật khẩu chính CŨ | Sau lần đổi master password, một thiết bị chưa nhận mật khẩu mới vẫn ghi, hoặc dịch vụ đồng bộ đặt lại bản cũ — hiếm hơn, người biết mật khẩu cũ. App **không gộp** bản đó | Bấm *Mở Sao lưu & khôi phục*, chọn bản có nhãn "ghi bằng mật khẩu cũ", xem khác biệt. Chỉ khôi phục mục nào bạn chắc chắn là thay đổi của mình. Mở kho bằng mật khẩu MỚI trên thiết bị kia |
| Bản này được ghi bằng một mật khẩu chính khác (mới hơn) | Một bản cạnh file kho dùng mật khẩu mà máy này không có — thường là bạn vừa đổi master password ở máy khác | Khoá app rồi mở lại bằng mật khẩu MỚI. Nếu bạn không hề đổi mật khẩu: xoá file được nêu tên (app không đụng tới nó, việc đồng bộ vẫn chạy bình thường) |
| Mật khẩu này có vẻ là một mật khẩu chính cũ (khi khôi phục) | Bạn vừa gõ một master password CŨ; khôi phục bằng nó sẽ đưa kho về mật khẩu đó và mất mọi thay đổi sau lần đổi. (Hiếm hơn: trong thư mục sao lưu có file lạ tự nhận là "mới hơn") | Gõ master password HIỆN TẠI (mật khẩu đặt gần nhất) rồi khôi phục lại. Chỉ chọn *Vẫn khôi phục bằng mật khẩu này* khi bạn thật sự không còn mật khẩu mới hơn, hoặc chắc chắn đây chính là mật khẩu hiện tại |
| Không có bản sao lưu nào dùng được (khi khôi phục) | Thư mục sao lưu trống / hỏng / không có bản nào mở được bằng mật khẩu này | Tìm bản khác: lịch sử phiên bản / thùng rác trên trang web của Drive-Dropbox-OneDrive, một máy khác, bản xem ngoại tuyến trên điện thoại, hoặc *Cứu hộ dữ liệu không cần app* bên dưới. Đừng tạo kho mới đè lên |
| Kho vừa mở KHÔNG phải là phần tiếp nối của kho máy này dùng lần trước | Bạn vừa mở bằng một master password CŨ, hoặc file kho đã bị thay bằng file do người biết mật khẩu cũ làm ra | Bấm *Khoá lại* và mở bằng master password HIỆN TẠI. Đừng tin địa chỉ trang web / mật khẩu đang hiện cho tới khi kiểm tra xong. Chỉ bấm *Đã hiểu, vẫn dùng kho này* nếu bạn biết rõ vì sao (ví dụ chính bạn vừa khôi phục kho từ một bản cũ) |
| Đã lưu, nhưng chưa kiểm tra lại được file vừa ghi | File đã được ghi, nhưng lúc đọc lại để kiểm tra thì bị chương trình đồng bộ / diệt virus giữ | Không cần làm gì: thay đổi vẫn còn trong app, lần đồng bộ tới app tự kiểm tra và ghi lại nếu cần. Nếu lần nào cũng báo, hãy cho thư mục kho vào danh sách loại trừ của phần mềm diệt virus |

App không bao giờ tự ghi đè file kho khi nó hỏng, biến mất, thuộc kho khác hay do bản mới hơn ghi.

Nếu app phải khoá (hết giờ, đóng cửa sổ) trong lúc file kho đang có vấn đề và còn thay đổi chưa ghi
được, nó để lại một **bản cứu hộ** (đã mã hoá bằng master password của bạn) trong
`%LOCALAPPDATA%\vn.pwv.vault\rescue` và tự gộp lại ở lần mở khoá sau — bạn không phải làm gì. Bản
cứu hộ nào không gộp được (ví dụ nó được ghi trước khi master password bị đổi ở máy khác) **không bị
xoá**: app báo "N bản cứu hộ chưa gộp được, vẫn được giữ lại" và thử lại ở lần mở khoá sau.

## Công cụ dòng lệnh `pwv.exe` (tuỳ chọn)

Tải `pwv.exe` ở trang Releases (hoặc tự build: `cargo build --release -p pwv-cli`), để vào một thư
mục, mở PowerShell **tại thư mục đó** và gõ lệnh với `.\` ở đầu — ví dụ `.\pwv list`. (Các ví dụ dưới
đây viết gọn là `pwv …`; muốn gõ được như vậy ở bất cứ đâu thì thêm thư mục chứa `pwv.exe` vào PATH.)

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
python tools\pwv_recover.py "G:\My Drive\Passwords\vault.pwv" -o backup.json
```
⚠ `backup.json` chứa toàn bộ mật khẩu ở dạng rõ — xoá ngay sau khi dùng. Luôn dùng `-o` (đừng dùng
`> backup.json`: trên Windows cách đó làm hỏng các ký tự có dấu). Công cụ này được viết độc lập với
app (chỉ dựa trên [docs/FORMAT.md](docs/FORMAT.md)) và đọc được cả file trong thư mục sao lưu.

## Giới hạn — những gì phần mềm KHÔNG bảo vệ được

- **Mã độc / keylogger đang chạy trên máy** khi bạn mở kho: không phần mềm quản lý mật khẩu nào chống được.
- **Máy đang mở khoá kho mà bị người khác dùng.** Hãy khoá app (Ctrl+L) khi rời máy; đừng tắt tự khoá.
- **Ổ đĩa không mã hoá:** khi kho đang mở, hệ điều hành có thể ghi một phần bộ nhớ xuống đĩa (pagefile,
  file ngủ đông). Hãy bật **mã hoá ổ đĩa** (BitLocker / "Device encryption" trên Windows; điện thoại
  Android đời mới đã bật sẵn).
- **Bản sao cũ của file kho** trong lịch sử phiên bản của dịch vụ đồng bộ vẫn mở được bằng master
  password của thời điểm đó (xem *Đổi master password*).
- **Clipboard khi app bị tắt đột ngột:** nếu app bị buộc dừng (Task Manager) hoặc app
  sập vì một lỗi nằm ngoài phần mã của chính nó (ví dụ trình hiển thị WebView) trong 20 giây sau khi
  sao chép, mật khẩu vừa chép nằm lại trong clipboard cho tới khi bạn chép thứ khác hoặc đăng xuất /
  tắt máy. (Khi chính app gặp lỗi nghiêm trọng, nó cố xoá clipboard trước khi thoát — nhưng chỉ là cố.)
- **Hai lần đổi master password trên hai máy chưa đồng bộ với nhau** (ví dụ cả hai máy đang mất mạng):
  app chỉ tự nối lại được trong một số trường hợp; nếu hai máy đổi sang hai mật khẩu KHÁC nhau thì
  không bao giờ tự nối được — những gì sửa trên máy kia phải lấy lại bằng tay từ bản sao lưu. Hãy chỉ
  đổi master password trên MỘT máy, khi các máy khác đã đồng bộ xong.
- **Thư mục sao lưu nằm trong thư mục đồng bộ.** Ai có quyền ghi vào thư mục đồng bộ (ví dụ biết mật
  khẩu tài khoản Google của bạn) có thể xoá các bản sao lưu, hoặc đặt vào đó những file "bản sao lưu"
  giả. Bản giả làm bằng mật khẩu cũ không bao giờ được tự gộp, nhưng vẫn HIỆN trong danh sách khôi
  phục với nhãn "ghi bằng mật khẩu cũ" — chỉ khôi phục từ bản mang nhãn đó khi chắc chắn nó là của bạn.
  Lịch sử phiên bản / thùng rác của dịch vụ đồng bộ là lớp dự phòng cuối cùng. Vì vậy hãy bảo vệ tài
  khoản cloud bằng mật khẩu mạnh và xác thực hai bước.
- **Máy mới cài không phát hiện được kho giả mạo.** Cảnh báo "kho này không nối tiếp từ kho máy này
  dùng lần trước" chỉ có trên máy đã từng mở kho thật. Trên máy mới cài (hoặc điện thoại), nếu bạn gõ
  một master password CŨ và thư mục đồng bộ đã bị người biết mật khẩu cũ thay file kho, app mở ra kho
  của họ mà không cảnh báo gì. Quy tắc: sau khi đổi master password, đừng bao giờ gõ lại mật khẩu cũ.
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
7. Khi gõ master password và mở khoá: điện thoại KHÔNG được hỏi "Lưu mật khẩu?" (Google Autofill /
   trình quản lý mật khẩu của máy không được đề nghị lưu master password).

## Phát hành bản mới (dành cho người bảo trì)

1. Nâng phiên bản (cập nhật cả 4 file cấu hình và các file khoá):
   ```bash
   python tools/set_version.py 0.2.1
   ```
2. Commit và push; chờ CI xanh (workflow Release từ chối chạy nếu CI của đúng commit đó chưa xanh).
3. Tab **Actions → Release → Run workflow** (chỉ chạy được trên nhánh mặc định). Workflow chạy test,
   build bộ cài Windows + `pwv.exe` (dòng lệnh) + APK Android, rồi tạo bản phát hành `v0.2.1` kèm `SHA256SUMS.txt`.
4. App đang cài trên các máy sẽ hiện "Có phiên bản mới" trong vòng 24 giờ.

**Khoá ký APK cố định** (để cài đè được, không phải gỡ app): tạo một keystore có alias `pwv`
(`keytool -genkeypair -keystore release.jks -alias pwv -keyalg RSA -keysize 3072 -validity 10000`),
lưu vào Secrets của repo: `ANDROID_KEYSTORE_BASE64` (nội dung file mã hoá base64) và
`ANDROID_KEYSTORE_PASSWORD`. Khoá này chỉ được dùng trong workflow Release (ở một bước riêng không
chạy mã của bên thứ ba); các bản build thử luôn ký bằng khoá tạm. **Giữ một bản sao của keystore ở
nơi an toàn** — mất nó là quay lại cảnh phải gỡ app để cập nhật. Không bao giờ đổi tên tài khoản GitHub chứa repo này: app kiểm tra bản mới
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
