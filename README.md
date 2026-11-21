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

### Khi nâng cấp lên 0.2.0

**Hãy cập nhật MỌI thiết bị.** File kho chuyển sang định dạng mới mà bản cũ (0.1.x) không đọc/ghi
được. Làm theo thứ tự:
1. **Mở kho trên từng máy và chờ đồng bộ xong**, rồi **khoá hoặc đóng pwv trên tất cả các máy**.
2. Cài 0.2.0 lần lượt trên từng máy tính và điện thoại, mở kho bình thường.
3. Mở kho trên máy 0.2.0 thôi thì CHƯA đổi gì: file kho chỉ chuyển sang định dạng mới khi một máy đã
   cập nhật **lưu một thay đổi** (thêm/sửa/xoá một mục). Trước lúc đó, máy chưa cập nhật vẫn mở và lưu
   bình thường — và những gì nó lưu sẽ được gộp vào sau theo kiểu "cả mục" (xem bên dưới). Từ khi máy
   đã cập nhật lưu một thay đổi, máy chưa cập nhật sẽ báo "hãy cập nhật phần mềm" thay vì mở file — dữ
   liệu trong file không bị ảnh hưởng, chỉ cần cài bản mới; nó không lưu được gì nữa cho tới khi cập
   nhật.

**Từ khi đã có một máy chạy 0.2.0, đừng dùng bản 0.1.x ở bất kỳ máy nào nữa** (kể cả `pwv.exe` cũ):
- Một mục được sửa trên máy còn chạy 0.1.x (ví dụ khi máy đó đang mất mạng), khi file của nó đồng bộ
  về và được gộp, sẽ **thay CẢ mục** — kể cả những trường bạn đã sửa sau đó trên máy 0.2.0. Ví dụ: bạn
  đặt mật khẩu ngân hàng mới trên máy đã cập nhật, rồi máy cũ chỉ sửa ghi chú của mục đó ⇒ mục quay về
  mật khẩu CŨ (mật khẩu mới vẫn nằm trong *Lịch sử* của mục).
- Xoá vĩnh viễn: app áp dụng đúng quy tắc của 0.1.x (một lần xoá không xoá mục đã được sửa SAU lần xoá
  đó), cả khi file của máy cũ đến muộn (bản xung đột, bản sao lưu). Nhưng khi một lần xoá đã được ghi
  vào file định dạng mới thì nó là tuyệt đối: một mục bị xoá ở máy này rồi được sửa muộn hơn trên một
  máy vẫn chạy 0.1.x vẫn có thể biến mất (nó còn trong các bản sao lưu).
- Nếu file kho bị thay lại bằng file của máy 0.1.x, mỗi lần lưu trên máy đó **xoá dần các bản sao lưu**
  của 0.2.0 trong thư mục sao lưu. Khi mở kho, máy 0.2.0 đã từng mở kho này sẽ báo "File kho vừa được
  một máy còn chạy bản 0.1.x ghi lại" — hãy cập nhật máy đó ngay.
- `pwv.exe` 0.1.x chạy trên một máy đã cài 0.2.0 xoá các mốc "đã thấy" mà máy này dùng để phát hiện
  file kho bị thay bằng bản cũ / bản giả.

Hai trường hợp cần làm thêm một lần:
- **Master password có dấu tiếng Việt, đặt từ bản 0.1.x:** lúc đầu hãy gõ nó bằng đúng bàn phím / bộ
  gõ như trước (cùng một chữ có dấu có thể được gõ ra theo nhiều cách khác nhau). Sau khi "đổi" master
  password một lần trên 0.2.0 — nhập lại đúng mật khẩu đó cũng được — nó mở được trên mọi máy dù gõ
  kiểu nào.
- **Đã từng đổi master password khi còn dùng 0.1.x:** bản đó chỉ đổi mật khẩu chứ không đổi khoá mã
  hoá, nên ai biết mật khẩu CŨ và có một bản sao lưu cũ vẫn mở được dữ liệu mới. Hãy **đổi master
  password một lần nữa trên 0.2.0** (trên MỘT máy, khi các máy khác đã khoá app). App tự phát hiện
  trường hợp này và hiện dải thông báo "Kho này từng được đổi mật khẩu chính bằng bản 0.1.x" với nút
  *Đổi mật khẩu chính…*; `pwv backups` cũng nhắc.

Về việc **nhập lại đúng master password đang dùng** (app và `pwv passwd` đều cho phép): khi đó mật khẩu
giữ nguyên, chỉ khoá mã hoá được thay mới ("Giữ nguyên mật khẩu — chỉ thay khoá mã hoá."), kể cả khi
mật khẩu đó không đạt chính sách mới của 0.2.0 — app / pwv chỉ cảnh báo và nhắc bạn đổi sang mật khẩu
mạnh hơn sau. Nếu mật khẩu đang dùng yếu (ngắn, có tên, ngày sinh…), tốt hơn là đổi hẳn: bấm **Gợi ý**,
**viết cụm từ mới ra giấy TRƯỚC khi bấm đổi**, rồi mới đổi.

## Dùng app

- **Tạo kho / mở kho có sẵn.** Ở máy thứ hai: chờ dịch vụ đồng bộ tải file về rồi chọn *Mở kho có
  sẵn* — đừng tạo kho mới trùng tên.
- **Master password:** tối thiểu 12 ký tự và phải thật khó đoán. **Cách tốt nhất: bấm «Gợi ý»** để lấy
  cụm 6 từ ngẫu nhiên, **viết ra giấy** và cất nơi an toàn. **Quên master password = mất toàn bộ dữ
  liệu**, không ai khôi phục được.
  - App từ chối: mật khẩu ngắn hơn 12 ký tự; mật khẩu mà bộ đo độ mạnh (zxcvbn) ước tính đoán ra được
    dưới 10^14 lần thử; và mật khẩu **chủ yếu ghép từ tên người Việt, tên ngân hàng / ví điện tử / nhà
    mạng / dịch vụ lớn, tên tỉnh thành với chữ số** (ngày tháng, năm sinh, số điện thoại) — ví dụ
    `nguyenvanan1990`, `Le.Thi.Mai.1990.12.03`, `Trần Văn Bình 12/03/1985`, `Vietcombank@Nguyenvanan`.
    Có dấu hay không dấu, viết hoa hay thường đều như nhau.
  - Những kiểu đó **thường** bị từ chối, **không phải luôn luôn**: app chỉ có một danh sách tên phổ
    biến, và **không biết tên, ngày sinh, số điện thoại, biển số xe… của chính bạn** hay người thân. Ghép
    chúng với một từ bình thường có thể vẫn được báo "✓ Đạt yêu cầu tối thiểu" — "đạt" không có nghĩa là
    an toàn. Đừng dùng thông tin cá nhân; dùng **Gợi ý**.
  - Chính sách chỉ được kiểm tra khi tạo kho và khi đổi sang một master password KHÁC, không bao giờ khi
    mở kho: mật khẩu đang dùng không bị khoá ngoài vì chính sách mới. Nhập lại đúng mật khẩu đang dùng
    (để chỉ thay khoá mã hoá) cũng không bị chặn — app chỉ cảnh báo nếu nó không còn đạt.
  - Tên dịch vụ trùng từ tiếng Anh (Google, Facebook, Yahoo, Banking…) cũng tính là thông tin cá nhân;
    chữ có dấu gõ theo kiểu nào cũng được xét như nhau.
- **Danh sách + tìm kiếm** (Ctrl+F), thêm (Ctrl+N), khoá (Ctrl+L), yêu thích, nhóm.
- **Bộ tạo mật khẩu / cụm từ**, thanh độ mạnh, **lịch sử mật khẩu** của từng mục (20 bản gần nhất).
- **Đổi mật khẩu một trang web — đúng thứ tự:** mở mục → *Sửa* → *Tạo* → bấm **Lưu** → rồi mới đổi
  mật khẩu trên trang web (mật khẩu cũ vẫn nằm trong *Lịch sử* của mục). Nếu lỡ quên lưu:
  - Form đang sửa dở được giữ thành **bản nháp** trên máy này (đã mã hoá bằng khoá kho): kho có tự
    khoá hay app bị đóng thì lần mở khoá sau form tự mở lại ("Đã khôi phục mục đang sửa dở…"). Nếu mục
    đã bị đổi ở máy khác trong lúc đó, app nhắc kiểm tra lại trước khi lưu (lời nhắc còn đó cho tới khi
    bạn lưu hoặc bỏ thay đổi, kể cả qua nhiều lần khoá). Bấm sang mục khác khi đang
    sửa dở thì app hỏi *Tiếp tục sửa* / *Lưu* / *Bỏ thay đổi*.
  - Trên máy tính, mỗi mật khẩu bạn sao chép hoặc bấm *Dùng* trong bộ tạo được ghi vào mục **"Mật khẩu
    vừa tạo gần đây"** của bộ tạo (tối đa 20, tự xoá sau 30 ngày; chỉ trên máy này, đã mã hoá bằng
    khoá kho). Bấm *Hiện* hoặc *Sao chép* để lấy lại, *Xoá danh sách* để xoá.
  - Ô mật khẩu để trống khi sửa nghĩa là **giữ nguyên** mật khẩu đang lưu; muốn xoá hẳn thì bấm *Xoá
    mật khẩu đã lưu*.
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
- **Tự khoá** khi không dùng (mặc định 5 phút), khi máy vừa ngủ dậy và khi đóng cửa sổ. Tự khoá, nút
  khoá và Ctrl+L không bao giờ phải chờ ổ đĩa / dịch vụ đồng bộ đang chậm: màn hình được xoá trước, việc
  lưu làm sau. Khoá
  màn hình Windows (Win+L) thì **không** khoá pwv: bấm **Ctrl+L** trước khi rời máy. **Tự xoá
  clipboard** sau 20 giây — kể cả khi bạn đã khoá hoặc đóng app trong lúc đó (app chạy ẩn cho tới
  khi xoá xong rồi mới thoát hẳn). Trên Windows, thứ bạn sao chép từ app không vào lịch sử clipboard
  (Win+V) và không đồng bộ lên cloud clipboard. Không kéo thả được chữ ra khỏi cửa sổ app; ô mật khẩu,
  ghi chú và mã 2FA không cho cắt (Ctrl+X).
- **Android:** việc xoá clipboard sau 20 giây do chính pwv làm, nên **có thể bị trễ** khi pwv đang nằm
  nền (ví dụ bạn chuyển sang app ngân hàng để dán): Android có thể "đóng băng" app nền cho tới khi bạn
  quay lại. Dán xong hãy quay lại pwv một lát, hoặc chép một thứ khác đè lên. (Android 13 trở lên tự
  xoá clipboard sau một thời gian.)
- Cửa sổ app được loại khỏi ảnh chụp / quay màn hình (Windows 10 2004 trở lên; Android chặn chụp màn hình).

### Đổi master password
**Trước khi đổi: khoá hoặc đóng pwv trên CÁC MÁY KHÁC** (một máy để mở khoá sẽ tiếp tục tin các file
ghi bằng mật khẩu cũ cho tới khi nó biết về lần đổi), và giữ an toàn tài khoản cloud (mật khẩu mạnh,
xác thực hai bước). Đổi mật khẩu cũng **đổi luôn khoá mã hoá** của kho và mã hoá lại các bản sao lưu
trên máy. Trước khi đổi, app đồng bộ một lần; nếu file kho đang có vấn đề (hỏng, chưa tải xong…) thì app báo lỗi và
**chưa đổi gì**. Các thiết bị khác sẽ hỏi mật khẩu mới ở lần mở tới. Nhập lại đúng mật khẩu đang dùng
cũng được: khoá mã hoá vẫn được thay mới. Nếu bản sao lưu nào không đọc hoặc không ghi lại được (đĩa đầy,
file bị chương trình khác giữ), app ghi rõ tên các file đó: chúng **có thể vẫn mở được bằng mật khẩu
CŨ** — nếu mật khẩu cũ có thể đã lộ, hãy xoá chúng khỏi thư mục sao lưu.

**Đổi mật khẩu bảo vệ được gì:**
- Người chỉ biết mật khẩu CŨ không đọc được những gì app ghi ra sau lần đổi (file kho, bản sao lưu) —
  trừ những gì một thiết bị *chưa nhận mật khẩu mới* tiếp tục ghi bằng mật khẩu cũ (kể cả khi app đã
  cất chúng thành bản "ghi bằng mật khẩu cũ": bản cất được giữ nguyên văn, nên vẫn mở được bằng mật
  khẩu cũ).
- Từ đó về sau, **mọi thứ trong thư mục đồng bộ được ghi bằng mật khẩu cũ không bao giờ được gộp tự
  động vào kho** — kể cả bản cứu hộ / bản lưu riêng trong thư mục riêng của app trên máy này. Nếu app
  gặp một bản như vậy (ví dụ một máy chưa nhận mật khẩu mới vẫn tiếp tục lưu, hoặc dịch vụ đồng bộ đặt
  lại một bản cũ), nó cất bản đó vào *Cài đặt → Sao lưu & khôi phục* với nhãn **"ghi bằng mật khẩu
  cũ"** và báo cho bạn. Ở đó bạn xem được mục nào khác với kho hiện tại và lấy lại từng mục — **chỉ làm
  vậy khi bạn biết chắc những thay đổi đó là của mình**, vì ai biết mật khẩu cũ cũng làm ra được một
  bản như thế. Nếu chính file kho bị một thiết bị chưa nhận mật khẩu mới ghi đè, mật khẩu HIỆN TẠI vẫn
  mở được kho (từ bản sao lưu mới nhất); file bị ghi đè được cất như trên.
- **Các bản sao lưu có từ trước lần đổi** được mã hoá lại bằng khoá mới (mật khẩu cũ không đọc được
  chúng nữa) và từ đó cũng mang nhãn "ghi bằng mật khẩu cũ": bạn vẫn xem và khôi phục từng mục từ
  chúng được, nhưng app không bao giờ tự dùng chúng — trước lần đổi, người biết mật khẩu cũ có thể đã
  sửa hoặc cài bản sao lưu.
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
2. **Khoá hoặc đóng pwv trên mọi máy khác**, rồi **đổi master password** trong pwv trên MỘT máy (bấm
   **Gợi ý**, viết cụm từ mới ra giấy trước).
3. **Xem lại các mục vừa thay đổi gần đây** (địa chỉ trang web, tên đăng nhập, mật khẩu): trước khi
   đổi, app gộp mọi thứ đang có trong thư mục đồng bộ — nếu người kia đã sửa kho bằng mật khẩu cũ
   trước lúc bạn đổi, những sửa đổi đó đã được gộp vào và vẫn còn sau khi đổi.
4. **Đổi mật khẩu của các tài khoản quan trọng** (ngân hàng, email): người kia có thể đã đọc được bản
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
  app sẽ báo không tìm thấy file kho — bấm *Chọn file kho…* (có trên cả màn hình mở khoá lẫn dải báo
  lỗi khi kho đang mở) và trỏ tới vị trí mới.
- Nếu bạn lỡ chọn một bản xung đột (ví dụ `vault (1).pwv`) làm file kho, app hỏi "Có vẻ là bản xung
  đột": bấm *Dùng «vault.pwv» (nên chọn)*; app sẽ tự gộp bản còn lại.

### Khi app báo có vấn đề

| App báo | Nghĩa là | Việc cần làm |
|---|---|---|
| Mật khẩu chính đã được đổi trên thiết bị khác | Máy kia đã đổi master password | Nhập mật khẩu mới |
| File kho trên đĩa bị hỏng hoặc chưa tải xong (khi kho đang mở) | Dịch vụ đồng bộ đang tải dở, hoặc file bị hỏng | Chờ rồi bấm *Thử lại*. Nếu vẫn vậy: *Ghi đè bằng bản đang mở* (file hỏng được cất vào thư mục sao lưu, không bị xoá), hoặc *Lưu sang chỗ khác…* (chỉ chép bản đang mở ra file mới, không đụng gì tới chỗ cũ; phải chọn một thư mục KHÁC thư mục của file kho, ví dụ Documents; app từ chối nếu master password vừa được đổi ở máy khác) |
| File kho không còn ở vị trí cũ (khi kho đang mở) | File bị chuyển/xoá, hoặc chưa đồng bộ về | Chờ rồi *Thử lại*; *Chọn file kho…* nếu kho đã được chuyển chỗ ở máy khác; *Tạo lại file ở đây* nếu bị xoá nhầm; hoặc *Lưu sang chỗ khác…* |
| Không tìm thấy file kho (màn hình mở khoá) | Như trên, khi kho đang khoá | *Thử lại*; *Chọn file kho…* nếu đã chuyển chỗ; *Khôi phục từ bản sao lưu…* nếu file bị xoá/hỏng; nếu app báo "Máy này còn giữ một bản lưu riêng của kho": *Tạo lại file kho từ bản lưu riêng* (không bao giờ ghi đè file đã có). Đừng bấm *Tạo kho mới ở vị trí khác* nếu bạn đã có kho |
| File kho cũ hơn bản máy này từng thấy | Dịch vụ đồng bộ khôi phục bản cũ, hoặc có người chép đè | Kiểm tra các mục mới thêm gần đây; dùng *Sao lưu & khôi phục* nếu thiếu |
| File kho được tạo bởi phiên bản app mới hơn / hãy cập nhật phần mềm | File do bản app mới hơn ghi | Cài bản mới nhất trên máy này (*Kiểm tra bản mới*). Chỉ khi bạn chắc không máy nào chạy bản mới hơn (file có thể hỏng đúng chỗ ghi phiên bản): *Chưa cập nhật app ở máy nào khác? … dựng lại từ bản sao lưu*, đánh dấu ô "Tôi hiểu…" rồi *Dựng lại từ bản sao lưu* |
| File kho bị hỏng hoặc chưa tải xong (màn hình mở khoá) | File kho hỏng — kể cả khi chỉ phần đầu file (phần chứa khoá đã gói) bị hỏng mà app chứng minh được mật khẩu bạn gõ là đúng | Chờ đồng bộ rồi *Mở khoá* lại; vẫn lỗi thì *Khôi phục từ bản sao lưu* ngay trên màn hình đó |
| Sai mật khẩu, lặp lại dù bạn chắc chắn gõ đúng | Thường là gõ nhầm (bộ gõ tiếng Việt, Caps Lock). Hiếm hơn: file kho hỏng theo cách app không chứng minh được | Sau 2 lần sai, app giữ lại mật khẩu vừa gõ và hiện *Chắc chắn mật khẩu đúng? Thử dựng lại kho từ các bản sao lưu*. Mật khẩu sai thật thì việc dựng lại cũng chỉ báo sai mật khẩu, không ghi gì |
| Bản dựng lại được cũ hơn dữ liệu máy này từng thấy (khi khôi phục) | Các bản sao lưu mới hơn chưa đồng bộ về máy này, hoặc đã bị xoá. Chưa có gì được ghi | Chờ đồng bộ xong, xem máy còn lại, hoặc lịch sử phiên bản của dịch vụ đồng bộ. Chỉ khi không còn bản nào mới hơn: *Vẫn khôi phục bản cũ hơn này* |
| File kho vừa mở thiếu một số thay đổi mà máy này đã lưu trước đó … đã gộp lại từ bản lưu riêng | Một máy khác ghi đè file kho khi chưa đồng bộ xong | Không cần làm gì (app đã gộp lại và ghi file); xem lại các mục vừa sửa gần đây |
| File kho vừa được một máy còn chạy bản 0.1.x ghi lại | Còn máy chưa cập nhật | Cập nhật app trên máy đó ngay (xem *Khi nâng cấp lên 0.2.0*) |
| Kho này từng được đổi mật khẩu chính bằng bản 0.1.x | Mật khẩu CŨ (của thời 0.1.x) vẫn mở được dữ liệu mới từ các bản sao lưu cũ | Bấm *Đổi mật khẩu chính…* và đổi một lần, trên MỘT máy, khi các máy khác đã khoá app. Nhập lại đúng mật khẩu đang dùng cũng được (chỉ thay khoá — app cảnh báo nếu mật khẩu đó không còn đạt); nếu nó yếu, tốt hơn là lấy cụm từ **Gợi ý**, viết ra giấy trước rồi mới đổi |
| N bản sao lưu chưa mã hoá lại được (sau khi đổi mật khẩu chính) | Không đọc hoặc không ghi lại được: đĩa đầy, hoặc file bị chương trình đồng bộ / diệt virus giữ | Các file được nêu tên có thể vẫn mở được bằng mật khẩu CŨ: nếu mật khẩu cũ có thể đã lộ, xoá chúng khỏi thư mục sao lưu |
| Bản lưu riêng trên máy này được ghi bằng mật khẩu chính CŨ và có nội dung mà kho hiện tại không có | Một bản cứu hộ / bản lưu riêng của máy này được ghi trước một lần đổi master password. App không gộp nó; đã cất vào thư mục sao lưu với nhãn "ghi bằng mật khẩu cũ" | Mở *Cài đặt → Sao lưu & khôi phục*, chọn bản đó, xem khác biệt; chỉ lấy lại mục nào bạn chắc là thay đổi của mình |
| Mục này vừa thay đổi … hãy bấm sao chép lại | Mục vừa được đồng bộ về bản mới trong lúc bạn đang xem | Bấm sao chép lại (app không chép giá trị cũ) |
| Tìm thấy bản của kho được ghi bằng mật khẩu chính CŨ | Sau lần đổi master password, một thiết bị chưa nhận mật khẩu mới vẫn ghi, hoặc dịch vụ đồng bộ đặt lại bản cũ — hiếm hơn, người biết mật khẩu cũ. App **không gộp** bản đó | Bấm *Mở Sao lưu & khôi phục*, chọn bản có nhãn "ghi bằng mật khẩu cũ", xem khác biệt. Chỉ khôi phục mục nào bạn chắc chắn là thay đổi của mình. Mở kho bằng mật khẩu MỚI trên thiết bị kia |
| Bản này được ghi bằng một mật khẩu chính khác (mới hơn) | Một bản cạnh file kho dùng mật khẩu mà máy này không có — thường là bạn vừa đổi master password ở máy khác | Khoá app rồi mở lại bằng mật khẩu MỚI. Nếu bạn không hề đổi mật khẩu: xoá file được nêu tên (app không đụng tới nó, việc đồng bộ vẫn chạy bình thường) |
| Mật khẩu này có vẻ là một mật khẩu chính cũ (khi khôi phục) | Bạn vừa gõ một master password CŨ; khôi phục bằng nó sẽ đưa kho về mật khẩu đó và mất mọi thay đổi sau lần đổi. (Hiếm hơn: trong thư mục sao lưu có file lạ tự nhận là "mới hơn") | Gõ master password HIỆN TẠI (mật khẩu đặt gần nhất) rồi khôi phục lại. Chỉ chọn *Vẫn khôi phục bằng mật khẩu này* khi bạn thật sự không còn mật khẩu mới hơn, hoặc chắc chắn đây chính là mật khẩu hiện tại |
| Chỉ còn các bản sao lưu có từ trước lần đổi mật khẩu (khi khôi phục) | Mật khẩu đúng, nhưng mọi bản sao lưu ghi sau lần đổi master password đã mất — và máy này cũng không còn bản lưu riêng dùng được (nếu còn, app đã tự dựng lại từ nó) | Thử tìm bản mới hơn trước (lịch sử phiên bản / thùng rác của dịch vụ đồng bộ, thiết bị khác). Nếu không có: bấm *Vẫn khôi phục từ các bản cũ này*, rồi kiểm tra lại địa chỉ trang web và mật khẩu của các tài khoản quan trọng |
| Không có bản sao lưu nào dùng được (khi khôi phục) | Thư mục sao lưu trống / hỏng / không có bản nào mở được bằng mật khẩu này | Tìm bản khác: lịch sử phiên bản / thùng rác trên trang web của Drive-Dropbox-OneDrive, một máy khác, bản xem ngoại tuyến trên điện thoại, hoặc *Cứu hộ dữ liệu không cần app* bên dưới. Đừng tạo kho mới đè lên |
| Kho vừa mở KHÔNG phải là phần tiếp nối của kho máy này dùng lần trước | Bạn vừa mở bằng một master password CŨ, hoặc file kho đã bị thay bằng file do người biết mật khẩu cũ làm ra | Bấm *Khoá lại* và mở bằng master password HIỆN TẠI. Đừng tin địa chỉ trang web / mật khẩu đang hiện cho tới khi kiểm tra xong. Chỉ bấm *Đã hiểu, vẫn dùng kho này* nếu bạn biết rõ vì sao (ví dụ chính bạn vừa khôi phục kho từ một bản cũ) |
| Đã lưu, nhưng chưa kiểm tra lại được file vừa ghi | File đã được ghi, nhưng lúc đọc lại để kiểm tra thì bị chương trình đồng bộ / diệt virus giữ | Không cần làm gì: thay đổi vẫn còn trong app, lần đồng bộ tới app tự kiểm tra và ghi lại nếu cần. Nếu lần nào cũng báo, hãy cho thư mục kho vào danh sách loại trừ của phần mềm diệt virus |

App không bao giờ tự ghi đè file kho khi nó hỏng, biến mất, thuộc kho khác hay do bản mới hơn ghi.

### Bản cứu hộ và bản lưu riêng trên máy này

Ngoài thư mục sao lưu (nằm trong thư mục đồng bộ), app trên máy tính còn giữ vài file trong thư mục
**riêng** của nó, **không đồng bộ** đi đâu: `%LOCALAPPDATA%\vn.pwv.vault\rescue`. Các file `.pwv` ở
đó được mã hoá y như file kho (mở bằng master password của thời điểm chúng được ghi).

- **Bản lưu riêng trên máy này** (`last-<mã kho>.pwv`): mỗi lần lưu / đồng bộ thành công và khi khoá,
  app chép toàn bộ kho vào đây. Lần mở khoá sau, app gộp nó vào kho: nếu một máy khác đã ghi đè file
  kho khi chưa đồng bộ xong, những gì máy này đã lưu được lấy lại (app báo "File kho vừa mở thiếu một
  số thay đổi… đã gộp lại từ bản lưu riêng"). Nó cũng được dùng khi **khôi phục** mà thư mục sao lưu
  không còn bản nào dùng được (hoặc chỉ còn các bản có từ trước lần đổi mật khẩu), và cho nút *Tạo lại file kho từ bản lưu riêng* khi file kho biến mất.
- **Bản cứu hộ** (`<mã kho>-<thời điểm>.pwv`): nếu app phải khoá (hết giờ, đóng cửa sổ) trong lúc file
  kho đang có vấn đề và còn thay đổi chưa ghi được, nó để lại một bản cứu hộ và tự gộp lại ở lần mở
  khoá sau — bạn không phải làm gì.
- **Bản nháp** và **mật khẩu vừa tạo gần đây** (`stash-<mã kho>.bin`, mã hoá bằng khoá kho).

Gộp hai loại `.pwv` trên là phép gộp an toàn: không làm sống lại mục đã xoá vĩnh viễn, không đè lên
thay đổi mới hơn. Chỉ bản ghi bằng **khoá hiện tại** của kho mới được gộp. Bản được ghi bằng một master
password **CŨ** (ví dụ ngay trước khi mật khẩu được đổi ở máy khác) **không bao giờ được gộp**, như mọi
file khác: nếu nó có nội dung mà kho không có, app **mã hoá lại nội dung đó bằng khoá hiện tại** (mật
khẩu cũ không mở được bản cất này) rồi cất vào thư mục sao lưu với nhãn **"ghi bằng mật khẩu cũ"**, xoá
bản trong thư mục riêng, và báo "Bản lưu riêng trên máy này được ghi bằng mật khẩu chính CŨ…" — mở
*Cài đặt → Sao lưu & khôi phục* để xem và lấy lại từng mục **nếu chắc đó là thay đổi của bạn**. Nếu nó
không có gì mới thì app chỉ xoá nó đi.

Bản nào **không gộp được** vì kho hiện tại không biết khoá của nó (ví dụ nó được ghi bằng một master
password MỚI HƠN hoặc khác hẳn — chẳng hạn bạn vừa khôi phục kho về một mật khẩu cũ) hoặc vì file bị
hỏng **không bị xoá**: app báo "N bản cứu hộ chưa gộp được… vẫn được giữ lại" và thử lại ở lần mở khoá
sau. Trong app không có nút mở chúng; muốn xem, dùng công cụ ở mục *Cứu hộ dữ liệu không cần app* với
**master password của lúc bản đó được ghi**, ví dụ:
`py pwv_recover.py "$env:LOCALAPPDATA\vn.pwv.vault\rescue\<tên file>.pwv" -o cuuho.json`.

Các file này chỉ do **app trên máy tính** ghi. Công cụ dòng lệnh `pwv.exe` không ghi bản lưu riêng, bản
nháp hay danh sách mật khẩu vừa tạo (xem mục dưới).

## Công cụ dòng lệnh `pwv.exe` (tuỳ chọn)

Tải `pwv.exe` ở trang Releases (hoặc tự build: `cargo build --release -p pwv-cli`), để vào một thư
mục, mở PowerShell **tại thư mục đó** và gõ lệnh với `.\` ở đầu — ví dụ `.\pwv list`. (Các ví dụ dưới
đây viết gọn là `pwv …`; muốn gõ được như vậy ở bất cứ đâu thì thêm thư mục chứa `pwv.exe` vào PATH.)

```powershell
pwv init                       # tạo kho; gợi ý đặt trong thư mục đồng bộ
pwv gen -p -w 6                # tạo cụm 6 từ (dùng làm master password rất tốt)
pwv add "Vietcombank" -u nguyenvana --url https://vcbdigibank.vietcombank.com.vn -g -l 24
pwv add "Gmail" -u toi@gmail.com --totp --notes   # mật khẩu, secret 2FA rồi ghi chú được HỎI sau khi chạy lệnh; ghi chú kết thúc bằng một dòng chỉ có dấu chấm "."
pwv list ngân                  # tìm kiếm
pwv copy gmail                 # chép mật khẩu, tự xoá clipboard sau 20 giây
pwv show gmail --reveal        # xem chi tiết (mật khẩu và ghi chú chỉ hiện khi có --reveal)
pwv edit gmail -g -c           # đổi sang mật khẩu ngẫu nhiên mới (mật khẩu cũ vào lịch sử); -c chép mật khẩu mới vào clipboard
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
sử lệnh của PowerShell). Ghi chú được phép có dòng trống: gõ (hoặc dán) xong thì Enter, gõ một dòng
chỉ có dấu chấm `.` rồi Enter (hoặc Ctrl+Z rồi Enter). Để trống mật khẩu khi `pwv add` hỏi thì pwv hỏi
lại có muốn tạo mật khẩu ngẫu nhiên không.

Khi pwv cảnh báo kho cũ hơn / không nối tiếp kho máy này dùng lần trước, các lệnh chỉ xem vẫn chạy, còn
lệnh sửa kho sẽ dừng lại hỏi (mặc định: không). Nếu tên bạn gõ chỉ khớp một phần với một mục, hoặc bản
sao lưu được ghi từ trước lần đổi mật khẩu / bằng mật khẩu cũ, pwv luôn hỏi lại — kể cả khi có `-y`.
`pwv recover` cũng luôn hỏi (không bỏ qua được bằng `-y`) trước khi dựng lại một kho CŨ HƠN nội dung
máy này từng thấy, hoặc bằng một mật khẩu có vẻ là mật khẩu cũ; trả lời không thì không ghi gì.
`pwv passwd` báo tên các bản sao lưu không mã hoá lại được, và hỏi trước khi đổi nếu đĩa / thư mục sao
lưu đang có vấn đề. `pwv backups` nhắc đổi master password một lần nếu kho từng đổi mật khẩu bằng 0.1.x.
Lỡ dán nhiều dòng vào ô hỏi mật khẩu thì các dòng thừa bị bỏ đi, không chạy thành lệnh. pwv cần một
cửa sổ dòng lệnh (PowerShell / Terminal) để hỏi master password; nó không nhận mật khẩu qua đường ống
hay file. `pwv passwd` nhập lại đúng mật khẩu đang dùng thì chỉ thay khoá mã hoá (có cảnh báo nếu mật
khẩu đó không đạt chính sách).

**`pwv.exe` không có các lưới an toàn của app:** nó không ghi bản lưu riêng trên máy, không giữ bản nháp
và không có danh sách "mật khẩu vừa tạo gần đây". Sau khi đổi mật khẩu một mục bằng dòng lệnh (ví dụ
`pwv edit … -g`), hãy kiểm tra mục đó trên một máy khác (hoặc trong app) TRƯỚC khi đổi mật khẩu trên trang
web.

## Cứu hộ dữ liệu không cần app

Khi app không mở được kho, công cụ `pwv_recover.py` (viết độc lập với app, chỉ dựa trên
[docs/FORMAT.md](docs/FORMAT.md)) giải mã file kho — hoặc một file trong thư mục sao lưu
`vault.pwv.backups`, hay một bản cứu hộ / bản lưu riêng — ra một file JSON đọc được. Nên chuẩn bị
sẵn (bước 1–2) từ bây giờ, khi mọi thứ còn chạy tốt.

1. **Tải công cụ:** trên trang [Releases](https://github.com/pichu124/password/releases), mỗi bản phát
   hành có file `pwv_recover.py` (và mã SHA-256 của nó trong `SHA256SUMS.txt`). Tải về một thư mục,
   ví dụ `C:\CuuHo`.
2. **Cài Python** (một lần): tải bộ cài Windows từ [python.org](https://www.python.org/downloads/),
   chạy, và **đánh dấu ô "Add python.exe to PATH"** ở màn hình đầu tiên trước khi bấm *Install Now*.
   Bộ cài mới ("Python install manager") không có ô này: cứ cài bình thường — lệnh `py` ở dưới vẫn dùng
   được.
3. Mở thư mục `C:\CuuHo` trong File Explorer, **giữ Shift + bấm chuột phải** vào chỗ trống → *Open
   PowerShell window here* (Windows 11: chuột phải → *Open in Terminal*). Cài hai thư viện (một lần, cần
   mạng):
   ```powershell
   py -m pip install pynacl argon2-cffi
   ```
4. Giải mã (thay đường dẫn bằng đường dẫn file kho của bạn; công cụ hỏi master password, gõ không hiện ra):
   ```powershell
   py pwv_recover.py "G:\My Drive\Passwords\vault.pwv" -o backup.json
   ```
   Muốn mở một bản sao lưu: trỏ tới file trong `vault.pwv.backups\` (tên có thời điểm, số lớn hơn là mới
   hơn). Thường dùng master password HIỆN TẠI (các bản có từ trước một lần đổi mật khẩu đã được mã hoá
   lại bằng mật khẩu mới); chỉ các bản app đã cất với tên `oldkey-…` (hoặc bản ghi bởi một máy chưa nhận
   mật khẩu mới) mới cần mật khẩu CŨ của lúc đó. Trong `backup.json`: `entries` là các mục, `trash` là
   thùng rác.

⚠ `backup.json` chứa toàn bộ mật khẩu ở dạng rõ — xoá ngay sau khi dùng (và dọn Thùng rác). Luôn dùng
`-o` (đừng dùng `> backup.json`: trên Windows cách đó làm hỏng các ký tự có dấu); công cụ không ghi đè
file đã có. Nếu công cụ in **CẢNH BÁO … dấu "pre_change"**: đó là bản sao lưu có từ TRƯỚC lần đổi master
password gần nhất — nội dung của nó có thể do người biết mật khẩu cũ ghi; hãy dùng một bản không có cảnh
báo này nếu còn, và nếu buộc phải dùng thì kiểm tra kỹ địa chỉ trang web và mật khẩu của các tài khoản
quan trọng.

## Giới hạn — những gì phần mềm KHÔNG bảo vệ được

- **Mã độc / keylogger đang chạy trên máy** khi bạn mở kho: không phần mềm quản lý mật khẩu nào chống được.
- **Máy đang mở khoá kho mà bị người khác dùng.** Hãy khoá app (Ctrl+L) khi rời máy; đừng tắt tự khoá.
  **Khoá màn hình Windows (Win+L) hoặc cho máy ngủ KHÔNG khoá pwv ngay** — bấm Ctrl+L trước. (Máy ngủ
  dậy thì app khoá, nhưng trong lúc ngủ kho vẫn đang mở trong bộ nhớ.)
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
  Họ cũng có thể đặt vào đó vài file giả làm app báo nhầm (ví dụ báo **sai mật khẩu** dù bạn gõ đúng
  mật khẩu hiện tại, khi file kho đã bị một máy chưa nhận mật khẩu mới ghi đè; hoặc báo "mật khẩu cũ"
  khi khôi phục) — dữ liệu không mất, nhưng đừng vì thế mà gõ một mật khẩu cũ.
  Lịch sử phiên bản / thùng rác của dịch vụ đồng bộ là lớp dự phòng cuối cùng. Vì vậy hãy bảo vệ tài
  khoản cloud bằng mật khẩu mạnh và xác thực hai bước.
- **Máy mới cài không phát hiện được kho giả mạo.** Cảnh báo "kho này không nối tiếp từ kho máy này
  dùng lần trước" chỉ có trên máy đã từng mở kho thật. Trên máy mới cài (hoặc điện thoại), nếu bạn gõ
  một master password CŨ và thư mục đồng bộ đã bị người biết mật khẩu cũ thay file kho, app mở ra kho
  của họ mà không cảnh báo gì. Quy tắc: sau khi đổi master password, đừng bao giờ gõ lại mật khẩu cũ.
- **Master password yếu.** Ai lấy được file kho đều có thể thử mật khẩu ngoại tuyến; Argon2id chỉ
  làm việc đó chậm đi. Cụm 6 từ ngẫu nhiên là đủ an toàn; tên + năm sinh thì không — và app không phải
  lúc nào cũng nhận ra (xem *Master password* ở trên).
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
8. **Tự khoá khi đang sửa dở:** mở một mục, bấm *Sửa*, gõ thử vào ghi chú, rồi để yên cho tới khi app
   tự khoá (Cài đặt có thể đặt 1 phút cho lần thử). Mở khoá: form phải tự mở lại với đúng chữ vừa gõ.
   Bấm *Bỏ thay đổi*.
9. **Khôi phục trên màn hình mở khoá** (chỉ với KHO THỬ, ví dụ `thu.pwv`): khoá và đóng app; chép
   `thu.pwv` ra một chỗ khác để phòng hờ. Mở PowerShell tại thư mục của kho thử và gõ
   `Set-Content .\thu.pwv "hong"` (ghi đè file kho THỬ bằng chữ "hong"). Mở app, nhập mật khẩu → app báo
   "File kho bị hỏng hoặc chưa tải xong" → *Khôi phục từ bản sao lưu*: kho phải về đủ các mục.
10. **Bản lưu riêng** (KHO THỬ): đóng app; đổi tên file kho thử (ví dụ `thu.pwv` → `thu-x.pwv`) rồi
    chuyển file đó ra khỏi thư mục. Mở app → "Không tìm thấy file kho" phải có dòng "Máy này còn giữ
    một bản lưu riêng của kho" → *Tạo lại file kho từ bản lưu riêng* → mở khoá: đủ các mục.
11. **Công cụ cứu hộ:** làm theo *Cứu hộ dữ liệu không cần app* với file kho thử và với MỘT file trong
    thư mục sao lưu của nó (dùng `-o`): mở `backup.json` bằng Notepad, chữ có dấu phải hiện đúng. Xoá
    `backup.json`.
12. **Trong lúc nâng cấp lên 0.2.0:** sau khi đã cập nhật máy đầu tiên, trên máy đó **sửa và lưu một
    mục thử** (chỉ mở kho thì file chưa đổi định dạng). Rồi mở kho trên một máy CHƯA cập nhật: nó phải
    báo "hãy cập nhật phần mềm" (chứ không mở hay sửa được file). Rồi cập nhật máy đó.

**Android**
1. Cài APK, chọn file kho từ Drive/Dropbox/OneDrive, mở khoá (mất 1–3 giây; nếu app báo không đủ bộ
   nhớ hoặc tự thoát thì điện thoại không đủ RAM cho bước dẫn xuất khoá 256 MiB).
2. Thử chụp màn hình khi đang xem một mục: phải bị chặn; trong màn hình "Ứng dụng gần đây" nội dung
   phải bị che.
3. Sao chép mật khẩu: khung xem trước clipboard không hiện mật khẩu; ở yên trong pwv 20 giây rồi dán
   thử: trống. Lần nữa: sao chép, chuyển ngay sang app khác, chờ hơn 20 giây rồi dán — nếu vẫn còn mật
   khẩu thì điện thoại của bạn đóng băng pwv khi nằm nền (xem mục *Android* ở trên): hãy luôn quay lại
   pwv sau khi dán.
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
   build bộ cài Windows + `pwv.exe` (dòng lệnh) + APK Android, rồi tạo bản phát hành `v0.2.1` kèm
   công cụ cứu hộ `pwv_recover.py` và `SHA256SUMS.txt` (mã băm của mọi file trên).
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
