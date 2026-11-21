#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sai mật khẩu chính hoặc file kho đã bị sửa đổi")]
    Decrypt,
    #[error("lỗi mật mã")]
    Crypto,
    #[error("đây không phải file kho pwv hoặc file bị hỏng")]
    BadFormat,
    #[error("phiên bản định dạng {0} chưa được hỗ trợ — hãy cập nhật phần mềm")]
    UnsupportedVersion(u16),
    #[error("tham số Argon2 không hợp lệ hoặc quá yếu")]
    InvalidKdfParams,
    #[error("không đủ bộ nhớ để mở kho (cần khoảng {0} MB RAM trống) — hãy đóng bớt ứng dụng khác rồi thử lại")]
    OutOfMemory(u32),
    #[error("hai file không thuộc cùng một kho (vault_id khác nhau)")]
    DifferentVault,
    #[error("không tìm thấy mục {0}")]
    EntryNotFound(String),
    #[error("file kho đã tồn tại: {0}")]
    AlreadyExists(String),
    #[error("vị trí mới trùng với vị trí hiện tại")]
    SamePath,
    #[error("không thể đặt kho bên trong thư mục sao lưu của chính nó — hãy chọn thư mục khác")]
    MoveIntoBackups,
    #[error("bản sao ở vị trí mới không đọc lại được — đã huỷ chuyển, kho cũ giữ nguyên")]
    MoveVerifyFailed,
    #[error("kho đang mở ở chế độ chỉ đọc")]
    ReadOnly,
    /// File kho biến mất khỏi vị trí đã mở (bị chuyển/xoá trên máy khác, hoặc dịch vụ đồng bộ chưa tải về).
    #[error("không còn thấy file kho tại {0} — có thể kho đã được chuyển sang thư mục khác trên máy kia")]
    VaultFileMissing(String),
    /// File kho trên đĩa không đọc/giải mã được (đồng bộ dở, hỏng, bị sửa). Dữ liệu trong RAM vẫn nguyên.
    #[error("file kho trên đĩa đang hỏng hoặc chưa đồng bộ xong (không giải mã được)")]
    VaultFileDamaged,
    /// Thiết bị khác đã đổi master password: phải nhập mật khẩu mới để tiếp tục.
    #[error("mật khẩu chính đã được đổi trên thiết bị khác — hãy mở khoá lại bằng mật khẩu mới")]
    PasswordChangedElsewhere,
    #[error("ghi xong nhưng đọc lại không khớp — file kho có thể chưa được ghi đúng")]
    WriteVerifyFailed,
    /// Một bản cạnh kho (bản xung đột) chỉ mở được bằng khoá của mật khẩu chính CŨ. Ai biết mật
    /// khẩu cũ cũng làm ra được bản như vậy, nên nó không bao giờ được tự gộp vào kho.
    #[error(
        "bản này được ghi bằng mật khẩu chính CŨ nên không được tự gộp — đã cất vào thư mục sao lưu \
         để bạn xem lại"
    )]
    RetiredKeyCopy,
    /// Một bản cạnh kho dùng một khoá mà máy này không có, và nó ghi là được tạo SAU lần đổi mật
    /// khẩu chính mà máy này biết. Không làm gì với nó (có thể chỉ là file rác).
    #[error(
        "bản này được ghi bằng một mật khẩu chính khác (mới hơn) — nếu bạn vừa đổi mật khẩu chính trên \
         thiết bị khác, hãy khoá app rồi mở lại bằng mật khẩu MỚI; nếu không, hãy xoá file này"
    )]
    CopyUsesOtherPassword,
    /// Khôi phục từ sao lưu: mật khẩu vừa nhập chỉ mở được các bản sao lưu tạo TRƯỚC lần đổi mật
    /// khẩu chính gần nhất. Dựng lại kho từ chúng sẽ quay về mật khẩu cũ và mất các thay đổi sau đó.
    #[error(
        "mật khẩu này chỉ mở được các bản sao lưu tạo TRƯỚC lần đổi mật khẩu chính gần nhất — hãy nhập \
         mật khẩu chính HIỆN TẠI (mật khẩu bạn đặt gần đây nhất)"
    )]
    OlderPasswordBackups,
    #[error("lỗi đọc/ghi file: {0}")]
    Io(#[from] std::io::Error),
    /// Lưu ý: không kèm thông báo gốc của serde_json vì nó có thể trích lại dữ liệu trong kho.
    #[error("dữ liệu trong kho không đúng cấu trúc")]
    Json,
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::Json
    }
}

pub type Result<T> = std::result::Result<T, Error>;
