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
