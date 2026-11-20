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
    #[error("bản sao ở vị trí mới không đọc lại được — đã huỷ chuyển, kho cũ giữ nguyên")]
    MoveVerifyFailed,
    #[error("lỗi đọc/ghi file: {0}")]
    Io(#[from] std::io::Error),
    #[error("lỗi dữ liệu: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
