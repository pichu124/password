//! Lõi kho mật khẩu `pwv`.
//!
//! Thiết kế mật mã (xem `docs/FORMAT.md`):
//! ```text
//! master password + salt ─Argon2id─► master key ─HKDF-SHA256─► KEK
//! KEK ─XChaCha20-Poly1305─► mở gói vault_key (32 byte ngẫu nhiên)
//! vault_key ─XChaCha20-Poly1305─► toàn bộ dữ liệu kho (header làm AAD, đệm 4 KiB)
//! ```

pub mod config;
pub mod crypto;
pub mod error;
pub mod format;
pub mod fsutil;
pub mod import;
mod memlock;
pub mod model;
pub mod totp;
mod vault;

pub use config::Config;
pub use crypto::KdfParams;
pub use error::{Error, Result};
pub use model::{Entry, HistoryItem, MergeStats, VaultData};
pub use totp::{Totp, TotpError};
pub use vault::{CreateOptions, MoveReport, SaveReport, Vault};
