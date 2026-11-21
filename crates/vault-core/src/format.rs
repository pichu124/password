//! Định dạng file kho `.pwv`. Đặc tả đầy đủ: `docs/FORMAT.md`.
//!
//! Phiên bản 2 (bản app ≥ 0.2) giữ nguyên khung nhị phân của phiên bản 1, chỉ khác nội dung JSON
//! bên trong phần mã hoá (thêm thời điểm từng trường, thùng rác, khoá cũ). Bản app cũ gặp số
//! phiên bản 2 sẽ từ chối mở thay vì âm thầm làm mất các trường mới.
//!
//! ```text
//! offset  size  nội dung
//! 0       4     magic  "PWV1"
//! 4       2     version (u16 LE) = 2 (đọc được cả 1)
//! 6       4     header_len (u32 LE)
//! 10      N     header (JSON UTF-8, không bí mật nhưng được xác thực)
//! 10+N    24    body_nonce
//! 34+N    ...   body_ciphertext = XChaCha20-Poly1305(vault_key, body_nonce,
//!                                   plaintext = padded(body), aad = bytes[0 .. 10+N])
//! ```

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, Key, KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::model::VaultData;

pub const MAGIC: &[u8; 4] = b"PWV1";
/// Phiên bản định dạng mà bản app này GHI ra.
pub const VERSION: u16 = 2;
/// Phiên bản cũ nhất còn ĐỌC được.
pub const MIN_VERSION: u16 = 1;
const PREFIX_LEN: usize = 10;
const MAX_HEADER_LEN: usize = 64 * 1024;
/// Thân kho được đệm lên bội số của kích thước này để không lộ số lượng mục.
pub const PAD_BLOCK: usize = 4096;

/// Phần header (không bí mật). Mọi trường đều được xác thực vì nằm trong AAD của body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    /// Định danh ngẫu nhiên của kho — dùng để nhận ra bản sao/bản xung đột của cùng một kho.
    pub vault_id: String,
    pub kdf: KdfParams,
    #[serde(with = "b64_array")]
    pub salt: [u8; SALT_LEN],
    #[serde(with = "b64_array")]
    pub key_nonce: [u8; NONCE_LEN],
    /// vault_key được mã hoá bằng KEK (dẫn xuất từ master password).
    #[serde(with = "b64_vec")]
    pub wrapped_key: Vec<u8>,
    /// Lần đổi master password cuối (ms). Khi đồng bộ, header mới hơn được giữ lại.
    pub key_changed_at: i64,
}

impl Header {
    /// Hai header dùng chung một "gói khoá": cùng kho, cùng tham số KDF, cùng muối và cùng khoá đã
    /// gói ⇒ cùng một master password mở ra cùng một khoá kho, bất kể `key_changed_at` (trường này
    /// không tham gia việc mở gói và chỉ được xác thực khi phần thân của file giải mã được).
    pub fn same_wrap(&self, other: &Header) -> bool {
        self.vault_id == other.vault_id
            && self.kdf == other.kdf
            && self.salt == other.salt
            && self.key_nonce == other.key_nonce
            && self.wrapped_key == other.wrapped_key
    }

    fn wrap_aad(vault_id: &str) -> Vec<u8> {
        let mut aad = b"pwv/v1/wrap:".to_vec();
        aad.extend_from_slice(vault_id.as_bytes());
        aad
    }

    /// Tạo header mới: sinh salt, dẫn xuất KEK, gói vault_key.
    /// Master password được chuẩn hoá Unicode (NFC) trước khi dùng.
    pub fn new_wrapped(
        vault_id: String,
        password: &[u8],
        kdf: KdfParams,
        vault_key: &Key,
        key_changed_at: i64,
    ) -> Result<Header> {
        let password = crypto::normalized_password(password);
        let salt = crypto::random_salt();
        let kek = crypto::derive_kek(&password, &salt, &kdf)?;
        let key_nonce = crypto::random_nonce();
        let wrapped_key = crypto::seal(
            &kek,
            &key_nonce,
            vault_key.as_ref(),
            &Self::wrap_aad(&vault_id),
        )?;
        Ok(Header {
            vault_id,
            kdf,
            salt,
            key_nonce,
            wrapped_key,
            key_changed_at,
        })
    }

    /// Mở gói vault_key bằng master password.
    ///
    /// Tham số Argon2 trong file được kiểm tra TRƯỚC khi chạy: quá lớn (file bị sửa để làm treo
    /// máy) hoặc quá yếu đều bị từ chối. `allow_weak_kdf` chỉ dành cho test.
    pub fn unwrap_key(&self, password: &[u8], allow_weak_kdf: bool) -> Result<Key> {
        self.kdf.validate(allow_weak_kdf)?;
        if self.wrapped_key.len() != KEY_LEN + TAG_LEN {
            return Err(Error::BadFormat);
        }
        // Thử dạng chuẩn NFC trước; kho tạo bởi bản cũ có thể dùng nguyên văn hoặc NFD.
        for candidate in crypto::password_candidates(password) {
            let kek = crypto::derive_kek(&candidate, &self.salt, &self.kdf)?;
            match crypto::open(
                &kek,
                &self.key_nonce,
                &self.wrapped_key,
                &Self::wrap_aad(&self.vault_id),
            ) {
                Ok(raw) => {
                    let mut key = Zeroizing::new([0u8; KEY_LEN]);
                    key.copy_from_slice(&raw);
                    return Ok(key);
                }
                Err(Error::Decrypt) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Decrypt)
    }
}

/// File đã tách phần nhưng chưa giải mã body.
pub struct RawFile<'a> {
    /// Phiên bản định dạng ghi trong file (1 hoặc 2).
    pub version: u16,
    pub header: Header,
    /// bytes[0 .. 10+N] — dùng làm AAD.
    pub aad: &'a [u8],
    pub body_nonce: [u8; NONCE_LEN],
    pub body_ct: &'a [u8],
}

/// Kiểm tra phần đầu file và trả về (phiên bản, vị trí kết thúc header).
fn parse_prefix(bytes: &[u8]) -> Result<(u16, usize)> {
    if bytes.len() < PREFIX_LEN || &bytes[0..4] != MAGIC {
        return Err(Error::BadFormat);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if !(MIN_VERSION..=VERSION).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }
    let header_len = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(Error::BadFormat);
    }
    let header_end = PREFIX_LEN.checked_add(header_len).ok_or(Error::BadFormat)?;
    if bytes.len() < header_end {
        return Err(Error::BadFormat);
    }
    Ok((version, header_end))
}

/// Số byte đầu file đủ để đọc được header (dùng khi chỉ cần biết file thuộc kho nào).
pub const HEADER_PEEK_LEN: usize = PREFIX_LEN + MAX_HEADER_LEN;

/// Đọc riêng header (không bí mật, CHƯA được xác thực) từ phần đầu của một file kho.
/// Chỉ dùng để nhận diện file (vault_id, thời điểm đổi mật khẩu) — không tin nội dung cho tới khi
/// phần thân giải mã thành công.
pub fn peek_header(prefix: &[u8]) -> Result<Header> {
    let (_, header_end) = parse_prefix(prefix)?;
    serde_json::from_slice(&prefix[PREFIX_LEN..header_end]).map_err(|_| Error::BadFormat)
}

pub fn parse(bytes: &[u8]) -> Result<RawFile<'_>> {
    let (version, header_end) = parse_prefix(bytes)?;
    let body_start = header_end + NONCE_LEN;
    if bytes.len() < body_start + TAG_LEN {
        return Err(Error::BadFormat);
    }
    let header: Header =
        serde_json::from_slice(&bytes[PREFIX_LEN..header_end]).map_err(|_| Error::BadFormat)?;
    let mut body_nonce = [0u8; NONCE_LEN];
    body_nonce.copy_from_slice(&bytes[header_end..body_start]);
    Ok(RawFile {
        version,
        header,
        aad: &bytes[..header_end],
        body_nonce,
        body_ct: &bytes[body_start..],
    })
}

impl RawFile<'_> {
    /// Giải mã phần thân và đưa dữ liệu về dạng chuẩn (xem [`VaultData::normalize`]).
    pub fn decrypt_body(&self, vault_key: &Key) -> Result<VaultData> {
        let plain = crypto::open(vault_key, &self.body_nonce, self.body_ct, self.aad)?;
        if plain.len() < 4 {
            return Err(Error::BadFormat);
        }
        let len = u32::from_le_bytes(plain[0..4].try_into().unwrap()) as usize;
        if len > plain.len() - 4 {
            return Err(Error::BadFormat);
        }
        let mut data: VaultData = serde_json::from_slice(&plain[4..4 + len])?;
        data.normalize();
        Ok(data)
    }
}

/// Mã hoá toàn bộ kho thành bytes để ghi ra đĩa.
pub fn serialize(header: &Header, data: &VaultData, vault_key: &Key) -> Result<Vec<u8>> {
    let header_json = serde_json::to_vec(header)?;
    let mut out = Vec::with_capacity(PREFIX_LEN + header_json.len() + NONCE_LEN + PAD_BLOCK);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);

    let json = Zeroizing::new(serde_json::to_vec(data)?);
    let unpadded = 4 + json.len();
    let padded_len = unpadded.div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut plain = Zeroizing::new(Vec::with_capacity(padded_len));
    plain.extend_from_slice(&(json.len() as u32).to_le_bytes());
    plain.extend_from_slice(&json);
    plain.resize(padded_len, 0);

    let nonce = crypto::random_nonce();
    let ct = crypto::seal(vault_key, &nonce, &plain, &out)?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) mod b64_array {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};
    pub fn serialize<S: Serializer, const N: usize>(
        v: &[u8; N],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> std::result::Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s).map_err(D::Error::custom)?;
        v.try_into().map_err(|_| D::Error::custom("sai độ dài"))
    }
}

mod b64_vec {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(D::Error::custom)
    }
}
