//! Các thao tác mật mã. KHÔNG tự viết thuật toán — chỉ ghép các thư viện RustCrypto:
//! Argon2id (KDF), HKDF-SHA256 (tách khoá), XChaCha20-Poly1305 (AEAD).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub type Key = Zeroizing<[u8; KEY_LEN]>;

/// Ngữ cảnh HKDF để từ master key sinh ra KEK.
const HKDF_INFO_KEK: &[u8] = b"pwv/v1/key-encryption-key";

/// Tham số Argon2id. Được lưu trong header để có thể tăng dần theo thời gian.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Bộ nhớ, đơn vị KiB.
    pub m_kib: u32,
    /// Số vòng lặp.
    pub t: u32,
    /// Số luồng song song.
    pub p: u32,
}

impl KdfParams {
    /// Mặc định: 256 MiB, 3 vòng, 4 luồng (~0,5–1 giây trên máy Windows phổ thông).
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 256 * 1024,
        t: 3,
        p: 4,
    };
    /// Mức tối thiểu chấp nhận khi tạo và khi mở kho (chặn file bị sửa để hạ tham số xuống thấp).
    /// Mức này cao hơn mức tối thiểu của OWASP (19 MiB, t=2).
    pub const MINIMUM: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 2,
        p: 1,
    };
    /// Giới hạn trên khi đọc file: chống file bị sửa để bắt máy chạy Argon2 hàng giờ / hàng chục GB.
    pub const MAXIMUM_M_KIB: u32 = 1024 * 1024;
    pub const MAXIMUM_T: u32 = 16;
    pub const MAXIMUM_P: u32 = 16;

    /// CHỈ dùng trong test: tham số rất thấp cho chạy nhanh.
    #[doc(hidden)]
    pub const INSECURE_TEST: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    pub(crate) fn validate(&self, allow_insecure: bool) -> Result<()> {
        if self.m_kib > Self::MAXIMUM_M_KIB
            || self.t == 0
            || self.t > Self::MAXIMUM_T
            || self.p == 0
            || self.p > Self::MAXIMUM_P
        {
            return Err(Error::InvalidKdfParams);
        }
        if !allow_insecure && (self.m_kib < Self::MINIMUM.m_kib || self.t < Self::MINIMUM.t) {
            return Err(Error::InvalidKdfParams);
        }
        Ok(())
    }
}

/// Chuẩn hoá master password trước khi đưa vào KDF.
///
/// Cùng một chữ tiếng Việt có thể được bàn phím gõ ra ở dạng dựng sẵn (NFC, ví dụ "ế" là 1 ký tự)
/// hoặc dạng tổ hợp (NFD, "e" + dấu mũ + dấu sắc) — nhìn giống hệt nhau nhưng khác byte, nên máy này
/// tạo kho, máy kia gõ đúng mà vẫn bị báo sai mật khẩu. Vì vậy mật khẩu luôn được đưa về NFC.
///
/// Trả về các phương án cần thử khi MỞ kho, theo thứ tự: NFC, nguyên văn (kho tạo bởi bản ≤ 0.1.2
/// không chuẩn hoá), NFD. Với mật khẩu ASCII cả ba trùng nhau ⇒ chỉ có một phương án.
/// Khi TẠO kho / ĐỔI mật khẩu luôn dùng phương án đầu tiên.
pub fn password_candidates(password: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    use unicode_normalization::UnicodeNormalization;
    let mut out: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(3);
    let mut push = |v: Zeroizing<Vec<u8>>| {
        if !out.iter().any(|x| **x == *v) {
            out.push(v);
        }
    };
    match std::str::from_utf8(password) {
        Ok(s) => {
            push(Zeroizing::new(s.nfc().collect::<String>().into_bytes()));
            push(Zeroizing::new(password.to_vec()));
            push(Zeroizing::new(s.nfd().collect::<String>().into_bytes()));
        }
        // Không phải UTF-8 hợp lệ (chỉ xảy ra khi gọi từ code, không phải từ bàn phím): dùng nguyên văn.
        Err(_) => push(Zeroizing::new(password.to_vec())),
    }
    out
}

/// Dạng chuẩn (NFC) của master password — dùng khi tạo kho / đổi mật khẩu.
pub fn normalized_password(password: &[u8]) -> Zeroizing<Vec<u8>> {
    password_candidates(password).swap_remove(0)
}

/// Argon2id(password, salt) → master key 32 byte, rồi HKDF → KEK.
pub fn derive_kek(password: &[u8], salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Key> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|_| Error::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, master.as_mut())
        .map_err(|_| Error::InvalidKdfParams)?;

    let hk = Hkdf::<Sha256>::new(None, master.as_ref());
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_INFO_KEK, kek.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(kek)
}

pub fn random_key() -> Key {
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(k.as_mut());
    k
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut s);
    s
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn seal(key: &Key, nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)
}

/// Giải mã + xác thực. Sai khoá hoặc dữ liệu bị sửa ⇒ `Error::Decrypt`.
pub fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic_and_salted() {
        let p = KdfParams::INSECURE_TEST;
        let s1 = [1u8; SALT_LEN];
        let s2 = [2u8; SALT_LEN];
        let a = derive_kek(b"pw", &s1, &p).unwrap();
        let b = derive_kek(b"pw", &s1, &p).unwrap();
        let c = derive_kek(b"pw", &s2, &p).unwrap();
        let d = derive_kek(b"pW", &s1, &p).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
    }

    /// Test vector cố định: nếu thư viện/thiết kế thay đổi ngoài ý muốn, test này sẽ báo.
    #[test]
    fn kdf_known_answer() {
        let kek = derive_kek(
            b"correct horse battery staple",
            &[0x42; SALT_LEN],
            &KdfParams {
                m_kib: 64,
                t: 2,
                p: 1,
            },
        )
        .unwrap();
        let hex: String = kek.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, include_str!("../tests/vectors/kek_v1.txt").trim());
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let k = random_key();
        let n = random_nonce();
        let ct = seal(&k, &n, b"secret", b"aad").unwrap();
        assert_eq!(&**open(&k, &n, &ct, b"aad").unwrap(), b"secret");
        assert!(matches!(open(&k, &n, &ct, b"aaX"), Err(Error::Decrypt)));
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(matches!(open(&k, &n, &bad, b"aad"), Err(Error::Decrypt)));
        assert!(matches!(
            open(&random_key(), &n, &ct, b"aad"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn param_validation() {
        assert!(KdfParams::DEFAULT.validate(false).is_ok());
        assert!(KdfParams::INSECURE_TEST.validate(false).is_err());
        assert!(KdfParams::INSECURE_TEST.validate(true).is_ok());
        let huge = KdfParams {
            m_kib: u32::MAX,
            t: 1,
            p: 1,
        };
        assert!(huge.validate(true).is_err());
        // File bị sửa để bắt chạy Argon2 rất lâu / rất nhiều RAM cũng bị từ chối.
        for bad in [
            KdfParams {
                m_kib: 2 * 1024 * 1024,
                t: 3,
                p: 4,
            },
            KdfParams {
                m_kib: 262_144,
                t: 100,
                p: 4,
            },
            KdfParams {
                m_kib: 262_144,
                t: 0,
                p: 4,
            },
            KdfParams {
                m_kib: 262_144,
                t: 3,
                p: 0,
            },
            KdfParams {
                m_kib: 262_144,
                t: 3,
                p: 64,
            },
        ] {
            assert!(bad.validate(true).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn password_is_normalized_to_nfc() {
        // "mật khẩu" gõ kiểu dựng sẵn (NFC) và kiểu tổ hợp (NFD) phải cho cùng một kết quả.
        let nfc = "m\u{1ead}t kh\u{1ea9}u";
        let nfd = "ma\u{323}\u{302}t kha\u{302}\u{309}u";
        assert_ne!(nfc.as_bytes(), nfd.as_bytes());
        assert_eq!(
            *normalized_password(nfc.as_bytes()),
            *normalized_password(nfd.as_bytes())
        );
        assert_eq!(*normalized_password(nfd.as_bytes()), nfc.as_bytes());
        // Gõ NFD: thử NFC trước, rồi nguyên văn (= NFD).
        let c = password_candidates(nfd.as_bytes());
        assert_eq!(c.len(), 2);
        assert_eq!(*c[0], nfc.as_bytes());
        assert_eq!(*c[1], nfd.as_bytes());
        // Gõ NFC: thử NFC, rồi NFD (kho cũ có thể được tạo bằng NFD).
        let c = password_candidates(nfc.as_bytes());
        assert_eq!(c.len(), 2);
        assert_eq!(*c[1], nfd.as_bytes());
        // ASCII: chỉ một phương án ⇒ không tốn thêm lần chạy Argon2 nào.
        assert_eq!(
            password_candidates(b"correct horse battery staple").len(),
            1
        );
        // Byte không phải UTF-8: giữ nguyên.
        assert_eq!(*password_candidates(&[0xff, 0xfe])[0], [0xff, 0xfe]);
    }
}
