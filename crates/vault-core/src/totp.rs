//! Mã xác thực 2 bước TOTP (RFC 6238) — tương thích Google Authenticator, Microsoft
//! Authenticator, Authy... Nhận URI `otpauth://totp/...` hoặc secret base32 thuần.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("secret TOTP không phải base32 hợp lệ")]
    BadSecret,
    #[error("URI otpauth không hợp lệ")]
    BadUri,
    #[error("chỉ hỗ trợ TOTP (không hỗ trợ HOTP)")]
    NotTotp,
    #[error("tham số TOTP không được hỗ trợ: {0}")]
    Unsupported(String),
}

#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl Totp {
    /// Phân tích `otpauth://totp/Issuer:account?secret=...&issuer=...` hoặc secret base32.
    pub fn parse(input: &str) -> Result<Totp, TotpError> {
        let input = input.trim();
        if input.len() >= 10 && input[..10].eq_ignore_ascii_case("otpauth://") {
            return Self::parse_uri(input);
        }
        Ok(Totp {
            secret: decode_base32(input)?,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
        })
    }

    fn parse_uri(uri: &str) -> Result<Totp, TotpError> {
        let rest = &uri[10..];
        let (kind, rest) = rest.split_once('/').ok_or(TotpError::BadUri)?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(TotpError::NotTotp);
        }
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label);
        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_string()), Some(a.trim().to_string())),
            None if label.is_empty() => (None, None),
            None => (None, Some(label.trim().to_string())),
        };

        let mut t = Totp {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: label_issuer,
            account,
        };
        let mut has_secret = false;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v);
            match k.to_ascii_lowercase().as_str() {
                "secret" => {
                    t.secret = decode_base32(&v)?;
                    has_secret = true;
                }
                "issuer" if !v.is_empty() => t.issuer = Some(v),
                "algorithm" => {
                    t.algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(TotpError::Unsupported(format!("algorithm={v}"))),
                    }
                }
                "digits" => {
                    t.digits = v.parse().map_err(|_| TotpError::BadUri)?;
                    if !(6..=10).contains(&t.digits) {
                        return Err(TotpError::Unsupported(format!("digits={v}")));
                    }
                }
                "period" => {
                    t.period = v.parse().map_err(|_| TotpError::BadUri)?;
                    if !(1..=3600).contains(&t.period) {
                        return Err(TotpError::Unsupported(format!("period={v}")));
                    }
                }
                _ => {}
            }
        }
        if !has_secret {
            return Err(TotpError::BadSecret);
        }
        Ok(t)
    }

    /// Mã tại thời điểm `unix_secs`.
    pub fn code_at(&self, unix_secs: u64) -> String {
        let counter = (unix_secs / self.period).to_be_bytes();
        let digest: Vec<u8> = match self.algorithm {
            Algorithm::Sha1 => hmac_digest::<Hmac<sha1::Sha1>>(&self.secret, &counter),
            Algorithm::Sha256 => hmac_digest::<Hmac<sha2::Sha256>>(&self.secret, &counter),
            Algorithm::Sha512 => hmac_digest::<Hmac<sha2::Sha512>>(&self.secret, &counter),
        };
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        let modulus = 10u64.pow(self.digits);
        format!(
            "{:0width$}",
            bin as u64 % modulus,
            width = self.digits as usize
        )
    }

    /// Mã hiện tại và số giây còn hiệu lực.
    pub fn now(&self) -> (String, u64) {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (self.code_at(secs), self.period - secs % self.period)
    }
}

fn hmac_digest<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC nhận khoá mọi độ dài");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Giải mã base32 (RFC 4648), bỏ qua dấu cách/gạch nối, không phân biệt hoa thường, padding tuỳ chọn.
fn decode_base32(s: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8));
    let (mut buf, mut bits) = (0u64, 0u32);
    let mut seen = 0usize;
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            'a'..='z' => c as u64 - 'a' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            ' ' | '-' | '=' => continue,
            _ => return Err(TotpError::BadSecret),
        };
        seen += 1;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    // Secret quá ngắn (< 80 bit) gần như chắc chắn là nhập sai.
    if seen < 16 {
        return Err(TotpError::BadSecret);
    }
    Ok(out)
}

fn percent_decode(s: &str) -> String {
    fn hex(c: u8) -> Option<u8> {
        (c as char).to_digit(16).map(|d| d as u8)
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0);
        for &x in bytes {
            buf = (buf << 8) | x as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(A[((buf >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    /// Test vector chính thức, RFC 6238 phụ lục B (8 chữ số).
    #[test]
    fn rfc6238_vectors() {
        let s1 = b32(b"12345678901234567890");
        let s256 = b32(b"12345678901234567890123456789012");
        let s512 = b32(b"1234567890123456789012345678901234567890123456789012345678901234");
        let cases: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (secs, e1, e256, e512) in cases {
            for (secret, alg, exp) in [
                (&s1, "SHA1", e1),
                (&s256, "SHA256", e256),
                (&s512, "SHA512", e512),
            ] {
                let t = Totp::parse(&format!(
                    "otpauth://totp/Test?secret={secret}&algorithm={alg}&digits=8"
                ))
                .unwrap();
                assert_eq!(&t.code_at(*secs), exp, "{alg} @ {secs}");
            }
        }
    }

    #[test]
    fn parses_google_authenticator_uri() {
        let t = Totp::parse(
            "otpauth://totp/Google%3Atoi%40gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google",
        )
        .unwrap();
        assert_eq!(t.issuer.as_deref(), Some("Google"));
        assert_eq!(t.account.as_deref(), Some("toi@gmail.com"));
        assert_eq!((t.digits, t.period, t.algorithm), (6, 30, Algorithm::Sha1));
        assert_eq!(t.code_at(0).len(), 6);
    }

    #[test]
    fn plain_secret_with_spaces() {
        let a = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        let b = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(a.code_at(1_700_000_000), b.code_at(1_700_000_000));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(
            Totp::parse("not base32!").unwrap_err(),
            TotpError::BadSecret
        );
        assert_eq!(Totp::parse("ABC").unwrap_err(), TotpError::BadSecret);
        assert_eq!(
            Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").unwrap_err(),
            TotpError::NotTotp
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?issuer=a").unwrap_err(),
            TotpError::BadSecret
        );
        assert!(Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=3").is_err());
        // Không panic với chuỗi % cụt.
        assert!(Totp::parse("otpauth://totp/a%2?secret=JBSWY3DPEHPK3PXP").is_ok());
        assert!(Totp::parse("otpauth://totp/a%?secret=JBSWY3DPEHPK3PXP").is_ok());
        assert!(Totp::parse("otpauth://totp/%Ãé?secret=JBSWY3DPEHPK3PXP").is_ok());
    }

    #[test]
    fn remaining_seconds_in_range() {
        let t = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        let (code, left) = t.now();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&left));
    }
}
