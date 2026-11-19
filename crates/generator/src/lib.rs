//! Bộ tạo mật khẩu và passphrase an toàn.
//!
//! - Chỉ dùng CSPRNG của hệ điều hành (`OsRng`, trên Windows là `BCryptGenRandom`).
//! - Chọn ký tự bằng `gen_range`, vốn dùng rejection sampling ⇒ không có modulo bias.
//! - Khi bắt buộc mỗi nhóm ký tự xuất hiện ít nhất một lần, ta **sinh lại toàn bộ**
//!   mật khẩu cho tới khi đạt (rejection), thay vì "chèn" ký tự vào vị trí cố định —
//!   như vậy phân bố vẫn đều trên tập mật khẩu hợp lệ.

use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
/// Ký hiệu được hầu hết các trang web chấp nhận (bỏ dấu cách, nháy, backslash).
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";
/// Ký tự dễ nhầm khi đọc/gõ lại.
pub const AMBIGUOUS: &str = "0Oo1lI|[]{}()/\\'\"`~,;:.<>";

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 256;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 20;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenError {
    #[error("độ dài phải trong khoảng {MIN_LENGTH}–{MAX_LENGTH}")]
    InvalidLength,
    #[error("phải chọn ít nhất một nhóm ký tự")]
    NoCharset,
    #[error("độ dài nhỏ hơn số nhóm ký tự bắt buộc")]
    TooShortForRequiredClasses,
    #[error("số từ phải trong khoảng {MIN_WORDS}–{MAX_WORDS}")]
    InvalidWordCount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Loại bỏ các ký tự dễ nhầm như `0 O l 1 I`.
    pub exclude_ambiguous: bool,
    /// Mỗi nhóm đã chọn phải xuất hiện ít nhất một lần.
    pub require_each: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            require_each: true,
        }
    }
}

impl PasswordOptions {
    fn classes(&self) -> Vec<Vec<char>> {
        let mut out = Vec::new();
        for (enabled, set) in [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ] {
            if !enabled {
                continue;
            }
            let chars: Vec<char> = set
                .chars()
                .filter(|c| !(self.exclude_ambiguous && AMBIGUOUS.contains(*c)))
                .collect();
            if !chars.is_empty() {
                out.push(chars);
            }
        }
        out
    }

    /// Bảng ký tự cuối cùng (đã loại ký tự dễ nhầm nếu có).
    pub fn charset(&self) -> Vec<char> {
        self.classes().concat()
    }

    /// Entropy xấp xỉ (bit) = độ dài × log2(kích thước bảng ký tự).
    pub fn entropy_bits(&self) -> f64 {
        let n = self.charset().len();
        if n == 0 {
            return 0.0;
        }
        self.length as f64 * (n as f64).log2()
    }
}

/// Tạo mật khẩu ngẫu nhiên. Kết quả được bọc `Zeroizing` để tự xoá khỏi RAM khi drop.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>, GenError> {
    generate_password_with(opts, &mut OsRng)
}

/// Giống [`generate_password`] nhưng nhận RNG tuỳ ý (dùng cho test).
pub fn generate_password_with<R: Rng + ?Sized>(
    opts: &PasswordOptions,
    rng: &mut R,
) -> Result<Zeroizing<String>, GenError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&opts.length) {
        return Err(GenError::InvalidLength);
    }
    let classes = opts.classes();
    if classes.is_empty() {
        return Err(GenError::NoCharset);
    }
    if opts.require_each && opts.length < classes.len() {
        return Err(GenError::TooShortForRequiredClasses);
    }
    let charset: Vec<char> = classes.concat();

    loop {
        let mut pw = Zeroizing::new(String::with_capacity(opts.length * 4));
        for _ in 0..opts.length {
            pw.push(charset[rng.gen_range(0..charset.len())]);
        }
        if !opts.require_each
            || classes
                .iter()
                .all(|cls| pw.chars().any(|c| cls.contains(&c)))
        {
            return Ok(pw);
        }
    }
}

// ---------------------------------------------------------------------------
// Passphrase (Diceware, danh sách từ lớn của EFF: 7776 từ ≈ 12,9 bit/từ)
// ---------------------------------------------------------------------------

/// File gốc của EFF (https://www.eff.org/dice), SHA-256 =
/// `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`.
const EFF_LARGE_RAW: &str = include_str!("../data/eff_large_wordlist.txt");
pub const EFF_WORD_COUNT: usize = 7776;

/// Danh sách 7776 từ EFF.
pub fn eff_wordlist() -> &'static [&'static str] {
    use std::sync::OnceLock;
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        EFF_LARGE_RAW
            .lines()
            .filter_map(|l| l.split('\t').nth(1))
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect()
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    /// Viết hoa chữ cái đầu mỗi từ (không tăng entropy, chỉ để hợp quy định của trang web).
    pub capitalize: bool,
    /// Thêm một chữ số ngẫu nhiên vào cuối một từ ngẫu nhiên.
    pub add_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            capitalize: true,
            add_number: true,
        }
    }
}

impl PassphraseOptions {
    pub fn entropy_bits(&self) -> f64 {
        let mut bits = self.words as f64 * (EFF_WORD_COUNT as f64).log2();
        if self.add_number && self.words > 0 {
            bits += 10f64.log2() + (self.words as f64).log2();
        }
        bits
    }
}

pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>, GenError> {
    generate_passphrase_with(opts, &mut OsRng)
}

pub fn generate_passphrase_with<R: Rng + ?Sized>(
    opts: &PassphraseOptions,
    rng: &mut R,
) -> Result<Zeroizing<String>, GenError> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&opts.words) {
        return Err(GenError::InvalidWordCount);
    }
    let list = eff_wordlist();
    let number_at = opts.add_number.then(|| rng.gen_range(0..opts.words));
    let mut out = Zeroizing::new(String::new());
    for i in 0..opts.words {
        if i > 0 {
            out.push_str(&opts.separator);
        }
        let word = list[rng.gen_range(0..list.len())];
        if opts.capitalize {
            let mut cs = word.chars();
            if let Some(first) = cs.next() {
                out.extend(first.to_uppercase());
                out.push_str(cs.as_str());
            }
        } else {
            out.push_str(word);
        }
        if number_at == Some(i) {
            out.push(char::from(b'0' + rng.gen_range(0..10u8)));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Đánh giá độ mạnh (zxcvbn) — dùng cho mật khẩu người dùng tự nhập.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Strength {
    /// 0 (rất yếu) – 4 (rất mạnh).
    pub score: u8,
    /// log10 số lần đoán ước tính.
    pub guesses_log10: f64,
    pub label: &'static str,
}

pub fn estimate_strength(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength {
            score: 0,
            guesses_log10: 0.0,
            label: label_for(0),
        };
    }
    let e = zxcvbn::zxcvbn(password, user_inputs);
    let score = u8::from(e.score());
    Strength {
        score,
        guesses_log10: e.guesses_log10(),
        label: label_for(score),
    }
}

fn label_for(score: u8) -> &'static str {
    match score {
        0 => "Rất yếu",
        1 => "Yếu",
        2 => "Trung bình",
        3 => "Mạnh",
        _ => "Rất mạnh",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sha2::{Digest, Sha256};

    #[test]
    fn eff_wordlist_is_authentic() {
        let digest = Sha256::digest(EFF_LARGE_RAW.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        let list = eff_wordlist();
        assert_eq!(list.len(), EFF_WORD_COUNT);
        let mut sorted = list.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), EFF_WORD_COUNT, "từ bị trùng");
    }

    #[test]
    fn default_password_has_all_classes() {
        for _ in 0..200 {
            let pw = generate_password(&PasswordOptions::default()).unwrap();
            assert_eq!(pw.chars().count(), 20);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn exclude_ambiguous_works() {
        let opts = PasswordOptions {
            exclude_ambiguous: true,
            length: 64,
            ..Default::default()
        };
        for _ in 0..200 {
            let pw = generate_password(&opts).unwrap();
            assert!(!pw.chars().any(|c| AMBIGUOUS.contains(c)), "{}", *pw);
        }
    }

    #[test]
    fn rejects_invalid_options() {
        let mut o = PasswordOptions {
            length: 2,
            ..Default::default()
        };
        assert_eq!(generate_password(&o), Err(GenError::InvalidLength));
        o.length = 16;
        o.lowercase = false;
        o.uppercase = false;
        o.digits = false;
        o.symbols = false;
        assert_eq!(generate_password(&o), Err(GenError::NoCharset));
        let p = PassphraseOptions {
            words: 1,
            ..Default::default()
        };
        assert_eq!(generate_passphrase(&p), Err(GenError::InvalidWordCount));
    }

    /// Kiểm định chi-bình phương: mọi ký tự phải xuất hiện với tần suất đều.
    #[test]
    fn character_distribution_is_uniform() {
        let opts = PasswordOptions {
            length: 100,
            require_each: false,
            ..Default::default()
        };
        let charset = opts.charset();
        let k = charset.len();
        let mut rng = StdRng::seed_from_u64(42);
        let mut counts = std::collections::HashMap::new();
        let samples = 2000;
        for _ in 0..samples {
            for c in generate_password_with(&opts, &mut rng).unwrap().chars() {
                *counts.entry(c).or_insert(0usize) += 1;
            }
        }
        let n = (samples * opts.length) as f64;
        let expected = n / k as f64;
        let chi2: f64 = charset
            .iter()
            .map(|c| {
                let o = *counts.get(c).unwrap_or(&0) as f64;
                (o - expected).powi(2) / expected
            })
            .sum();
        // k-1 = 88 bậc tự do; ngưỡng p=0.001 ≈ 135.
        assert!(chi2 < 135.0, "chi2 = {chi2}");
    }

    #[test]
    fn passphrase_shape_and_entropy() {
        let opts = PassphraseOptions::default();
        let pp = generate_passphrase(&opts).unwrap();
        let parts: Vec<&str> = pp.split('-').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(
            parts
                .iter()
                .filter(|p| p.chars().any(|c| c.is_ascii_digit()))
                .count(),
            1
        );
        assert!(parts
            .iter()
            .all(|p| p.chars().next().unwrap().is_uppercase()));
        assert!(opts.entropy_bits() > 77.0);
    }

    #[test]
    fn entropy_estimates() {
        let o = PasswordOptions::default(); // 20 ký tự, 89 ký hiệu
        assert!((o.entropy_bits() - 20.0 * 89f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn strength_estimation() {
        assert!(estimate_strength("password", &[]).score <= 1);
        let strong = generate_password(&PasswordOptions::default()).unwrap();
        assert_eq!(estimate_strength(&strong, &[]).score, 4);
    }
}
