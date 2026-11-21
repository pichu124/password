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

/// Số ký tự tối thiểu của master password.
pub const MASTER_MIN_CHARS: usize = 12;
/// Số lần đoán tối thiểu (log10) mà zxcvbn ước tính cho master password.
///
/// Mức cũ ("điểm ≥ 3", tức chỉ khoảng 10^8 lần đoán) để lọt cả những mật khẩu kiểu "tên + năm sinh"
/// (`nguyenvanan1990`, `Matkhau@2024`, `Techcombank123`): zxcvbn không có từ điển tiếng Việt nên chấm
/// chúng như chuỗi ngẫu nhiên. Với 10^14 lần đoán, kẻ có file kho phải chạy Argon2id 256 MiB khoảng
/// 10^14 lần — hàng nghìn năm-GPU. Cụm 4 từ ngẫu nhiên từ bộ tạo đạt ≈ 10^15,6; 6 từ ≈ 10^23.
pub const MASTER_MIN_GUESSES_LOG10: f64 = 14.0;

/// Kết quả chấm master password.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MasterCheck {
    /// Đủ điều kiện làm master password.
    pub ok: bool,
    pub guesses_log10: f64,
    /// "Đạt" hoặc lý do chưa đạt (hiển thị cho người dùng).
    pub message: String,
}

/// Lý do từ chối khi master password chủ yếu ghép từ tên người, tên ngân hàng / dịch vụ và chữ số.
pub const MASTER_PERSONAL_MESSAGE: &str =
    "Mật khẩu này chủ yếu ghép từ tên người, tên ngân hàng/dịch vụ và chữ số — người biết bạn có \
     thể đoán được. Hãy dùng một cụm 5–6 từ ngẫu nhiên (bấm «Gợi ý»).";

/// Còn ít hơn chừng này chữ cái "không giải thích được" (không thuộc tên người, tên ngân hàng /
/// dịch vụ, địa danh) thì master password bị coi là ghép từ thông tin cá nhân.
pub const MASTER_MIN_FREE_LETTERS: usize = 6;

/// Chỉ áp dụng luật trên khi các tên tìm thấy dài từ 3 chữ cái trở lên phủ ít nhất chừng này chữ
/// cái: một mật khẩu ngẫu nhiên nhiều chữ số / ký hiệu (ít chữ cái, có thể tình cờ chứa `vu`, `le`,
/// `hua`) không phải là "tên + ngày sinh". (Thử với hàng triệu mật khẩu ngẫu nhiên từ 14 ký tự: mức
/// 6 vẫn từ chối nhầm vài cái, mức 8 thì không cái nào.)
const MASTER_MIN_PERSONAL_LETTERS: usize = 8;

/// Chấm một master password theo chính sách của pwv. Dùng chung cho app và CLI.
///
/// Ba luật, theo thứ tự: (1) ít nhất [`MASTER_MIN_CHARS`] ký tự; (2) không chủ yếu ghép từ tên
/// người Việt, tên ngân hàng / ví / nhà mạng / dịch vụ lớn, địa danh và chữ số (xem
/// [`personal_pattern_scan`] — zxcvbn không có từ điển tiếng Việt nên chấm những mật khẩu như
/// `tranvanbinh12031985` như chuỗi ngẫu nhiên); (3) zxcvbn ước tính ít nhất
/// 10^[`MASTER_MIN_GUESSES_LOG10`] lần đoán.
///
/// Chỉ dùng khi TẠO kho hoặc ĐỔI master password — không bao giờ khi mở kho, nên siết chính sách
/// không khoá ai khỏi kho đang có.
pub fn check_master_password(password: &str) -> MasterCheck {
    use unicode_normalization::UnicodeNormalization;
    // Kho mã hoá dạng NFC của master password (vault-core `normalized_password`): chấm ĐÚNG chuỗi
    // đó. Gõ bằng bàn phím tiếng Việt kiểu "Unicode tổ hợp" (dấu thanh rời) cho ra dạng NFD — trước
    // đây mỗi dấu rời cắt đôi một âm tiết (`Trần` thành `tra` + `n`) nên luật tên người không bắt
    // được, và độ dài bị đếm cả các dấu rời.
    let nfc: Zeroizing<String> = Zeroizing::new(password.nfc().collect());
    let password = nfc.as_str();
    let s = estimate_strength(password, master_user_inputs());
    let chars = password.chars().count();
    let personal = personal_pattern_scan(password).is_personal();
    let (ok, message) = if chars < MASTER_MIN_CHARS {
        (
            false,
            format!("Quá ngắn: cần ít nhất {MASTER_MIN_CHARS} ký tự (hiện {chars})."),
        )
    } else if personal {
        (false, MASTER_PERSONAL_MESSAGE.to_string())
    } else if s.guesses_log10 < MASTER_MIN_GUESSES_LOG10 {
        (
            false,
            "Quá dễ đoán (tên, ngày sinh, số điện thoại, từ quen thuộc… ghép lại rất dễ bị dò). \
             Hãy dùng một cụm 5–6 từ ngẫu nhiên, KHÔNG liên quan đến nhau (bộ tạo mật khẩu của pwv \
             tạo được cụm như vậy)."
                .to_string(),
        )
    } else {
        (true, "Đạt".to_string())
    };
    MasterCheck {
        ok,
        guesses_log10: s.guesses_log10,
        message,
    }
}

/// Từ "của pwv" luôn bị phạt, cộng các tên ngân hàng / dịch vụ / địa danh cho zxcvbn: từ 4 chữ cái
/// trở lên (âm tiết tên người thì quá ngắn — zxcvbn sẽ chia nhỏ cả từ tiếng Anh bình thường) và
/// không có trong danh sách EFF (để không hạ điểm passphrase do bộ tạo sinh ra, ví dụ `apple`).
fn master_user_inputs() -> &'static [&'static str] {
    use std::sync::OnceLock;
    static INPUTS: OnceLock<Vec<&'static str>> = OnceLock::new();
    INPUTS.get_or_init(|| {
        let mut v: Vec<&'static str> = vec!["pwv", "vault", "matkhau", "password", "master"];
        for w in VN_SERVICE_WORDS.iter().chain(VN_PLACE_WORDS) {
            if w.len() >= 4 && !v.contains(w) && !eff_wordlist().contains(w) {
                v.push(w);
            }
        }
        v
    })
}

/// Kết quả quét "mẫu cá nhân" của một mật khẩu (xem [`personal_pattern_scan`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PersonalScan {
    /// Chữ cái nằm trong một tên người / ngân hàng / dịch vụ / địa danh dài từ 3 chữ cái trở lên.
    pub personal_letters: usize,
    /// Chữ cái nằm trong một tên 2 chữ cái (`an`, `le`, `vu`, `mb`): giải thích được, nhưng không
    /// tính vào `personal_letters` (chuỗi ngẫu nhiên rất hay tình cờ chứa chúng).
    pub short_name_letters: usize,
    /// Chữ cái còn lại (không giải thích được).
    pub free_letters: usize,
    /// Tổng số chữ cái của các dãy chữ cái tách TRỌN VẸN được thành các từ trong danh sách (tên
    /// người kể cả tên 2 chữ cái, ngân hàng / dịch vụ, địa danh) — xem [`personal_pattern_scan`].
    pub explained_run_letters: usize,
    /// Số dãy chữ cái KHÔNG tách trọn vẹn được như vậy (kể cả dãy gồm toàn từ EFF, dãy dài quá
    /// [`MAX_SEGMENTED_RUN`] chữ cái, và mỗi chữ cái ngoài bảng a–z).
    pub unexplained_runs: usize,
}

/// Luật thứ hai: mọi dãy chữ cái đều ghép trọn vẹn từ tên / ngân hàng / địa danh, và chúng có tổng
/// cộng ít nhất chừng này chữ cái (`Le.Thi.Mai.1990`, `Vu.An.Ha@0912345678`). Ít chữ cái hơn ⇒ để
/// zxcvbn chấm.
pub const MASTER_MIN_EXPLAINED_RUN_LETTERS: usize = 5;

/// Dãy chữ cái dài hơn chừng này không được tách thử (coi là không giải thích được): chặn thời gian
/// chạy với đầu vào rất dài.
pub const MAX_SEGMENTED_RUN: usize = 64;

impl PersonalScan {
    /// Mật khẩu chủ yếu ghép từ thông tin cá nhân: các tên dài từ 3 chữ cái phủ ít nhất
    /// [`MASTER_MIN_PERSONAL_LETTERS`] chữ cái và còn lại ít hơn [`MASTER_MIN_FREE_LETTERS`] chữ
    /// cái tự do.
    ///
    /// Hoặc (luật thứ hai, theo cấu trúc): KHÔNG có dãy chữ cái nào ngoài các dãy tách trọn vẹn được
    /// thành tên / ngân hàng / dịch vụ / địa danh, và các dãy đó có ít nhất
    /// [`MASTER_MIN_EXPLAINED_RUN_LETTERS`] chữ cái.
    pub fn is_personal(&self) -> bool {
        self.mostly_personal() || self.only_personal_words()
    }

    /// Luật thứ nhất (tỉ lệ chữ cái).
    pub fn mostly_personal(&self) -> bool {
        self.personal_letters >= MASTER_MIN_PERSONAL_LETTERS
            && self.free_letters < MASTER_MIN_FREE_LETTERS
    }

    /// Luật thứ hai (mọi dãy chữ cái đều là tên / ngân hàng / địa danh).
    pub fn only_personal_words(&self) -> bool {
        self.unexplained_runs == 0 && self.explained_run_letters >= MASTER_MIN_EXPLAINED_RUN_LETTERS
    }
}

/// Quét mật khẩu (xác định, không ngẫu nhiên): chữ thường, bỏ dấu tiếng Việt (đ → d), rồi trong
/// mỗi dãy chữ cái liền nhau, từ trái sang phải, đánh dấu từ dài nhất khớp được trong các danh sách
/// tên người Việt (họ, tên đệm, tên), tên ngân hàng / ví điện tử / nhà mạng / dịch vụ lớn (và các
/// từ như `pwv`, `matkhau`, `password`), địa danh. Chữ số, ký hiệu, khoảng trắng luôn "giải thích
/// được" (không phải chữ cái). Chữ cái nào không thuộc từ nào là chữ cái tự do.
///
/// Ngoại lệ: một dãy chữ cái tách trọn vẹn được thành các từ của danh sách EFF (đúng những từ bộ
/// tạo passphrase dùng) là chữ cái tự do hết — các từ đó được chọn ngẫu nhiên, không phải thông tin
/// cá nhân, kể cả khi trong từ có một âm tiết trùng tên người (`manhandle`, `chosen`). TRỪ KHI chính
/// cả dãy là một từ trong danh sách: khoảng chục từ EFF cũng là tên dịch vụ / tên người (`google`,
/// `facebook`, `yahoo`, `banking`, `apple`, `yen`...) và vẫn bị tính là thông tin cá nhân
/// (`Google@TranVanBinh85`). Một passphrase do pwv tạo chỉ bị từ chối nếu hầu hết các từ của nó rơi
/// đúng vào nhóm chục từ đó — với 4 từ trở lên, xác suất cỡ 10⁻¹⁰.
///
/// Mật khẩu được tách dấu (NFD) và bỏ mọi dấu kết hợp trước khi quét, nên dạng dựng sẵn (NFC), dạng
/// dấu rời (NFD) và dạng trộn đều cho cùng kết quả.
///
/// Song song, mỗi dãy chữ cái được thử tách TRỌN VẸN (quy hoạch động, không chỉ tham lam) thành
/// các từ trong danh sách, kể cả tên 2 chữ cái: `lethimai` = le+thi+mai. Dãy tách được (và không
/// phải toàn từ EFF) cộng vào `explained_run_letters`; dãy không tách được, dãy toàn từ EFF, dãy dài
/// quá [`MAX_SEGMENTED_RUN`] chữ cái và mỗi chữ cái ngoài bảng a–z cộng vào `unexplained_runs`.
pub fn personal_pattern_scan(password: &str) -> PersonalScan {
    let dict = personal_dictionary();
    let mut scan = PersonalScan::default();
    let mut run: Vec<u8> = Vec::new();
    let flush = |run: &mut Vec<u8>, scan: &mut PersonalScan| {
        if run.is_empty() {
            return;
        }
        // Ngoại lệ EFF, trừ khi chính dãy đó là một từ trong danh sách (`google`, `facebook`,
        // `yahoo`, `banking`...: vừa là từ EFF vừa là tên dịch vụ).
        if !dict.words.contains(&run[..]) && dict.splits_into_eff_words(run) {
            scan.free_letters += run.len();
            scan.unexplained_runs += 1;
            run.clear();
            return;
        }
        if dict.splits_into_personal_words(run) {
            scan.explained_run_letters += run.len();
        } else {
            scan.unexplained_runs += 1;
        }
        let mut i = 0;
        while i < run.len() {
            let longest = (2..=dict.max_len.min(run.len() - i))
                .rev()
                .find(|&n| dict.words.contains(&run[i..i + n]));
            match longest {
                Some(n) if n >= 3 => {
                    scan.personal_letters += n;
                    i += n;
                }
                Some(n) => {
                    scan.short_name_letters += n;
                    i += n;
                }
                None => {
                    scan.free_letters += 1;
                    i += 1;
                }
            }
        }
        run.clear();
    };
    use unicode_normalization::char::is_combining_mark;
    use unicode_normalization::UnicodeNormalization;
    // Tách dấu (NFD) rồi bỏ mọi dấu kết hợp: `ầ`, `a` + dấu rời, hay `â` + dấu rời đều thành `a`.
    // `đ` không có dạng tách — `fold_vietnamese` lo.
    for c in password
        .nfd()
        .flat_map(char::to_lowercase)
        .filter(|c| !is_combining_mark(*c))
    {
        let c = fold_vietnamese(c);
        if c.is_ascii_lowercase() {
            run.push(c as u8);
        } else {
            flush(&mut run, &mut scan);
            if c.is_alphabetic() {
                // Chữ cái ngoài bảng a–z (chữ Hy Lạp, Cyrillic, chữ Hán...): không có trong từ điển.
                scan.free_letters += 1;
                scan.unexplained_runs += 1;
            }
        }
    }
    flush(&mut run, &mut scan);
    scan
}

/// Quy hoạch động: `run` có tách trọn vẹn được thành các từ trong `words` (từ dài tối đa `max_len`)
/// không. Thời gian O(độ dài × max_len).
fn splits_into(
    run: &[u8],
    words: &std::collections::HashSet<&'static [u8]>,
    max_len: usize,
) -> bool {
    if run.is_empty() {
        return false;
    }
    // reach[i]: run[..i] tách được.
    let mut reach = vec![false; run.len() + 1];
    reach[0] = true;
    for i in 0..run.len() {
        if !reach[i] {
            continue;
        }
        for n in 1..=max_len.min(run.len() - i) {
            if words.contains(&run[i..i + n]) {
                reach[i + n] = true;
            }
        }
    }
    reach[run.len()]
}

struct PersonalDictionary {
    words: std::collections::HashSet<&'static [u8]>,
    max_len: usize,
    eff: std::collections::HashSet<&'static [u8]>,
    eff_max_len: usize,
}

impl PersonalDictionary {
    /// `run` (chữ thường a–z) ghép trọn vẹn từ một hay nhiều từ EFF.
    fn splits_into_eff_words(&self, run: &[u8]) -> bool {
        splits_into(run, &self.eff, self.eff_max_len)
    }

    /// `run` (chữ thường a–z, tối đa [`MAX_SEGMENTED_RUN`] chữ cái) ghép trọn vẹn từ các tên người
    /// (kể cả tên 2 chữ cái), tên ngân hàng / dịch vụ, địa danh.
    fn splits_into_personal_words(&self, run: &[u8]) -> bool {
        run.len() <= MAX_SEGMENTED_RUN && splits_into(run, &self.words, self.max_len)
    }
}

fn personal_dictionary() -> &'static PersonalDictionary {
    use std::sync::OnceLock;
    static DICT: OnceLock<PersonalDictionary> = OnceLock::new();
    DICT.get_or_init(|| {
        let words: std::collections::HashSet<&'static [u8]> = VN_NAME_SYLLABLES
            .iter()
            .chain(VN_SERVICE_WORDS)
            .chain(VN_PLACE_WORDS)
            .map(|w| w.as_bytes())
            .filter(|w| w.len() >= 2)
            .collect();
        let max_len = words.iter().map(|w| w.len()).max().unwrap_or(0);
        let eff: std::collections::HashSet<&'static [u8]> =
            // "drop-down", "t-shirt"...: dấu gạch ngang tách thành hai dãy chữ cái.
            eff_wordlist()
                .iter()
                .flat_map(|w| std::iter::once(*w).chain(w.split('-')))
                .filter(|w| !w.is_empty())
                .map(str::as_bytes)
                .collect();
        let eff_max_len = eff.iter().map(|w| w.len()).max().unwrap_or(0);
        PersonalDictionary {
            words,
            max_len,
            eff,
            eff_max_len,
        }
    })
}

/// Bỏ dấu một chữ cái tiếng Việt (đã viết thường): `ằ` → `a`, `đ` → `d`, `ữ` → `u`...
fn fold_vietnamese(c: char) -> char {
    const GROUPS: [(&str, char); 7] = [
        ("àáảãạăằắẳẵặâầấẩẫậ", 'a'),
        ("èéẻẽẹêềếểễệ", 'e'),
        ("ìíỉĩị", 'i'),
        ("òóỏõọôồốổỗộơờớởỡợ", 'o'),
        ("ùúủũụưừứửữự", 'u'),
        ("ỳýỷỹỵ", 'y'),
        ("đ", 'd'),
    ];
    if c.is_ascii() {
        return c;
    }
    GROUPS
        .iter()
        .find(|(set, _)| set.contains(c))
        .map_or(c, |&(_, base)| base)
}

/// Họ, tên đệm và tên phổ biến của người Việt (viết thường, không dấu).
pub const VN_NAME_SYLLABLES: &[&str] = &[
    // Họ
    "nguyen", "tran", "le", "pham", "hoang", "huynh", "phan", "vu", "vo", "dang", "bui", "do", "ho",
    "ngo", "duong", "ly", "dinh", "doan", "trinh", "truong", "lam", "luong", "luu", "mai", "cao",
    "ha", "ta", "tang", "thai", "chau", "quach", "ton", "la", "kieu", "khuc", "giang", "mac",
    "hua", "trieu", "vuong", "tong", "phung", "kim", "diep", "nghiem", "lai", "thach", "khong",
    "bach", "tieu", "nong", "lo", "chu", "dao", "lieu", "ung", "ong", "khuat", "quan", "au", "lu",
    "cu", "kha", "thieu", "uong", "lang", "tiet", "ninh", "son", "ma", "doan",
    // Tên đệm và tên
    "van", "thi", "huu", "duc", "cong", "quang", "dinh", "xuan", "thanh", "minh", "ngoc", "gia",
    "bao", "anh", "an", "binh", "hung", "hoa", "hai", "hanh", "hien", "hieu", "hoai", "hong",
    "hue", "huong", "huy", "khanh", "khoa", "kien", "lan", "linh", "loan", "long", "my", "nam",
    "nga", "ngan", "nhan", "nhung", "phong", "phuc", "phuong", "quoc", "quyen", "tam", "tan",
    "thao", "thang", "thinh", "thu", "thuy", "tien", "trang", "trung", "tuan", "tung", "tuyet",
    "uyen", "viet", "vinh", "yen", "cuong", "chi", "dung", "dat", "diem", "dieu", "hau", "hiep",
    "hoan", "khang", "khai", "loc", "luan", "man", "nhi", "nhu", "phat", "phu", "quy", "sang",
    "tai", "thien", "thong", "thuan", "ti", "toan", "truc", "tu", "tue", "tuong", "vy", "duy",
    "hao", "dong", "nhat", "nhien", "nguyet", "tuyen", "chinh", "dai", "dien", "doanh", "giao",
    "han", "hang", "hop", "khiem", "khue", "lap", "lien", "loi", "luyen", "mien", "mong", "nghia",
    "phi", "phuoc", "quynh", "sinh", "suong", "tham", "thoa", "thom", "thuong", "tin", "tinh",
    "trai", "tram", "tri", "trong", "uy", "vi", "vien", "xuyen", "khoi", "khuong", "quyet", "sam",
    "sau", "sen", "tho", "toai", "ut", "bich", "bang", "cam", "chien", "dan", "danh", "luc",
    "manh", "thai", "hoang", "diu", "ly", "nhan", "oanh", "kiet", "kiem", "lich", "lua", "nguyen",
    "phat", "quang", "thuc", "trieu", "trinh", "tri", "tuyet", "vu",
    // Viết tắt và các từ hay đi kèm tên trong mật khẩu ("Ng.Van.An", "ngay sinh", "Ha.Noi").
    "ng", "ngay", "sinh", "noi",
];

/// Ngân hàng, ví điện tử, nhà mạng và dịch vụ lớn ở Việt Nam, cùng các từ luôn bị phạt.
pub const VN_SERVICE_WORDS: &[&str] = &[
    "vietcombank",
    "vcb",
    "techcombank",
    "tcb",
    "bidv",
    "vietinbank",
    "ctg",
    "agribank",
    "mbbank",
    "mb",
    "acb",
    "vpbank",
    "tpbank",
    "sacombank",
    "stb",
    "hdbank",
    "vib",
    "shb",
    "ocb",
    "msb",
    "eximbank",
    "seabank",
    "lienvietpostbank",
    "lpbank",
    "namabank",
    "abbank",
    "baovietbank",
    "bacabank",
    "pvcombank",
    "kienlongbank",
    "ncb",
    "scb",
    "vietbank",
    "vietabank",
    "shinhan",
    "hsbc",
    "citibank",
    "uob",
    "woori",
    "cake",
    "timo",
    "tnex",
    "momo",
    "zalopay",
    "vnpay",
    "shopeepay",
    "viettelpay",
    "moca",
    "airpay",
    "viettel",
    "vinaphone",
    "mobifone",
    "vietnamobile",
    "gmobile",
    "vnpt",
    "fpt",
    "zalo",
    "facebook",
    "fb",
    "google",
    "gmail",
    "yahoo",
    "hotmail",
    "outlook",
    "icloud",
    "apple",
    "microsoft",
    "shopee",
    "lazada",
    "tiki",
    "sendo",
    "grab",
    "gojek",
    "tiktok",
    "youtube",
    "instagram",
    "messenger",
    "netflix",
    "evn",
    "bank",
    "nganhang",
    "banking",
    "pwv",
    "vault",
    "matkhau",
    "mk",
    "password",
    "pass",
    "master",
    "admin",
    "login",
    "email",
    "mail",
    "com",
    "vn",
];

/// Tỉnh, thành phố hay được dùng trong mật khẩu.
pub const VN_PLACE_WORDS: &[&str] = &[
    "vietnam",
    "hanoi",
    "saigon",
    "hcm",
    "tphcm",
    "sg",
    "hn",
    "danang",
    "haiphong",
    "cantho",
    "hue",
    "nhatrang",
    "dalat",
    "vungtau",
    "quangninh",
    "halong",
    "namdinh",
    "thaibinh",
    "nghean",
    "thanhhoa",
    "binhduong",
    "dongnai",
    "bienhoa",
    "quynhon",
    "buonmathuot",
    "phuquoc",
];

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

    /// Lỗi của bản 0.1.2: các mật khẩu dưới đây đều được chấp nhận làm master password và còn
    /// được gắn nhãn "Mạnh".
    #[test]
    fn master_password_policy_rejects_name_and_year_style_passwords() {
        for weak in [
            "nguyenvanan1990",
            "Matkhau@2024",
            "0912345678ab",
            "Concho123456",
            "Mai19951995!",
            "Baby@20102012",
            "tranthimai1995",
            "quangtrung1985",
            "Minhanh@2010",
            "Vietcombank@1",
            "Techcombank123",
            "yeuemnhieulam",
            "123456789012",
            "short",
            "",
        ] {
            let c = check_master_password(weak);
            assert!(
                !c.ok,
                "{weak} lẽ ra phải bị từ chối ({:.1})",
                c.guesses_log10
            );
            assert_ne!(c.message, "Đạt");
        }
        // Mọi cụm từ do bộ tạo sinh ra (4–6 từ) đều đạt.
        for words in 4..=6 {
            for _ in 0..50 {
                let p = generate_passphrase(&PassphraseOptions {
                    words,
                    ..Default::default()
                })
                .unwrap();
                let c = check_master_password(&p);
                assert!(c.ok, "{} ({:.1})", *p, c.guesses_log10);
                assert_eq!(c.message, "Đạt");
            }
        }
        // Mật khẩu ngẫu nhiên 20 ký tự cũng đạt.
        let p = generate_password(&PasswordOptions::default()).unwrap();
        assert!(check_master_password(&p).ok);
    }

    /// docs-claims#1: zxcvbn không có từ điển tên người / ngân hàng Việt Nam nên các mật khẩu này
    /// từng được chấm "Đạt".
    #[test]
    fn master_password_policy_rejects_names_banks_and_dates() {
        for weak in [
            "Vietcombank@Nguyenvanan",
            "tranvanbinh12031985",
            "Techcombank#Tranthibinh",
            "phamminhanh0912345678",
            "Nguyen.Van.An.1990!",
            "nguyenvanan_vcb_1990",
            "NguyenVanAn-12/03/1985",
            "nguyenvanan@yahoo.com",
            "an.nguyen.1990@gmail",
            "Minhanh2012@Hanoi",
            "Hanoi2024Vietcombank",
            "Trần Văn Bình 12/03/1985",
            "Đặng Thị Hồng Nhung 1990",
            "MOMO-hoangthuy-0987654321",
            // Tên ngắn (luật thứ hai: mọi dãy chữ cái đều là tên / ngân hàng).
            "Le.Thi.Mai.1990.12.03",
            "lethimai19901203",
            "Vu.An.Ha@0912345678",
            "Do Thi Ha 12/03/1985",
            "Mai@Vietcombank2024",
            "nguyenvanan1990",
        ] {
            let c = check_master_password(weak);
            assert!(!c.ok, "{weak} lẽ ra phải bị từ chối");
            assert_eq!(c.message, MASTER_PERSONAL_MESSAGE, "{weak}");
            assert!(personal_pattern_scan(weak).is_personal(), "{weak}");
        }
        assert!(
            MASTER_PERSONAL_MESSAGE.contains("tên người")
                && MASTER_PERSONAL_MESSAGE.contains("Gợi ý")
        );
        // Tên ngân hàng / dịch vụ còn được đưa cho zxcvbn: ước tính thấp hơn hẳn trước đây.
        let old = estimate_strength(
            "Vietcombank@Nguyenvanan",
            &["pwv", "vault", "matkhau", "password", "master"],
        );
        assert!(
            check_master_password("Vietcombank@Nguyenvanan").guesses_log10
                < old.guesses_log10 - 3.0
        );
    }

    /// fix2-cli-policy#1: bàn phím tiếng Việt kiểu "Unicode tổ hợp" (dấu thanh rời, NFD) hay dạng
    /// trộn (nguyên âm dựng sẵn + dấu thanh rời) không được lách luật tên người; độ dài được đếm trên
    /// dạng NFC — đúng chuỗi mà kho mã hoá.
    #[test]
    fn decomposed_vietnamese_input_is_checked_like_the_precomposed_form() {
        use unicode_normalization::UnicodeNormalization;
        for nfc in [
            "Trần Thị Bình 12/03/1985",
            "Nguyễn Văn Ánh 1985",
            "Đặng Thị Hồng 0912345678",
            "Phạm Đức Huy@1990",
            "Hoàng Minh Tuấn 15081988",
            "Lê.Thị.Mai.1990.12.03",
        ] {
            let nfd: String = nfc.nfd().collect();
            assert_ne!(nfc, nfd);
            // Dạng trộn: chữ có mũ / móc dựng sẵn, dấu thanh rời (như vài bộ gõ tạo ra).
            let mixed: String = nfd
                .replace("a\u{302}", "â")
                .replace("e\u{302}", "ê")
                .replace("o\u{302}", "ô")
                .replace("a\u{306}", "ă")
                .replace("u\u{31b}", "ư");
            for form in [nfc.to_string(), nfd, mixed] {
                let c = check_master_password(&form);
                assert!(!c.ok, "{form:?}");
                assert_eq!(c.message, MASTER_PERSONAL_MESSAGE, "{form:?}");
                assert_eq!(
                    personal_pattern_scan(&form),
                    personal_pattern_scan(nfc),
                    "{form:?}"
                );
            }
        }
        // 11 ký tự ở dạng NFC nhưng 23 "ký tự" ở dạng NFD: vẫn là quá ngắn.
        let short_nfc = "ồẩẫẹữ#1ởĩxy";
        let short_nfd: String = short_nfc.nfd().collect();
        assert!(short_nfd.chars().count() >= MASTER_MIN_CHARS);
        let c = check_master_password(&short_nfd);
        assert!(!c.ok && c.message.contains("(hiện 11)"), "{}", c.message);
        // Dạng NFD của một passphrase tiếng Việt hợp lệ vẫn đạt.
        let good: String = "chiếc ghế gỗ kêu cót két dưới gầm bếp".nfd().collect();
        assert!(check_master_password(&good).ok);
    }

    /// fix2-cli-policy#2: một từ vừa là từ EFF vừa là tên dịch vụ (`google`, `facebook`, `yahoo`)
    /// đứng riêng thành một dãy vẫn là thông tin cá nhân; nhiều từ EFF ghép lại vẫn là ngẫu nhiên.
    #[test]
    fn service_names_that_are_also_eff_words_still_count() {
        for weak in [
            "Google@TranVanBinh85",
            "Facebook.Nguyenvanan.1985",
            "Yahoo-Lethimai-1990",
            "Banking.Phamminhanh.0912",
            "Ng.Van.An.1990!!",
            "ngay sinh 12/03/1985 Ha.Noi",
        ] {
            let c = check_master_password(weak);
            assert!(!c.ok, "{weak}");
            assert_eq!(c.message, MASTER_PERSONAL_MESSAGE, "{weak}");
        }
        for (w, personal) in [("google", true), ("facebook", true), ("manhandle", false)] {
            let s = personal_pattern_scan(w);
            assert_eq!(s.unexplained_runs == 0, personal, "{w}: {s:?}");
        }
        // Nhiều từ EFF trong một dãy (passphrase không dấu ngăn cách): vẫn là ngẫu nhiên.
        assert_eq!(personal_pattern_scan("googlemanhandle").unexplained_runs, 1);
    }

    /// Luật thứ hai (theo cấu trúc) tách trọn vẹn bằng quy hoạch động, không chỉ tham lam.
    #[test]
    fn short_name_rule_segments_whole_runs_only() {
        for (pw, rule2) in [
            ("Le.Thi.Mai.1990.12.03", true),
            ("lethimai19901203", true),
            ("Vu.An.Ha@0912345678", true),
            ("Đỗ Thị Hà 12/03/1985", true),
            // Có từ không nằm trong danh sách.
            ("mai anh di hoc ve nha", false),
            // Quá ít chữ cái: để zxcvbn chấm.
            ("an#8391$2047!6", false),
            ("k9$Tq2mLx7Rw4pZb", false),
            // Dãy toàn từ EFF không tính là "tên" — trừ khi chính dãy là tên dịch vụ.
            ("Manhandle.Chosen.Among", false),
            ("Google.Facebook.Grab", true),
            // Chữ cái ngoài a–z là một dãy không giải thích được.
            ("Nguyen Ωμέγα", false),
        ] {
            let s = personal_pattern_scan(pw);
            assert_eq!(s.only_personal_words(), rule2, "{pw}: {s:?}");
        }
        for pw in [
            "mai anh di hoc ve nha",
            "an#8391$2047!6",
            "k9$Tq2mLx7Rw4pZb",
        ] {
            assert!(!personal_pattern_scan(pw).is_personal(), "{pw}");
        }
        // Đầu vào rất dài / Unicode lạ: không chậm bất thường, không panic.
        let long = "nguyen".repeat(20_000);
        let s = personal_pattern_scan(&long);
        assert!(
            !s.only_personal_words(),
            "dãy dài quá {MAX_SEGMENTED_RUN} chữ cái không được tách"
        );
        let short = "nguyen".repeat(10);
        assert!(personal_pattern_scan(&short).only_personal_words());
        for odd in [
            "İ\u{0301}ﬃ𝔄🙂\u{200d}ǅß\u{0}Ωé",
            "\u{FEFF}\u{202E}an\u{0}le",
            "",
        ] {
            let _ = check_master_password(odd);
        }
    }

    #[test]
    fn master_password_policy_accepts_unrelated_words_and_random_strings() {
        for good in [
            "correct horse battery staple wagon",
            "chiếc ghế gỗ kêu cót két dưới gầm bếp",
            "ngua-pin-kep-dung-bien-xanh-42",
            "mot-cum-tu-moi-rat-dai-khac-han-77",
            "q8#Vz!pL2@xR7&mKw",
            "Gx7-Tq2!vRz9@Lp4",
        ] {
            let c = check_master_password(good);
            assert!(c.ok, "{good}: {} ({:.1})", c.message, c.guesses_log10);
            assert_eq!(c.message, "Đạt");
        }
        // Chữ cái ngoài a–z, chữ số, ký hiệu: không phải tên.
        assert_eq!(personal_pattern_scan("19851203!!").personal_letters, 0);
        assert_eq!(personal_pattern_scan("Ωμέγα").free_letters, 5);
        assert_eq!(fold_vietnamese('ệ'), 'e');
        assert_eq!(fold_vietnamese('đ'), 'd');
        assert_eq!(fold_vietnamese('ữ'), 'u');
    }

    /// Luật "tên + ngân hàng + chữ số" không bao giờ được từ chối thứ mà chính bộ tạo của pwv đề xuất:
    /// mọi số từ của passphrase, có/không viết hoa, chữ số, mọi kiểu dấu ngăn cách; và mật khẩu ngẫu
    /// nhiên từ 14 ký tự với mọi tổ hợp nhóm ký tự.
    #[test]
    fn personal_pattern_rule_never_rejects_generated_secrets() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut n = 0;
        for words in MIN_WORDS..=MAX_WORDS {
            for sep in ["-", " ", "", ".", "_"] {
                for (capitalize, add_number) in
                    [(false, false), (true, false), (false, true), (true, true)]
                {
                    for _ in 0..12 {
                        let o = PassphraseOptions {
                            words,
                            separator: sep.into(),
                            capitalize,
                            add_number,
                        };
                        let p = generate_passphrase_with(&o, &mut rng).unwrap();
                        assert!(!personal_pattern_scan(&p).is_personal(), "{}", *p);
                        n += 1;
                    }
                }
            }
        }
        for length in 14..=48 {
            for (lowercase, uppercase, digits, symbols, exclude_ambiguous) in [
                (true, true, true, true, false),
                (true, true, true, false, false),
                (true, false, true, false, false),
                (true, false, false, false, false),
                (true, false, true, true, false),
                (true, true, true, true, true),
                (false, true, true, false, false),
            ] {
                for _ in 0..30 {
                    let o = PasswordOptions {
                        length,
                        lowercase,
                        uppercase,
                        digits,
                        symbols,
                        exclude_ambiguous,
                        require_each: true,
                    };
                    let p = generate_password_with(&o, &mut rng).unwrap();
                    assert!(!personal_pattern_scan(&p).is_personal(), "{}", *p);
                    n += 1;
                }
            }
        }
        assert!(n > 10_000);
        // Toàn bộ chính sách với passphrase mặc định của «Gợi ý» / `pwv gen -p` (5–8 từ).
        for words in 5..=8 {
            for _ in 0..25 {
                let o = PassphraseOptions {
                    words,
                    ..Default::default()
                };
                let p = generate_passphrase_with(&o, &mut rng).unwrap();
                let c = check_master_password(&p);
                assert!(c.ok, "{}: {}", *p, c.message);
            }
        }
    }
}
