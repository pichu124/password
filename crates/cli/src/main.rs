//! `pwv` — công cụ dòng lệnh cho kho mật khẩu.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use pwv_generator::{
    estimate_strength, generate_passphrase, generate_password, PassphraseOptions, PasswordOptions,
};
use pwv_vault_core::{Entry, KdfParams, SaveReport, Totp, Vault};
use zeroize::Zeroizing;

const CLIPBOARD_CLEAR_SECS: u64 = 20;

#[derive(Parser)]
#[command(
    name = "pwv",
    version,
    about = "Kho mật khẩu cá nhân — mã hoá Argon2id + XChaCha20-Poly1305"
)]
struct Cli {
    /// Đường dẫn file kho (mặc định lấy từ `pwv config` hoặc biến môi trường PWV_VAULT).
    #[arg(long, global = true, env = "PWV_VAULT")]
    vault: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Tạo kho mới (gợi ý đặt trong thư mục Google Drive để đồng bộ).
    Init { path: Option<PathBuf> },
    /// Tạo mật khẩu / passphrase ngẫu nhiên.
    Gen(GenArgs),
    /// Thêm mục mới.
    Add {
        title: String,
        #[arg(short, long, default_value = "")]
        username: String,
        #[arg(long)]
        url: Vec<String>,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long, default_value = "")]
        notes: String,
        /// Secret 2FA: URI `otpauth://...` hoặc chuỗi base32.
        #[arg(long)]
        totp: Option<String>,
        /// Tự tạo mật khẩu thay vì nhập.
        #[arg(short, long)]
        generate: bool,
        #[command(flatten)]
        gen: GenArgs,
    },
    /// Liệt kê / tìm kiếm mục.
    #[command(alias = "ls")]
    List { query: Option<String> },
    /// Xem chi tiết một mục.
    Show {
        target: String,
        /// Hiện mật khẩu ra màn hình.
        #[arg(long)]
        reveal: bool,
    },
    /// Sao chép mật khẩu (hoặc username) vào clipboard, tự xoá sau 20 giây.
    #[command(alias = "cp")]
    Copy {
        target: String,
        #[arg(long)]
        username: bool,
    },
    /// Sửa một mục.
    Edit {
        target: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(short, long)]
        username: Option<String>,
        /// Thay toàn bộ danh sách URL.
        #[arg(long)]
        url: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Đặt secret 2FA (otpauth:// hoặc base32); chuỗi rỗng để xoá.
        #[arg(long)]
        totp: Option<String>,
        /// Nhập mật khẩu mới.
        #[arg(long)]
        password: bool,
        /// Tạo mật khẩu mới ngẫu nhiên.
        #[arg(short, long)]
        generate: bool,
        #[command(flatten)]
        gen: GenArgs,
    },
    /// Xoá một mục.
    #[command(alias = "rm")]
    Delete {
        target: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Đổi master password.
    Passwd,
    /// Hiện mã 2FA (TOTP) 6 số của một mục.
    Totp {
        target: String,
        /// Sao chép mã vào clipboard.
        #[arg(short, long)]
        copy: bool,
    },
    /// Kiểm tra sức khoẻ mật khẩu: yếu, dùng trùng, lâu chưa đổi, đã bị lộ (Have I Been Pwned).
    Health {
        /// Không kiểm tra rò rỉ qua mạng.
        #[arg(long)]
        offline: bool,
    },
    /// Nhập mật khẩu từ file CSV (Chrome, Edge, Firefox, Bitwarden, KeePass, 1Password...).
    Import {
        file: PathBuf,
        /// Xoá file CSV sau khi nhập thành công (khuyến nghị — file chứa mật khẩu dạng rõ).
        #[arg(long)]
        delete_csv: bool,
    },
    /// Đồng bộ: nạp thay đổi từ máy khác và gộp các bản xung đột của Google Drive.
    Sync,
    /// Cấu hình đường dẫn kho mặc định.
    Config { path: Option<PathBuf> },
}

#[derive(Args, Clone)]
struct GenArgs {
    /// Độ dài mật khẩu.
    #[arg(short, long, default_value_t = 20)]
    length: usize,
    #[arg(long)]
    no_symbols: bool,
    #[arg(long)]
    no_digits: bool,
    #[arg(long)]
    no_uppercase: bool,
    /// Bỏ ký tự dễ nhầm (0 O l 1 I ...).
    #[arg(long)]
    no_ambiguous: bool,
    /// Tạo passphrase gồm các từ tiếng Anh thay vì ký tự ngẫu nhiên.
    #[arg(short, long)]
    passphrase: bool,
    /// Số từ cho passphrase.
    #[arg(short, long, default_value_t = 6)]
    words: usize,
    /// Sao chép kết quả vào clipboard (lệnh `gen`).
    #[arg(short, long)]
    copy: bool,
}

impl GenArgs {
    fn generate(&self) -> Result<(Zeroizing<String>, f64)> {
        if self.passphrase {
            let o = PassphraseOptions {
                words: self.words,
                ..Default::default()
            };
            Ok((generate_passphrase(&o)?, o.entropy_bits()))
        } else {
            let o = PasswordOptions {
                length: self.length,
                symbols: !self.no_symbols,
                digits: !self.no_digits,
                uppercase: !self.no_uppercase,
                exclude_ambiguous: self.no_ambiguous,
                ..Default::default()
            };
            Ok((generate_password(&o)?, o.entropy_bits()))
        }
    }
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("Lỗi: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init { path } => init(path.or(cli.vault)),
        Cmd::Config { path } => config_cmd(path),
        Cmd::Gen(g) => {
            let (pw, bits) = g.generate()?;
            println!("{}", *pw);
            eprintln!("≈ {bits:.0} bit entropy");
            if g.copy {
                copy_to_clipboard(&pw)?;
            }
            Ok(())
        }
        cmd => {
            let path = vault_path(cli.vault)?;
            let mut v = unlock(&path, !matches!(cmd, Cmd::Sync))?;
            vault_cmd(&mut v, cmd)
        }
    }
}

fn vault_cmd(v: &mut Vault, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::List { query } => {
            let list = v.search(query.as_deref().unwrap_or(""));
            if list.is_empty() {
                println!("(không có mục nào)");
            }
            for e in list {
                println!(
                    "{}  {}{:<28} {:<28} {}",
                    &e.id[..8],
                    if e.favorite { "★ " } else { "" },
                    truncate(&e.title, 28),
                    truncate(&e.username, 28),
                    e.urls.first().map(String::as_str).unwrap_or("")
                );
            }
            Ok(())
        }
        Cmd::Show { target, reveal } => {
            let e = resolve(v, &target)?;
            println!("ID:        {}", e.id);
            println!("Tiêu đề:   {}", e.title);
            println!("Username:  {}", e.username);
            println!(
                "Mật khẩu:  {}",
                if reveal {
                    e.password.clone()
                } else {
                    "•".repeat(10) + "  (dùng --reveal để hiện)"
                }
            );
            for u in &e.urls {
                println!("URL:       {u}");
            }
            if !e.tags.is_empty() {
                println!("Tag:       {}", e.tags.join(", "));
            }
            if !e.notes.is_empty() {
                println!("Ghi chú:   {}", e.notes);
            }
            if let Some(t) = e.totp.as_deref() {
                match Totp::parse(t) {
                    Ok(t) => {
                        let (code, left) = t.now();
                        println!("Mã 2FA:    {code}  (còn {left}s)");
                    }
                    Err(err) => println!("Mã 2FA:    lỗi — {err}"),
                }
            }
            let s = estimate_strength(&e.password, &[&e.username, &e.title]);
            println!("Độ mạnh:   {} ({}/4)", s.label, s.score);
            println!("Lịch sử:   {} mật khẩu cũ", e.password_history.len());
            Ok(())
        }
        Cmd::Copy { target, username } => {
            let e = resolve(v, &target)?;
            let value = Zeroizing::new(if username {
                e.username.clone()
            } else {
                e.password.clone()
            });
            eprintln!("Đã chọn: {}", e.title);
            copy_to_clipboard(&value)
        }
        Cmd::Add {
            title,
            username,
            url,
            tag,
            notes,
            totp,
            generate,
            gen,
        } => {
            let totp = totp.map(|t| validate_totp(&t)).transpose()?;
            let password = if generate {
                let (pw, bits) = gen.generate()?;
                eprintln!("Đã tạo mật khẩu ngẫu nhiên (≈ {bits:.0} bit).");
                pw
            } else {
                prompt_new_secret("Mật khẩu của tài khoản (để trống = tự tạo): ", false)?
                    .map(Ok)
                    .unwrap_or_else(|| gen.generate().map(|(p, _)| p))?
            };
            let mut e = Entry::new(title);
            e.username = username;
            e.password = password.to_string();
            e.urls = url;
            e.tags = tag;
            e.notes = notes;
            e.totp = totp;
            let id = v.add(e);
            save(v)?;
            println!("Đã thêm {}", &id[..8]);
            Ok(())
        }
        Cmd::Edit {
            target,
            title,
            username,
            url,
            notes,
            totp,
            password,
            generate,
            gen,
        } => {
            let id = resolve(v, &target)?.id.clone();
            let totp = match totp {
                Some(t) if t.trim().is_empty() => Some(None),
                Some(t) => Some(Some(validate_totp(&t)?)),
                None => None,
            };
            let new_pw = if generate {
                Some(gen.generate()?.0)
            } else if password {
                prompt_new_secret("Mật khẩu mới: ", false)?
            } else {
                None
            };
            v.update(&id, |e| {
                if let Some(t) = title {
                    e.title = t;
                }
                if let Some(u) = username {
                    e.username = u;
                }
                if !url.is_empty() {
                    e.urls = url;
                }
                if let Some(n) = notes {
                    e.notes = n;
                }
                if let Some(t) = totp {
                    e.totp = t;
                }
                if let Some(p) = &new_pw {
                    e.password = p.to_string();
                }
            })?;
            save(v)?;
            println!("Đã cập nhật.");
            Ok(())
        }
        Cmd::Delete { target, yes } => {
            let e = resolve(v, &target)?;
            let (id, title) = (e.id.clone(), e.title.clone());
            if !yes && !confirm(&format!("Xoá \"{title}\"?"))? {
                return Ok(());
            }
            v.delete(&id)?;
            save(v)?;
            println!("Đã xoá \"{title}\" (vẫn còn trong các bản sao lưu cũ).");
            Ok(())
        }
        Cmd::Passwd => {
            let new = prompt_new_secret("Master password MỚI: ", true)?
                .ok_or_else(|| anyhow!("không được để trống"))?;
            v.change_password(new.as_bytes(), KdfParams::DEFAULT)?;
            save(v)?;
            println!("Đã đổi master password.");
            Ok(())
        }
        Cmd::Sync => {
            if let Some(s) = v.reload()? {
                println!(
                    "Đã nạp thay đổi từ máy khác: +{} mới, {} cập nhật, {} xoá.",
                    s.added, s.updated, s.deleted
                );
            }
            for c in v.conflict_copies() {
                match v.merge_file(&c) {
                    Ok(s) => {
                        println!(
                            "Gộp bản xung đột {}: +{} mới, {} cập nhật, {} xoá.",
                            c.display(),
                            s.added,
                            s.updated,
                            s.deleted
                        );
                        archive_conflict(&c, v.path())?;
                    }
                    Err(e) => eprintln!("Bỏ qua {}: {e}", c.display()),
                }
            }
            save(v)?;
            println!("Đồng bộ xong — {} mục.", v.entries().len());
            Ok(())
        }
        Cmd::Totp { target, copy } => {
            let e = resolve(v, &target)?;
            let t = Totp::parse(
                e.totp
                    .as_deref()
                    .ok_or_else(|| anyhow!("\"{}\" chưa có secret 2FA", e.title))?,
            )?;
            let (code, left) = t.now();
            println!("{code}");
            eprintln!("{} — còn hiệu lực {left} giây", e.title);
            if copy {
                copy_to_clipboard(&code)?;
            }
            Ok(())
        }
        Cmd::Health { offline } => health(v, offline),
        Cmd::Import { file, delete_csv } => {
            let f = std::fs::File::open(&file)
                .with_context(|| format!("không mở được {}", file.display()))?;
            let res = pwv_vault_core::import::import_csv(f, v.entries())?;
            let n = res.entries.len();
            for e in res.entries {
                v.add(e);
            }
            save(v)?;
            println!(
                "Định dạng: {}. Đã nhập {n} mục, bỏ qua {} mục trùng, {} dòng trống.",
                res.detected, res.duplicates, res.skipped
            );
            if delete_csv {
                std::fs::remove_file(&file)?;
                println!("Đã xoá {}.", file.display());
            } else {
                eprintln!("⚠  File CSV chứa mật khẩu dạng rõ — hãy xoá nó (và dọn Thùng rác).");
            }
            println!("Gợi ý: chạy `pwv health` để xem mật khẩu nào yếu, trùng hoặc đã bị lộ.");
            Ok(())
        }
        Cmd::Init { .. } | Cmd::Config { .. } | Cmd::Gen(_) => unreachable!(),
    }
}

fn validate_totp(t: &str) -> Result<String> {
    Totp::parse(t)?;
    Ok(t.trim().to_string())
}

fn health(v: &Vault, offline: bool) -> Result<()> {
    use pwv_health::{check_breaches, hibp_fetch, offline_report, Issue};
    let mut report = offline_report(v.entries());
    if !offline {
        eprintln!(
            "Đang kiểm tra rò rỉ qua Have I Been Pwned (chỉ gửi 5 ký tự đầu của mã băm SHA-1)..."
        );
        if let Err(e) = check_breaches(v.entries(), &mut report, hibp_fetch) {
            eprintln!("⚠  {e} — bỏ qua kiểm tra rò rỉ.");
        }
    }
    let mut rows: Vec<(&Entry, &Vec<Issue>)> = report
        .issues
        .iter()
        .filter_map(|(id, is)| v.get(id).map(|e| (e, is)))
        .collect();
    rows.sort_by_key(|(e, is)| (is[0].severity(), e.title.to_lowercase()));
    for (e, issues) in &rows {
        let icon = match issues[0].severity() {
            0 => "🔴",
            1 | 2 => "🟠",
            _ => "🟡",
        };
        let text: Vec<String> = issues.iter().map(Issue::describe).collect();
        println!("{icon} {:<28} {}", truncate(&e.title, 28), text.join("; "));
    }
    let breached = report.count(|i| matches!(i, Issue::Breached { .. }));
    let reused = report.count(|i| matches!(i, Issue::Reused { .. }));
    let weak = report.count(|i| matches!(i, Issue::Weak { .. }));
    let old = report.count(|i| matches!(i, Issue::Old { .. }));
    println!();
    println!(
        "Điểm an toàn: {}/100 — {} mục: {breached} bị lộ, {reused} dùng trùng, {weak} yếu, {old} lâu chưa đổi{}",
        report.score(),
        report.checked,
        if report.breach_check_done { "" } else { " (chưa kiểm tra rò rỉ)" }
    );
    if rows.is_empty() {
        println!("✅ Không phát hiện vấn đề nào.");
    } else {
        println!("Sửa nhanh: `pwv edit <tên> -g` để đổi sang mật khẩu ngẫu nhiên mạnh.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------

fn init(path: Option<PathBuf>) -> Result<()> {
    let path = match path {
        Some(p) => p,
        None => {
            let suggested = suggest_vault_location();
            eprintln!("Gợi ý vị trí: {}", suggested.display());
            let input = prompt_line("Đường dẫn file kho (Enter = dùng gợi ý): ")?;
            if input.trim().is_empty() {
                suggested
            } else {
                PathBuf::from(input.trim())
            }
        }
    };
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("không tạo được thư mục {}", dir.display()))?;
    }
    eprintln!();
    eprintln!("⚠  QUÊN MASTER PASSWORD = MẤT TOÀN BỘ DỮ LIỆU. Không ai khôi phục được, kể cả phần mềm này.");
    eprintln!("   Gợi ý: dùng passphrase 5–6 từ (ví dụ chạy `pwv gen -p -w 6`) và viết ra giấy cất ở nơi an toàn.");
    eprintln!();
    let pw = prompt_new_secret("Master password: ", true)?
        .ok_or_else(|| anyhow!("không được để trống"))?;
    eprintln!("Đang tạo kho (Argon2id 256 MiB, có thể mất vài giây)...");
    Vault::create(&path, pw.as_bytes(), Default::default())?;
    write_config(&path)?;
    println!("Đã tạo kho: {}", path.display());
    Ok(())
}

/// Ưu tiên thư mục Google Drive for Desktop (bản tiếng Anh "My Drive" hoặc tiếng Việt "Drive của tôi").
fn suggest_vault_location() -> PathBuf {
    if cfg!(windows) {
        for letter in b'D'..=b'Z' {
            for name in ["My Drive", "Drive của tôi"] {
                let dir = PathBuf::from(format!("{}:\\{name}", letter as char));
                if dir.is_dir() {
                    return dir.join("Passwords").join("vault.pwv");
                }
            }
        }
    }
    dirs::document_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vault.pwv")
}

fn config_file() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .ok_or_else(|| anyhow!("không tìm thấy thư mục cấu hình"))?
        .join("pwv")
        .join("config.json"))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Config {
    vault: PathBuf,
}

fn write_config(vault: &Path) -> Result<()> {
    let f = config_file()?;
    std::fs::create_dir_all(f.parent().unwrap())?;
    let abs = std::path::absolute(vault).unwrap_or_else(|_| vault.to_path_buf());
    std::fs::write(&f, serde_json::to_vec_pretty(&Config { vault: abs })?)?;
    Ok(())
}

fn config_cmd(path: Option<PathBuf>) -> Result<()> {
    match path {
        Some(p) => {
            write_config(&p)?;
            println!("Kho mặc định: {}", p.display());
        }
        None => match read_config() {
            Some(c) => println!("Kho mặc định: {}", c.vault.display()),
            None => println!("Chưa cấu hình. Chạy `pwv init` hoặc `pwv config <đường-dẫn>`."),
        },
    }
    Ok(())
}

fn read_config() -> Option<Config> {
    serde_json::from_slice(&std::fs::read(config_file().ok()?).ok()?).ok()
}

fn vault_path(flag: Option<PathBuf>) -> Result<PathBuf> {
    flag.or_else(|| read_config().map(|c| c.vault))
        .ok_or_else(|| anyhow!("chưa có kho. Chạy `pwv init` trước."))
}

fn unlock(path: &Path, warn_conflicts: bool) -> Result<Vault> {
    if !path.exists() {
        bail!("không thấy file kho {}", path.display());
    }
    let pw = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
    let v = Vault::open(path, pw.as_bytes())?;
    let conflicts = v.conflict_copies();
    if warn_conflicts && !conflicts.is_empty() {
        eprintln!(
            "⚠  Có {} bản xung đột của Google Drive. Chạy `pwv sync` để gộp.",
            conflicts.len()
        );
    }
    Ok(v)
}

fn save(v: &mut Vault) -> Result<()> {
    let SaveReport {
        merged_remote,
        adopted_remote_password,
    } = v.save()?;
    if let Some(s) = merged_remote {
        eprintln!(
            "(Đã gộp thay đổi từ máy khác: +{} mới, {} cập nhật, {} xoá.)",
            s.added, s.updated, s.deleted
        );
    }
    if adopted_remote_password {
        eprintln!("(Master password đã được đổi ở máy khác — lần sau hãy dùng mật khẩu mới.)");
    }
    Ok(())
}

/// Tìm mục theo tiền tố id (≥ 4 ký tự) hoặc theo từ khoá (phải khớp đúng 1 mục).
fn resolve<'a>(v: &'a Vault, target: &str) -> Result<&'a Entry> {
    if target.len() >= 4 {
        let by_id: Vec<&Entry> = v
            .entries()
            .iter()
            .filter(|e| e.id.starts_with(target))
            .collect();
        if by_id.len() == 1 {
            return Ok(by_id[0]);
        }
    }
    let found = v.search(target);
    if let Some(exact) = found.iter().find(|e| e.title.eq_ignore_ascii_case(target)) {
        if found
            .iter()
            .filter(|e| e.title.eq_ignore_ascii_case(target))
            .count()
            == 1
        {
            return Ok(exact);
        }
    }
    match found.len() {
        0 => bail!("không tìm thấy \"{target}\""),
        1 => Ok(found[0]),
        n => {
            eprintln!("Có {n} mục khớp:");
            for e in &found {
                eprintln!("  {}  {}  ({})", &e.id[..8], e.title, e.username);
            }
            bail!("hãy chỉ rõ bằng ID")
        }
    }
}

fn archive_conflict(conflict: &Path, vault: &Path) -> Result<()> {
    let dir = pwv_vault_core::fsutil::backup_dir(vault);
    std::fs::create_dir_all(&dir)?;
    let name = format!(
        "merged-{}-{}",
        pwv_vault_core::model::now_ms(),
        conflict.file_name().unwrap().to_string_lossy()
    );
    std::fs::rename(conflict, dir.join(name))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Nhập liệu

fn prompt_line(msg: &str) -> Result<String> {
    eprint!("{msg}");
    io::stderr().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s)
}

fn confirm(msg: &str) -> Result<bool> {
    let a = prompt_line(&format!("{msg} [y/N] "))?;
    Ok(matches!(a.trim(), "y" | "Y" | "yes" | "c" | "có"))
}

/// Nhập bí mật 2 lần. `master = true` thì bắt buộc đủ mạnh (zxcvbn ≥ 3).
fn prompt_new_secret(msg: &str, master: bool) -> Result<Option<Zeroizing<String>>> {
    loop {
        let a = Zeroizing::new(rpassword::prompt_password(msg)?);
        if a.is_empty() {
            return Ok(None);
        }
        let s = estimate_strength(&a, &[]);
        if master && (s.score < 3 || a.chars().count() < 12) {
            eprintln!("Mật khẩu chính quá yếu ({}). Cần ≥ 12 ký tự và độ mạnh ≥ 3/4. Hãy thử passphrase nhiều từ.", s.label);
            continue;
        }
        let b = Zeroizing::new(rpassword::prompt_password("Nhập lại: ")?);
        if *a != *b {
            eprintln!("Hai lần nhập không khớp, thử lại.");
            continue;
        }
        if !master && s.score < 3 {
            eprintln!(
                "Lưu ý: mật khẩu này {} ({}/4).",
                s.label.to_lowercase(),
                s.score
            );
        }
        return Ok(Some(a));
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

// ---------------------------------------------------------------------------
// Clipboard

fn copy_to_clipboard(value: &str) -> Result<()> {
    let mut cb = arboard::Clipboard::new().context("không mở được clipboard")?;
    set_clipboard(&mut cb, value)?;
    eprintln!(
        "Đã sao chép. Clipboard sẽ tự xoá sau {CLIPBOARD_CLEAR_SECS} giây (Ctrl+C để xoá ngay)..."
    );
    for remaining in (1..=CLIPBOARD_CLEAR_SECS).rev() {
        eprint!("\r  còn {remaining:>2}s ");
        io::stderr().flush().ok();
        std::thread::sleep(Duration::from_secs(1));
    }
    // Chỉ xoá nếu clipboard vẫn còn đúng giá trị của ta (người dùng có thể đã copy thứ khác).
    if cb.get_text().map(|t| t == value).unwrap_or(true) {
        let _ = cb.clear();
    }
    eprintln!("\r  Đã xoá clipboard.");
    Ok(())
}

#[cfg(windows)]
fn set_clipboard(cb: &mut arboard::Clipboard, value: &str) -> Result<()> {
    use arboard::SetExtWindows;
    // Không lưu vào lịch sử clipboard (Win+V) và không đồng bộ lên cloud clipboard.
    cb.set()
        .exclude_from_history()
        .exclude_from_cloud()
        .text(value)?;
    Ok(())
}

#[cfg(not(windows))]
fn set_clipboard(cb: &mut arboard::Clipboard, value: &str) -> Result<()> {
    cb.set_text(value)?;
    Ok(())
}
