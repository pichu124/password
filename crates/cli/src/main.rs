//! `pwv` — công cụ dòng lệnh cho kho mật khẩu.
//!
//! Nguyên tắc:
//! - Mọi thay đổi đều đi qua [`Vault::transact`] (gộp file trên đĩa trước, hoàn tác nếu ghi lỗi).
//! - Bí mật (mật khẩu, secret 2FA, ghi chú) KHÔNG BAO GIỜ nhận qua tham số dòng lệnh, vì tham số
//!   bị lưu vào lịch sử lệnh của PowerShell/bash — luôn hỏi sau khi lệnh đã chạy.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use pwv_generator::{
    check_master_password, estimate_strength, generate_passphrase, generate_password,
    PassphraseOptions, PasswordOptions,
};
use pwv_vault_core::config::Rollback;
use pwv_vault_core::fsutil::backup_dir;
use pwv_vault_core::import::ImportResult;
use pwv_vault_core::{
    BackupFile, BackupKind, Config, Entry, Error as CoreError, KdfParams, MergeStats, OpenOptions,
    PasswordChangeReport, SaveReport, SyncReport, Totp, Vault,
};
use zeroize::Zeroizing;

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
    ///
    /// Mật khẩu, secret 2FA và ghi chú không nhận qua tham số (sẽ bị lưu vào lịch sử lệnh):
    /// pwv hỏi chúng sau khi chạy lệnh.
    Add {
        title: String,
        #[arg(short, long, default_value = "")]
        username: String,
        #[arg(long)]
        url: Vec<String>,
        #[arg(long)]
        tag: Vec<String>,
        /// Nhập ghi chú (nhiều dòng) sau khi chạy lệnh; kết thúc bằng một dòng trống.
        #[arg(long)]
        notes: bool,
        /// Nhập secret 2FA (otpauth://... hoặc base32) sau khi chạy lệnh — được hỏi ẩn.
        #[arg(long)]
        totp: bool,
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
        /// Hiện mật khẩu và ghi chú ra màn hình.
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
    ///
    /// Mật khẩu, secret 2FA và ghi chú không nhận qua tham số (sẽ bị lưu vào lịch sử lệnh):
    /// pwv hỏi chúng sau khi chạy lệnh.
    Edit {
        target: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(short, long)]
        username: Option<String>,
        /// Thay toàn bộ danh sách URL.
        #[arg(long)]
        url: Vec<String>,
        /// Nhập lại ghi chú (nhiều dòng) sau khi chạy lệnh; kết thúc bằng một dòng trống.
        /// Dòng trống ngay từ đầu = xoá ghi chú.
        #[arg(long)]
        notes: bool,
        /// Đặt secret 2FA mới (otpauth://... hoặc base32) — được hỏi ẩn sau khi chạy lệnh.
        #[arg(long, conflicts_with = "no_totp")]
        totp: bool,
        /// Xoá secret 2FA của mục.
        #[arg(long)]
        no_totp: bool,
        /// Nhập mật khẩu mới.
        #[arg(long)]
        password: bool,
        /// Tạo mật khẩu mới ngẫu nhiên.
        #[arg(short, long)]
        generate: bool,
        #[command(flatten)]
        gen: GenArgs,
    },
    /// Chuyển một mục vào thùng rác (lấy lại được bằng `pwv trash restore`).
    #[command(alias = "rm")]
    Delete {
        target: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Thùng rác: xem, lấy lại, hoặc xoá vĩnh viễn.
    Trash {
        #[command(subcommand)]
        action: Option<TrashCmd>,
    },
    /// Đổi master password (đồng thời thay khoá mã hoá của kho).
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
        /// Xoá file CSV sau khi nhập và lưu thành công (khuyến nghị — file chứa mật khẩu dạng rõ).
        #[arg(long)]
        delete_csv: bool,
    },
    /// Đồng bộ: nạp thay đổi từ máy khác và gộp các bản xung đột của Google Drive.
    Sync,
    /// Chuyển kho sang vị trí mới (ví dụ vào thư mục Dropbox) — kèm thư mục sao lưu.
    Move { new_path: PathBuf },
    /// Cấu hình đường dẫn kho mặc định.
    Config { path: Option<PathBuf> },
    /// Dựng lại kho từ thư mục sao lưu khi file kho không mở được (hỏng / bị xoá).
    Recover {
        #[arg(short, long)]
        yes: bool,
    },
    /// Liệt kê các bản sao lưu của kho.
    Backups,
    /// Lấy lại một mục (hoặc mọi mục khác biệt) từ một bản sao lưu.
    Restore {
        /// Số thứ tự (theo `pwv backups`) hoặc tên file của bản sao lưu.
        #[arg(long, value_name = "SỐ|TÊN-FILE")]
        from: String,
        /// Mục cần lấy lại (ID hoặc tên, tìm trong bản sao lưu).
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        target: Option<String>,
        /// Lấy lại mọi mục có nội dung khác với hiện tại.
        #[arg(long)]
        all: bool,
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum TrashCmd {
    /// Liệt kê các mục trong thùng rác (mặc định).
    #[command(alias = "ls")]
    List,
    /// Lấy một mục ra khỏi thùng rác.
    Restore { target: String },
    /// Xoá VĨNH VIỄN một mục trong thùng rác, trên mọi thiết bị.
    Purge {
        target: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Xoá VĨNH VIỄN mọi mục trong thùng rác, trên mọi thiết bị.
    Empty {
        #[arg(short, long)]
        yes: bool,
    },
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
        Cmd::Recover { yes } => recover(&vault_path(cli.vault)?, yes),
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
            warn_if_rollback(&v);
            vault_cmd(&mut v, cmd)?;
            remember_seen(&v);
            Ok(())
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
                    short_id(e),
                    if e.favorite { "★ " } else { "" },
                    truncate(&e.title, 28),
                    truncate(&e.username, 28),
                    e.urls.first().map(String::as_str).unwrap_or("")
                );
            }
            if query.is_none() && !v.trash().is_empty() {
                eprintln!(
                    "({} mục trong thùng rác — xem bằng `pwv trash`.)",
                    v.trash().len()
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
                println!("Ghi chú:   {}", notes_display(&e.notes, reveal));
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
            let totp = if totp { prompt_totp()? } else { None };
            let notes = if notes {
                prompt_notes()?
            } else {
                Zeroizing::new(String::new())
            };
            let password = if generate {
                let (pw, bits) = gen.generate()?;
                eprintln!("Đã tạo mật khẩu ngẫu nhiên (≈ {bits:.0} bit).");
                pw
            } else {
                prompt_new_secret("Mật khẩu của tài khoản (để trống = tự tạo): ")?
                    .map(Ok)
                    .unwrap_or_else(|| gen.generate().map(|(p, _)| p))?
            };
            let mut e = Entry::new(title);
            e.username = username;
            e.password = password.to_string();
            e.urls = url;
            e.tags = tag;
            e.notes = notes.to_string();
            e.totp = totp.map(|t| t.to_string());
            let id = commit(v, move |v| Ok(v.add(e)))?;
            println!("Đã thêm {}", &id[..8.min(id.len())]);
            Ok(())
        }
        Cmd::Edit {
            target,
            title,
            username,
            url,
            notes,
            totp,
            no_totp,
            password,
            generate,
            gen,
        } => {
            let id = resolve(v, &target)?.id.clone();
            let totp: Option<Option<Zeroizing<String>>> = if no_totp {
                Some(None)
            } else if totp {
                match prompt_totp()? {
                    Some(t) => Some(Some(t)),
                    None => {
                        eprintln!("Không nhập secret 2FA — giữ nguyên mã 2FA cũ.");
                        None
                    }
                }
            } else {
                None
            };
            let notes = if notes { Some(prompt_notes()?) } else { None };
            let new_pw = if generate {
                Some(gen.generate()?.0)
            } else if password {
                prompt_new_secret("Mật khẩu mới: ")?
            } else {
                None
            };
            let changed = commit(v, move |v| {
                let before = v.get(&id).cloned();
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
                    if let Some(n) = &notes {
                        e.notes = n.to_string();
                    }
                    if let Some(t) = &totp {
                        e.totp = t.as_ref().map(|t| t.to_string());
                    }
                    if let Some(p) = &new_pw {
                        e.password = p.to_string();
                    }
                })?;
                Ok(v.get(&id) != before.as_ref())
            })?;
            println!(
                "{}",
                if changed {
                    "Đã cập nhật."
                } else {
                    "Không có gì thay đổi."
                }
            );
            Ok(())
        }
        Cmd::Delete { target, yes } => {
            let e = resolve(v, &target)?;
            let (id, title) = (e.id.clone(), e.title.clone());
            if !yes && !confirm(&format!("Chuyển \"{title}\" vào thùng rác?"))? {
                return Ok(());
            }
            let del = id.clone();
            commit(v, move |v| v.delete(&del))?;
            println!("{}", deleted_message(&title, &id));
            Ok(())
        }
        Cmd::Trash { action } => trash_cmd(v, action.unwrap_or(TrashCmd::List)),
        Cmd::Passwd => {
            let new = prompt_new_master("Master password MỚI: ")?;
            eprintln!(
                "Đang thay khoá kho và mã hoá lại kho + các bản sao lưu (Argon2id, có thể mất vài giây)..."
            );
            let r = v
                .change_password(new.as_bytes(), KdfParams::DEFAULT)
                .map_err(core_err)?;
            for line in save_report_lines(&r.save, &backup_dir(v.path())) {
                eprintln!("{line}");
            }
            for line in passwd_report_lines(&r, &backup_dir(v.path())) {
                println!("{line}");
            }
            Ok(())
        }
        Cmd::Sync => {
            let r = v.sync().map_err(core_err)?;
            for line in sync_report_lines(&r, &backup_dir(v.path())) {
                println!("{line}");
            }
            println!(
                "Đồng bộ xong — {} mục ({} trong thùng rác).",
                v.entries().len(),
                v.trash().len()
            );
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
        Cmd::Move { new_path } => {
            let from = v.path().display().to_string();
            let r = v.move_to(&new_path).map_err(core_err)?;
            write_config(v.path())?;
            println!(
                "Đã chuyển kho:\n  từ  {from}\n  sang {}",
                v.path().display()
            );
            if r.conflicts_merged > 0 {
                println!(
                    "Đã gộp {} bản xung đột trước khi chuyển.",
                    r.conflicts_merged
                );
            }
            if r.rescued {
                eprintln!(
                    "⚠  File ở vị trí cũ không đọc được (hỏng, biến mất hoặc thuộc kho khác): chỉ ghi \
                     bản đang mở sang vị trí mới. Mọi thứ ở vị trí cũ (kể cả thư mục sao lưu) được \
                     giữ nguyên — hãy tự kiểm tra rồi dọn."
                );
            } else {
                if r.backups_moved {
                    println!("Thư mục sao lưu đã được chuyển theo.");
                }
                if !r.old_removed {
                    eprintln!("⚠  Chưa xoá được file ở vị trí cũ — hãy tự xoá: {from}");
                }
            }
            println!(
                "Trên máy khác: chạy `pwv config \"{}\"`.",
                v.path().display()
            );
            Ok(())
        }
        Cmd::Import { file, delete_csv } => {
            let f = std::fs::File::open(&file)
                .with_context(|| format!("không mở được {}", file.display()))?;
            let mut res = pwv_vault_core::import::import_csv(f, v.entries())?;
            let entries = std::mem::take(&mut res.entries);
            let n = entries.len();
            commit(v, move |v| {
                for e in entries {
                    v.add(e);
                }
                Ok(())
            })?;
            for line in import_summary_lines(&res, n) {
                println!("{line}");
            }
            if delete_csv {
                std::fs::remove_file(&file).with_context(|| {
                    format!("đã nhập xong nhưng không xoá được {}", file.display())
                })?;
                println!("Đã xoá {}.", file.display());
                eprintln!(
                    "⚠  Nếu file nằm trong thư mục được đồng bộ (Google Drive / Dropbox / OneDrive), một \
                     bản sao vẫn còn trong thùng rác trên cloud — hãy vào trang web của dịch vụ đó để \
                     xoá hẳn (và dọn cả Thùng rác của máy)."
                );
            } else {
                eprintln!(
                    "⚠  File CSV chứa mật khẩu dạng rõ — hãy xoá nó (và dọn Thùng rác). Nếu nó nằm trong \
                     thư mục được đồng bộ, hãy xoá cả bản trong thùng rác trên cloud."
                );
            }
            println!("Gợi ý: chạy `pwv health` để xem mật khẩu nào yếu, trùng hoặc đã bị lộ.");
            Ok(())
        }
        Cmd::Backups => backups_cmd(v),
        Cmd::Restore {
            from,
            target,
            all,
            yes,
        } => restore_cmd(v, &from, target.as_deref(), all, yes),
        Cmd::Init { .. } | Cmd::Config { .. } | Cmd::Gen(_) | Cmd::Recover { .. } => {
            unreachable!()
        }
    }
}

fn trash_cmd(v: &mut Vault, action: TrashCmd) -> Result<()> {
    match action {
        TrashCmd::List => {
            if v.trash().is_empty() {
                println!("Thùng rác trống.");
                return Ok(());
            }
            for e in v.trash() {
                println!(
                    "{}  {:<28} {:<28} xoá lúc {}",
                    short_id(e),
                    truncate(&e.title, 28),
                    truncate(&e.username, 28),
                    format_utc(e.trashed_at())
                );
            }
            println!();
            println!("Lấy lại: `pwv trash restore <ID|tên>` · Xoá vĩnh viễn: `pwv trash purge <ID|tên>` hoặc `pwv trash empty`.");
            Ok(())
        }
        TrashCmd::Restore { target } => {
            let e = resolve_trash(v, &target)?;
            let (id, title) = (e.id.clone(), e.title.clone());
            commit(v, move |v| v.restore(&id))?;
            println!("Đã lấy \"{title}\" ra khỏi thùng rác.");
            Ok(())
        }
        TrashCmd::Purge { target, yes } => {
            let e = resolve_trash(v, &target)?;
            let (id, title) = (e.id.clone(), e.title.clone());
            if !yes
                && !confirm(&format!(
                    "Xoá VĨNH VIỄN \"{title}\"? Mục sẽ bị xoá trên MỌI thiết bị khi đồng bộ và không lấy lại được (trừ khi một bản sao lưu cũ còn giữ nó)."
                ))?
            {
                return Ok(());
            }
            commit(v, move |v| v.purge(&id))?;
            println!("Đã xoá vĩnh viễn \"{title}\".");
            Ok(())
        }
        TrashCmd::Empty { yes } => {
            let n = v.trash().len();
            if n == 0 {
                println!("Thùng rác trống.");
                return Ok(());
            }
            if !yes
                && !confirm(&format!(
                    "Xoá VĨNH VIỄN {n} mục trong thùng rác? Các mục sẽ bị xoá trên MỌI thiết bị khi đồng bộ và không lấy lại được."
                ))?
            {
                return Ok(());
            }
            let removed = commit(v, |v| Ok(v.empty_trash()))?;
            println!("Đã xoá vĩnh viễn {removed} mục.");
            Ok(())
        }
    }
}

fn backups_cmd(v: &Vault) -> Result<()> {
    let list = v.backups();
    if list.is_empty() {
        println!(
            "Chưa có bản sao lưu nào trong {}.",
            backup_dir(v.path()).display()
        );
        return Ok(());
    }
    println!("Thư mục sao lưu: {}", backup_dir(v.path()).display());
    for (i, b) in list.iter().enumerate() {
        let count = v
            .read_backup(&b.path)
            .map(|d| (d.entries.len(), d.trash.len()))
            .map_err(|e| e.to_string());
        println!("{}", backup_line(i + 1, b, &count));
    }
    println!();
    println!("Lấy lại: `pwv restore --from <số> <ID|tên>` hoặc `pwv restore --from <số> --all`.");
    Ok(())
}

fn restore_cmd(
    v: &mut Vault,
    from: &str,
    target: Option<&str>,
    all: bool,
    yes: bool,
) -> Result<()> {
    let list = v.backups();
    let b = pick_backup(&list, from)?.clone();
    let data = v.read_backup(&b.path).map_err(core_err)?;
    let olds: Vec<Entry> = if all {
        data.entries
            .iter()
            .filter(|o| v.get(&o.id).is_none_or(|cur| !same_content(cur, o)))
            .cloned()
            .collect()
    } else {
        let t = target.unwrap_or_default();
        let old = match find_target(&data.entries, t) {
            Found::One(e) => e,
            Found::None => bail!(
                "bản sao lưu lúc {} không có mục \"{t}\"",
                format_utc(b.timestamp)
            ),
            Found::Many(m) => {
                print_ambiguous(&m);
                bail!("hãy chỉ rõ bằng ID")
            }
        };
        if v.get(&old.id).is_some_and(|cur| same_content(cur, old)) {
            println!(
                "\"{}\" hiện tại giống hệt bản sao lưu — không có gì để lấy lại.",
                old.title
            );
            return Ok(());
        }
        vec![old.clone()]
    };
    if olds.is_empty() {
        println!("Mọi mục trong bản sao lưu đều giống hiện tại — không có gì để lấy lại.");
        return Ok(());
    }
    println!(
        "Từ bản sao lưu lúc {} sẽ lấy lại {} mục:",
        format_utc(b.timestamp),
        olds.len()
    );
    for o in &olds {
        let state = if v.get(&o.id).is_some() {
            "đưa về phiên bản trong bản sao lưu"
        } else if v.get_trashed(&o.id).is_some() {
            "lấy ra khỏi thùng rác và đưa về phiên bản trong bản sao lưu"
        } else {
            "đã bị xoá vĩnh viễn — thêm lại thành mục mới"
        };
        println!("  {}  {:<28} {state}", short_id(o), truncate(&o.title, 28));
    }
    if all {
        println!("(Các mục được thêm sau thời điểm đó không bị ảnh hưởng.)");
    }
    if !yes && !confirm("Tiếp tục?")? {
        return Ok(());
    }
    let changed = commit(v, move |v| {
        Ok(olds.iter().filter(|o| v.reinstate(o)).count())
    })?;
    println!("Đã lấy lại {changed} mục.");
    println!(
        "Nếu mật khẩu đang dùng khác với bản sao lưu, nó đã được đưa vào lịch sử mật khẩu của mục — không mất."
    );
    Ok(())
}

/// Hai phiên bản của một mục có cùng nội dung (bỏ qua thời điểm và lịch sử).
fn same_content(a: &Entry, b: &Entry) -> bool {
    a.title == b.title
        && a.username == b.username
        && a.password == b.password
        && a.urls == b.urls
        && a.notes == b.notes
        && a.totp == b.totp
        && a.tags == b.tags
        && a.favorite == b.favorite
}

/// Chọn bản sao lưu theo số thứ tự (bắt đầu từ 1, như `pwv backups`) hoặc theo tên file.
fn pick_backup<'a>(list: &'a [BackupFile], from: &str) -> Result<&'a BackupFile> {
    let from = from.trim();
    if let Ok(i) = from.parse::<usize>() {
        if i >= 1 && i <= list.len() {
            return Ok(&list[i - 1]);
        }
        bail!(
            "không có bản sao lưu số {i} (hiện có {}) — xem `pwv backups`",
            list.len()
        );
    }
    list.iter()
        .find(|b| {
            b.path
                .file_name()
                .is_some_and(|n| n.to_string_lossy() == from)
        })
        .ok_or_else(|| anyhow!("không có bản sao lưu \"{from}\" — xem `pwv backups`"))
}

fn backup_kind_label(k: BackupKind) -> &'static str {
    match k {
        BackupKind::Auto => "tự động",
        BackupKind::Merged => "bản xung đột đã gộp",
        BackupKind::Damaged => "file hỏng đã cất",
    }
}

fn backup_line(index: usize, b: &BackupFile, count: &Result<(usize, usize), String>) -> String {
    let content = match count {
        Ok((n, 0)) => format!("{n} mục"),
        Ok((n, t)) => format!("{n} mục (+{t} trong thùng rác)"),
        Err(e) => format!("không đọc được: {e}"),
    };
    format!(
        "{index:>3}  {}  {:<20} {content}  [{}]",
        format_utc(b.timestamp),
        backup_kind_label(b.kind),
        b.path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    )
}

fn validate_totp(t: &str) -> Result<Zeroizing<String>> {
    let t = t.trim();
    Totp::parse(t)?;
    Ok(Zeroizing::new(t.to_string()))
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
// Tạo / mở / khôi phục kho

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
    if path.exists() {
        bail!(
            "đã có file tại {} — nếu đó là kho của bạn, chạy `pwv config \"{}\"` để dùng nó",
            path.display(),
            path.display()
        );
    }
    let signs = existing_vault_signs(&path);
    if !signs.is_empty() {
        eprintln!("⚠  Có vẻ ĐÃ CÓ một kho ở thư mục này (có thể từ máy khác và chưa đồng bộ xong về máy này):");
        for s in &signs {
            eprintln!("     {}", s.display());
        }
        eprintln!(
            "   Tạo kho mới ở đây sẽ sinh ra HAI kho tách biệt, mật khẩu không tự gộp với nhau."
        );
        eprintln!("   Muốn dùng kho có sẵn: đợi đồng bộ xong rồi chạy `pwv config <file-kho>`.");
        if !confirm("Vẫn tạo một kho MỚI, riêng biệt?")? {
            return Ok(());
        }
    }
    if let Some(old) = Config::load().vault.filter(|p| p.exists()) {
        eprintln!(
            "(Kho mặc định hiện tại là {} — sau khi tạo, kho mặc định sẽ là kho mới.)",
            old.display()
        );
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("không tạo được thư mục {}", dir.display()))?;
    }
    eprintln!();
    eprintln!("⚠  QUÊN MASTER PASSWORD = MẤT TOÀN BỘ DỮ LIỆU. Không ai khôi phục được, kể cả phần mềm này.");
    eprintln!("   Gợi ý: dùng passphrase 5–6 từ (ví dụ chạy `pwv gen -p -w 6`) và viết ra giấy cất ở nơi an toàn.");
    eprintln!();
    let pw = prompt_new_master("Master password: ")?;
    eprintln!("Đang tạo kho (Argon2id 256 MiB, có thể mất vài giây)...");
    let v = Vault::create(&path, pw.as_bytes(), Default::default()).map_err(core_err)?;
    write_config(&path)?;
    remember_seen(&v);
    println!("Đã tạo kho: {}", path.display());
    Ok(())
}

/// Dấu hiệu cho thấy thư mục đích đã có một kho: thư mục `<file>.backups` hoặc file `*.pwv` khác.
fn existing_vault_signs(path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let bdir = backup_dir(path);
    if bdir.exists() {
        out.push(bdir);
    }
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if let Ok(rd) = std::fs::read_dir(dir) {
        for p in rd.flatten().map(|e| e.path()) {
            let is_pwv = p.extension().is_some_and(|x| x.eq_ignore_ascii_case("pwv"));
            if is_pwv && p.is_file() && p.file_name() != path.file_name() {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn suggest_vault_location() -> PathBuf {
    pwv_vault_core::config::suggest_vault_location()
}

fn write_config(vault: &Path) -> Result<()> {
    Config::load()
        .set_vault(vault)
        .context("không ghi được file cấu hình")
}

fn config_cmd(path: Option<PathBuf>) -> Result<()> {
    match path {
        Some(p) => {
            write_config(&p)?;
            println!("Kho mặc định: {}", p.display());
            if !p.exists() {
                eprintln!("⚠  Hiện chưa thấy file này (có thể dịch vụ đồng bộ chưa tải về).");
            }
        }
        None => {
            let c = Config::load();
            match &c.vault {
                Some(v) => println!("Kho mặc định: {}", v.display()),
                None => println!("Chưa cấu hình. Chạy `pwv init` hoặc `pwv config <đường-dẫn>`."),
            }
            println!(
                "Tự khoá (app): {} phút · Xoá clipboard: {} giây",
                c.auto_lock_minutes, c.clipboard_clear_secs
            );
        }
    }
    Ok(())
}

fn vault_path(flag: Option<PathBuf>) -> Result<PathBuf> {
    flag.or_else(|| Config::load().vault)
        .ok_or_else(|| anyhow!("chưa có kho. Chạy `pwv init` trước."))
}

fn unlock(path: &Path, warn_conflicts: bool) -> Result<Vault> {
    if !path.exists() {
        return Err(core_err(CoreError::VaultFileMissing(
            path.display().to_string(),
        )));
    }
    let pw = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
    let v = Vault::open(path, pw.as_bytes()).map_err(core_err)?;
    let conflicts = v.conflict_copies();
    if warn_conflicts && !conflicts.is_empty() {
        eprintln!(
            "⚠  Có {} bản xung đột từ dịch vụ đồng bộ (Drive/Dropbox/OneDrive). Chạy `pwv sync` để gộp.",
            conflicts.len()
        );
    }
    if v.has_unsaved_changes() {
        eprintln!(
            "(Kho được mở nhờ một bản xung đột mới hơn — chạy `pwv sync` để ghi lại file kho.)"
        );
    }
    Ok(v)
}

fn warn_if_rollback(v: &Vault) {
    if let Some(r) = Config::load().rollback_of(v.vault_id(), v.modified_at(), v.key_changed_at()) {
        eprintln!("{}", rollback_warning(&r));
    }
}

fn rollback_warning(r: &Rollback) -> String {
    let mut s = format!(
        "⚠  CẢNH BÁO: file kho này CŨ HƠN bản mà máy này đã từng thấy (máy này đã thấy nội dung sửa \
         lúc {}, còn file hiện tại chỉ tới {}).\n   Có thể dịch vụ đồng bộ (Drive/Dropbox/OneDrive) \
         đã khôi phục một bản cũ, hoặc ai đó đã chép đè file cũ lên — các mục thêm/sửa gần đây có \
         thể bị THIẾU.",
        format_utc(r.seen_modified_at),
        format_utc(r.file_modified_at)
    );
    if r.older_password {
        s.push_str(
            "\n   File này còn dùng master password CŨ hơn lần đổi mật khẩu gần nhất mà máy này biết.",
        );
    }
    s.push_str(
        "\n   Trước khi sửa gì: kiểm tra lịch sử phiên bản trên dịch vụ đồng bộ, các máy khác, và \
         `pwv backups`.",
    );
    s
}

/// Ghi nhận mốc mới nhất đã thấy của kho (để lần sau phát hiện file bị thay bằng bản cũ).
fn remember_seen(v: &Vault) {
    let mut c = Config::load();
    if c.note_seen(v.vault_id(), v.modified_at(), v.key_changed_at()) {
        if let Err(e) = c.save() {
            eprintln!("(Không ghi được file cấu hình: {e})");
        }
    }
}

fn recover(path: &Path, yes: bool) -> Result<()> {
    let pw = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
    if path.exists() {
        if let Ok(v) = Vault::open(path, pw.as_bytes()) {
            println!(
                "File kho {} vẫn mở bình thường — không cần dựng lại.",
                path.display()
            );
            println!("Để lấy lại một mục cũ: `pwv backups` rồi `pwv restore --from <số> <mục>`.");
            remember_seen(&v);
            return Ok(());
        }
    }
    eprintln!(
        "Đang tìm trong {} (mỗi bản thử mất khoảng 1 giây)...",
        backup_dir(path).display()
    );
    let (mut v, used, newest) =
        Vault::recover_from_backups(path, pw.as_bytes(), OpenOptions::default())
            .map_err(core_err)?;
    println!(
        "Tìm thấy {} mục (+{} trong thùng rác), gộp từ {used} file sao lưu; bản sao lưu mới nhất \
         dùng được tạo lúc {}, nội dung sửa lần cuối lúc {}.",
        v.entries().len(),
        v.trash().len(),
        format_utc(newest),
        format_utc(v.modified_at())
    );
    println!(
        "Lưu ý: nếu lần ghi cuối cùng vào kho là của bản app cũ (≤ 0.1.2) thì thay đổi cuối cùng \
         trước khi file hỏng có thể không có trong sao lưu."
    );
    if path.exists() {
        println!("File kho hiện tại sẽ được cất vào thư mục sao lưu (không bị xoá).");
    } else {
        println!("Sẽ tạo lại file kho tại {}.", path.display());
        eprintln!(
            "⚠  Nếu kho đã được chuyển sang thư mục khác trên máy kia, ĐỪNG dựng lại ở đây — chạy \
             `pwv config <đường-dẫn-mới>` thay vào đó."
        );
    }
    if !yes && !confirm("Ghi kho dựng lại?")? {
        return Ok(());
    }
    if let Some(archived) = v.force_write().map_err(core_err)? {
        println!("File hỏng đã được cất tại: {}", archived.display());
    }
    println!("Đã ghi kho: {}", path.display());
    // Người dùng đã chủ động dựng lại kho: lấy trạng thái này làm mốc mới (không cảnh báo
    // "file kho CŨ HƠN" ở mỗi lệnh sau đó nữa).
    let mut c = Config::load();
    if c.rollback_of(v.vault_id(), v.modified_at(), v.key_changed_at())
        .is_some()
    {
        eprintln!(
            "(Kho dựng lại cũ hơn bản máy này từng thấy — hãy kiểm tra xem có mục nào bị thiếu.)"
        );
    }
    c.set_seen(v.vault_id(), v.modified_at(), v.key_changed_at());
    if let Err(e) = c.save() {
        eprintln!("(Không ghi được file cấu hình: {e})");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Ghi + thông báo

/// Thực hiện một thay đổi qua [`Vault::transact`] và báo những gì xảy ra khi lưu.
fn commit<T>(v: &mut Vault, f: impl FnOnce(&mut Vault) -> pwv_vault_core::Result<T>) -> Result<T> {
    let (t, report) = v.transact(f).map_err(core_err)?;
    for line in save_report_lines(&report, &backup_dir(v.path())) {
        eprintln!("{line}");
    }
    Ok(t)
}

fn merge_stats_text(s: &MergeStats) -> String {
    format!(
        "+{} mới, {} cập nhật, {} xoá",
        s.added, s.updated, s.deleted
    )
}

fn save_report_lines(r: &SaveReport, backups: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(s) = &r.merged_remote {
        out.push(format!(
            "(Đã gộp thay đổi từ máy khác: {}.)",
            merge_stats_text(s)
        ));
    }
    if r.adopted_remote_password {
        out.push(adopted_password_line());
    }
    if r.backup_failed {
        out.push(backup_failed_line(backups));
    }
    out
}

fn adopted_password_line() -> String {
    "(Master password của kho đã được đổi ở máy khác — từ lần mở khoá sau, hãy dùng mật khẩu mới đó.)"
        .to_string()
}

fn backup_failed_line(backups: &Path) -> String {
    format!(
        "⚠  Không tạo được bản sao lưu trước khi ghi (file kho vẫn được ghi an toàn). Kiểm tra dung lượng đĩa và quyền ghi của {}.",
        backups.display()
    )
}

fn sync_report_lines(r: &SyncReport, backups: &Path) -> Vec<String> {
    let mut out = Vec::new();
    match &r.merged_remote {
        Some(s) => out.push(format!(
            "Đã nạp thay đổi từ máy khác: {}.",
            merge_stats_text(s)
        )),
        None => out.push("File kho trên đĩa không có thay đổi mới từ máy khác.".to_string()),
    }
    for c in &r.conflicts {
        let name = c.path.display();
        match &c.result {
            Ok(s) if c.archived => out.push(format!(
                "Đã gộp bản xung đột {name}: {} — đã cất vào thư mục sao lưu.",
                merge_stats_text(s)
            )),
            Ok(s) => out.push(format!(
                "Đã gộp bản xung đột {name}: {} — nhưng chưa cất được, vẫn để nguyên tại chỗ (có thể tự xoá).",
                merge_stats_text(s)
            )),
            Err(e) => out.push(format!(
                "⚠  Không gộp được {name}: {e} — để nguyên tại chỗ."
            )),
        }
    }
    if r.adopted_remote_password {
        out.push(adopted_password_line());
    }
    if r.backup_failed {
        out.push(backup_failed_line(backups));
    }
    out.push(if r.wrote {
        "Đã ghi lại file kho.".to_string()
    } else {
        "File kho đã đầy đủ — không cần ghi lại.".to_string()
    });
    out
}

fn passwd_report_lines(r: &PasswordChangeReport, backups: &Path) -> Vec<String> {
    let mut out = vec!["Đã đổi master password và thay khoá mã hoá của kho.".to_string()];
    let mut b = format!(
        "Bản sao lưu trên máy này: đã mã hoá lại {} bản bằng khoá mới",
        r.backups_reencrypted
    );
    if r.backups_skipped > 0 {
        b.push_str(&format!(
            "; {} bản KHÔNG mã hoá lại được — nếu đọc được, chúng vẫn mở bằng mật khẩu CŨ (xem trong {})",
            r.backups_skipped,
            backups.display()
        ));
    }
    b.push('.');
    out.push(b);
    out.push(String::new());
    out.push(
        "⚠  Lưu ý: những bản sao ĐÃ RỜI KHỎI máy này vẫn mở được bằng mật khẩu CŨ và chứa dữ liệu tại thời điểm đó:"
            .to_string(),
    );
    out.push(
        "   • lịch sử phiên bản và thùng rác trên cloud (Google Drive, Dropbox, OneDrive);"
            .to_string(),
    );
    out.push("   • bản offline trên điện thoại;".to_string());
    out.push("   • các máy tính khác chưa đồng bộ.".to_string());
    out.push(
        "   Nếu mật khẩu cũ có thể đã bị lộ, hãy đổi mật khẩu của các tài khoản quan trọng (ngân hàng, email)."
            .to_string(),
    );
    out.push("Các thiết bị khác sẽ hỏi mật khẩu mới ở lần mở khoá tới.".to_string());
    out
}

fn deleted_message(title: &str, id: &str) -> String {
    let short = &id[..8.min(id.len())];
    format!(
        "Đã chuyển \"{title}\" vào thùng rác. Lấy lại: `pwv trash restore {short}` · Xoá vĩnh viễn: `pwv trash purge {short}`."
    )
}

fn import_summary_lines(res: &ImportResult, imported: usize) -> Vec<String> {
    let mut out = vec![format!(
        "Định dạng: {}. Đã nhập {imported} mục, bỏ qua {} dòng trùng khớp hoàn toàn, {} dòng trống.",
        res.detected, res.duplicates, res.skipped
    )];
    if !res.similar.is_empty() {
        out.push(format!(
            "{} mục được nhập, có vẻ trùng — hãy rà lại:",
            res.similar.len()
        ));
        out.extend(res.similar.iter().map(|t| format!("  • {t}")));
    }
    if !res.bad_totp.is_empty() {
        out.push(format!(
            "{} mục có mã 2FA không đọc được, đã chép vào ghi chú:",
            res.bad_totp.len()
        ));
        out.extend(res.bad_totp.iter().map(|t| format!("  • {t}")));
    }
    out
}

/// Lời khuyên cho các lỗi của lõi mà người dùng cần làm gì đó.
fn advice(e: &CoreError) -> Option<&'static str> {
    Some(match e {
        CoreError::PasswordChangedElsewhere => {
            "Thay đổi vừa rồi CHƯA được lưu. Hãy chạy lại lệnh và mở khoá bằng master password MỚI (đã đặt trên thiết bị kia)."
        }
        CoreError::VaultFileMissing(_) => {
            "Cũng có thể dịch vụ đồng bộ chưa tải file về máy này. \
             pwv sẽ KHÔNG tự tạo lại kho ở đây.\n   • Kho đã được chuyển: chạy `pwv config <đường-dẫn-mới>`.\n   \
             • File bị xoá/mất thật: `pwv recover` dựng lại từ thư mục sao lưu."
        }
        CoreError::VaultFileDamaged | CoreError::BadFormat => {
            "Nếu dịch vụ đồng bộ đang tải file, đợi một lát rồi thử lại. Nếu vẫn lỗi: chạy `pwv recover` để \
             dựng lại kho từ thư mục sao lưu (file hỏng được cất đi, không bị xoá)."
        }
        CoreError::UnsupportedVersion(_) => {
            "File kho được ghi bởi một phiên bản pwv MỚI HƠN. Hãy cập nhật pwv (cả CLI lẫn app) lên bản mới \
             nhất; bản này sẽ không ghi đè lên file đó."
        }
        CoreError::DifferentVault => {
            "File ở vị trí kho hiện thuộc về một kho KHÁC (có thể ai đó hoặc dịch vụ đồng bộ đã chép một kho khác \
             vào đây). pwv không ghi đè lên nó — kiểm tra lại đường dẫn bằng `pwv config`."
        }
        CoreError::MoveIntoBackups => {
            "Hãy chọn một thư mục nằm NGOÀI thư mục `<tên-kho>.backups`."
        }
        CoreError::Decrypt => {
            "Nếu master password vừa được đổi trên thiết bị khác, hãy dùng mật khẩu mới."
        }
        CoreError::WriteVerifyFailed => {
            "Thay đổi đã được hoàn tác trong bộ nhớ. Chạy `pwv sync` để kiểm tra file kho rồi thử lại."
        }
        _ => return None,
    })
}

fn core_err(e: CoreError) -> anyhow::Error {
    match advice(&e) {
        Some(a) => anyhow!("{e}\n   → {a}"),
        None => anyhow::Error::new(e),
    }
}

// ---------------------------------------------------------------------------
// Tìm mục

enum Found<'a> {
    One(&'a Entry),
    None,
    Many(Vec<&'a Entry>),
}

/// Tìm mục theo tiền tố id (≥ 4 ký tự) hoặc theo từ khoá (phải khớp đúng 1 mục, hoặc đúng 1 mục
/// có tiêu đề trùng khớp).
fn find_target<'a>(entries: &'a [Entry], target: &str) -> Found<'a> {
    if target.len() >= 4 {
        let by_id: Vec<&Entry> = entries
            .iter()
            .filter(|e| e.id.starts_with(target))
            .collect();
        if by_id.len() == 1 {
            return Found::One(by_id[0]);
        }
    }
    let mut found: Vec<&Entry> = entries.iter().filter(|e| e.matches(target)).collect();
    found.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
    let exact: Vec<&Entry> = found
        .iter()
        .copied()
        .filter(|e| e.title.to_lowercase() == target.to_lowercase())
        .collect();
    if exact.len() == 1 {
        return Found::One(exact[0]);
    }
    match found.len() {
        0 => Found::None,
        1 => Found::One(found[0]),
        _ => Found::Many(found),
    }
}

fn print_ambiguous(found: &[&Entry]) {
    eprintln!("Có {} mục khớp:", found.len());
    for e in found {
        eprintln!("  {}  {}  ({})", short_id(e), e.title, e.username);
    }
}

/// Tìm trong các mục đang dùng.
fn resolve<'a>(v: &'a Vault, target: &str) -> Result<&'a Entry> {
    match find_target(v.entries(), target) {
        Found::One(e) => Ok(e),
        Found::Many(m) => {
            print_ambiguous(&m);
            bail!("hãy chỉ rõ bằng ID")
        }
        Found::None => match find_target(v.trash(), target) {
            Found::None => bail!("không tìm thấy \"{target}\""),
            _ => bail!(
                "không tìm thấy \"{target}\" trong các mục đang dùng — nó đang nằm trong thùng rác \
                 (lấy lại: `pwv trash restore \"{target}\"`)"
            ),
        },
    }
}

/// Tìm trong thùng rác.
fn resolve_trash<'a>(v: &'a Vault, target: &str) -> Result<&'a Entry> {
    match find_target(v.trash(), target) {
        Found::One(e) => Ok(e),
        Found::Many(m) => {
            print_ambiguous(&m);
            bail!("hãy chỉ rõ bằng ID")
        }
        Found::None => bail!("không có \"{target}\" trong thùng rác (xem: `pwv trash`)"),
    }
}

fn short_id(e: &Entry) -> &str {
    &e.id[..8.min(e.id.len())]
}

// ---------------------------------------------------------------------------
// Thời gian

/// Định dạng mốc thời gian (ms kể từ 1970) thành ngày giờ UTC, không cần thư viện ngày giờ.
fn format_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

/// Số ngày kể từ 1970-01-01 → (năm, tháng, ngày) theo lịch Gregory (thuật toán của H. Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
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
    Ok(is_yes(&a))
}

fn is_yes(a: &str) -> bool {
    matches!(
        a.trim().to_lowercase().as_str(),
        "y" | "yes" | "c" | "có" | "co"
    )
}

/// Đọc ghi chú nhiều dòng cho tới một dòng trống hoặc hết dữ liệu (EOF).
fn read_notes_from(r: &mut impl BufRead) -> io::Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(4096));
    let mut line = Zeroizing::new(String::with_capacity(1024));
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break;
        }
        let l = line.trim_end_matches(['\n', '\r']);
        if l.trim().is_empty() {
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(l);
    }
    Ok(out)
}

fn prompt_notes() -> Result<Zeroizing<String>> {
    eprintln!(
        "Nhập ghi chú (nhiều dòng). Kết thúc bằng một dòng trống{}:",
        if cfg!(windows) {
            " hoặc Ctrl+Z rồi Enter"
        } else {
            " hoặc Ctrl+D"
        }
    );
    Ok(read_notes_from(&mut io::stdin().lock())?)
}

fn notes_display(notes: &str, reveal: bool) -> String {
    if reveal {
        notes.replace('\n', "\n           ")
    } else {
        let lines = notes.lines().count().max(1);
        format!("{}  ({lines} dòng — dùng --reveal để hiện)", "•".repeat(10))
    }
}

/// Hỏi secret 2FA (ẩn khi gõ) cho tới khi hợp lệ. Để trống = bỏ qua.
fn prompt_totp() -> Result<Option<Zeroizing<String>>> {
    loop {
        let s = Zeroizing::new(rpassword::prompt_password(
            "Secret 2FA (otpauth://... hoặc base32, ẩn khi gõ; Enter để bỏ qua): ",
        )?);
        if s.trim().is_empty() {
            return Ok(None);
        }
        match validate_totp(&s) {
            Ok(t) => {
                if let Ok(parsed) = Totp::parse(&t) {
                    let (code, left) = parsed.now();
                    eprintln!("Mã hiện tại: {code} (còn {left}s) — so với app xác thực để chắc đã nhập đúng.");
                }
                return Ok(Some(t));
            }
            Err(e) => eprintln!("Secret 2FA không hợp lệ: {e}. Thử lại."),
        }
    }
}

/// Hỏi master password mới 2 lần; bắt buộc đạt chính sách `check_master_password`.
fn prompt_new_master(msg: &str) -> Result<Zeroizing<String>> {
    loop {
        let a = Zeroizing::new(rpassword::prompt_password(msg)?);
        if a.is_empty() {
            bail!("không được để trống");
        }
        let c = check_master_password(&a);
        if !c.ok {
            eprintln!("Chưa dùng được: {}", c.message);
            eprintln!(
                "Gợi ý: chạy `pwv gen -p -w 6` để lấy một cụm 6 từ ngẫu nhiên, rồi viết ra giấy."
            );
            continue;
        }
        let b = Zeroizing::new(rpassword::prompt_password("Nhập lại: ")?);
        if *a != *b {
            eprintln!("Hai lần nhập không khớp, thử lại.");
            continue;
        }
        return Ok(a);
    }
}

/// Nhập mật khẩu tài khoản 2 lần (cảnh báo nếu yếu). Để trống = `None`.
fn prompt_new_secret(msg: &str) -> Result<Option<Zeroizing<String>>> {
    loop {
        let a = Zeroizing::new(rpassword::prompt_password(msg)?);
        if a.is_empty() {
            return Ok(None);
        }
        let b = Zeroizing::new(rpassword::prompt_password("Nhập lại: ")?);
        if *a != *b {
            eprintln!("Hai lần nhập không khớp, thử lại.");
            continue;
        }
        let s = estimate_strength(&a, &[]);
        if s.score < 3 {
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

fn clipboard_notice(secs: u64, ctrl_c_clears: bool) -> String {
    if ctrl_c_clears {
        format!("Đã sao chép. Clipboard sẽ tự xoá sau {secs} giây (Ctrl+C để xoá ngay và thoát)...")
    } else {
        format!(
            "Đã sao chép. Clipboard sẽ tự xoá sau {secs} giây — hãy đợi hết thời gian đếm ngược \
             (nếu ngắt bằng Ctrl+C, clipboard sẽ KHÔNG được xoá)..."
        )
    }
}

/// Có nên xoá clipboard không: chỉ khi nó vẫn còn đúng giá trị của ta (người dùng có thể đã copy
/// thứ khác). Không đọc được vì clipboard đang chứa thứ không phải chữ ⇒ không phải của ta.
fn should_clear(current: std::result::Result<&str, &arboard::Error>, ours: &str) -> bool {
    match current {
        Ok(t) => t == ours,
        Err(arboard::Error::ContentNotAvailable) => false,
        Err(_) => true,
    }
}

fn clear_if_ours(cb: &mut arboard::Clipboard, ours: &str) {
    let current = cb.get_text().map(Zeroizing::new);
    if should_clear(current.as_ref().map(|t| t.as_str()), ours) {
        let _ = cb.clear();
    }
}

fn copy_to_clipboard(value: &str) -> Result<()> {
    let mut cb = arboard::Clipboard::new().context("không mở được clipboard")?;
    set_clipboard(&mut cb, value)?;
    let ctrl_c_clears = ctrl_handler::install(value);
    let secs = u64::from(Config::load().clipboard_clear_secs);
    eprintln!("{}", clipboard_notice(secs, ctrl_c_clears));
    for remaining in (1..=secs).rev() {
        eprint!("\r  còn {remaining:>2}s ");
        io::stderr().flush().ok();
        std::thread::sleep(Duration::from_secs(1));
    }
    ctrl_handler::uninstall();
    clear_if_ours(&mut cb, value);
    eprintln!("\r  Đã xoá clipboard.");
    Ok(())
}

#[cfg(windows)]
fn set_clipboard(cb: &mut arboard::Clipboard, value: &str) -> Result<()> {
    use arboard::SetExtWindows;
    // Không lưu vào lịch sử clipboard (Win+V), không đồng bộ lên cloud clipboard, và báo cho các
    // phần mềm theo dõi clipboard (trình quản lý clipboard) đừng ghi lại.
    cb.set()
        .exclude_from_history()
        .exclude_from_cloud()
        .exclude_from_monitoring()
        .text(value)?;
    Ok(())
}

#[cfg(not(windows))]
fn set_clipboard(cb: &mut arboard::Clipboard, value: &str) -> Result<()> {
    cb.set_text(value)?;
    Ok(())
}

/// Windows: khi người dùng bấm Ctrl+C / Ctrl+Break hoặc đóng cửa sổ console trong lúc đếm ngược,
/// xoá clipboard (nếu vẫn là giá trị của ta) rồi để tiến trình thoát như bình thường.
#[cfg(windows)]
mod ctrl_handler {
    use std::sync::Mutex;

    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
    };
    use zeroize::Zeroizing;

    /// Giá trị vừa sao chép — trình xử lý chạy trên một luồng riêng do Windows tạo nên phải dùng chung qua đây.
    static COPIED: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);

    fn take_copied() -> Option<Zeroizing<String>> {
        match COPIED.lock() {
            Ok(mut g) => g.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }

    fn clear_now() {
        if let Some(ours) = take_copied() {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                super::clear_if_ours(&mut cb, &ours);
            }
        }
    }

    unsafe extern "system" fn handler(ctrl_type: u32) -> BOOL {
        if matches!(
            ctrl_type,
            CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT
        ) {
            // Không bao giờ để panic thoát ra khỏi hàm `extern "system"`.
            let _ = std::panic::catch_unwind(clear_now);
        }
        // FALSE: chuyển tiếp cho trình xử lý mặc định ⇒ tiến trình thoát như bình thường.
        0
    }

    /// Cài trình xử lý. Trả về true nếu cài được (khi đó Ctrl+C sẽ xoá clipboard).
    pub fn install(value: &str) -> bool {
        match COPIED.lock() {
            Ok(mut g) => *g = Some(Zeroizing::new(value.to_string())),
            Err(poisoned) => *poisoned.into_inner() = Some(Zeroizing::new(value.to_string())),
        }
        // SAFETY: `handler` là hàm `extern "system"` có chữ ký đúng PHANDLER_ROUTINE và sống suốt chương trình.
        unsafe { SetConsoleCtrlHandler(Some(handler), 1) != 0 }
    }

    pub fn uninstall() {
        // SAFETY: gỡ đúng con trỏ hàm đã cài ở `install`.
        unsafe {
            SetConsoleCtrlHandler(Some(handler), 0);
        }
        drop(take_copied());
    }
}

/// Các nền tảng khác: không có trình xử lý — không hứa rằng Ctrl+C sẽ xoá clipboard.
#[cfg(not(windows))]
mod ctrl_handler {
    pub fn install(_value: &str) -> bool {
        false
    }

    pub fn uninstall() {}
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pwv_vault_core::ConflictOutcome;

    fn entry(id: &str, title: &str, user: &str) -> Entry {
        let mut e = Entry::new(title);
        e.id = id.to_string();
        e.username = user.to_string();
        e
    }

    fn one<'a>(f: Found<'a>) -> &'a Entry {
        match f {
            Found::One(e) => e,
            Found::None => panic!("không thấy"),
            Found::Many(m) => panic!("nhiều mục: {}", m.len()),
        }
    }

    #[test]
    fn find_by_id_prefix_title_and_keyword() {
        let list = vec![
            entry("aaaa1111-x", "Gmail", "an@gmail.com"),
            entry("bbbb2222-x", "Gmail công việc", "an@congty.vn"),
            entry("cccc3333-x", "Ngân hàng", "an"),
        ];
        assert_eq!(one(find_target(&list, "bbbb")).title, "Gmail công việc");
        // Tiêu đề trùng khớp (không phân biệt hoa thường) thắng dù từ khoá khớp nhiều mục.
        assert_eq!(one(find_target(&list, "gmail")).id, "aaaa1111-x");
        assert_eq!(one(find_target(&list, "congty")).id, "bbbb2222-x");
        assert_eq!(one(find_target(&list, "NGÂN HÀNG")).id, "cccc3333-x");
        assert!(matches!(find_target(&list, "an"), Found::Many(m) if m.len() == 3));
        assert!(matches!(find_target(&list, "facebook"), Found::None));
        // Tiền tố id dưới 4 ký tự không được coi là id.
        assert!(matches!(find_target(&list, "aaa"), Found::None));
    }

    #[test]
    fn find_in_trash_is_separate_from_live_entries() {
        let live = vec![entry("aaaa1111", "Gmail", "a")];
        let trash = vec![entry("dddd4444", "Facebook", "b")];
        assert!(matches!(find_target(&live, "Facebook"), Found::None));
        assert_eq!(one(find_target(&trash, "facebook")).id, "dddd4444");
        assert_eq!(one(find_target(&trash, "dddd")).title, "Facebook");
        assert!(matches!(find_target(&trash, "Gmail"), Found::None));
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_utc(1_700_000_000_123), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_utc(1_709_251_199_999), "2024-02-29 23:59:59 UTC");
        assert_eq!(format_utc(-1), "1969-12-31 23:59:59 UTC");
        assert_eq!(format_utc(4_102_444_800_000), "2100-01-01 00:00:00 UTC");
    }

    #[test]
    fn notes_reader_stops_at_blank_line_or_eof() {
        let mut r = io::Cursor::new("mã khôi phục: 1234\r\ndòng 2\n\nkhông đọc tới đây\n");
        assert_eq!(
            read_notes_from(&mut r).unwrap().as_str(),
            "mã khôi phục: 1234\ndòng 2"
        );
        let mut r = io::Cursor::new("chỉ một dòng, không xuống dòng");
        assert_eq!(
            read_notes_from(&mut r).unwrap().as_str(),
            "chỉ một dòng, không xuống dòng"
        );
        let mut r = io::Cursor::new("\nbị bỏ qua");
        assert_eq!(read_notes_from(&mut r).unwrap().as_str(), "");
        let mut r = io::Cursor::new("");
        assert_eq!(read_notes_from(&mut r).unwrap().as_str(), "");
        let mut r = io::Cursor::new("  thụt lề giữ nguyên\n   \nhết");
        assert_eq!(
            read_notes_from(&mut r).unwrap().as_str(),
            "  thụt lề giữ nguyên"
        );
    }

    #[test]
    fn notes_are_masked_unless_revealed() {
        let masked = notes_display("mã 1\nmã 2", false);
        assert!(!masked.contains("mã"));
        assert!(masked.contains("2 dòng"));
        assert!(notes_display("mã 1\nmã 2", true).contains("mã 2"));
    }

    #[test]
    fn totp_validation() {
        assert_eq!(
            validate_totp("  JBSWY3DPEHPK3PXP \n").unwrap().as_str(),
            "JBSWY3DPEHPK3PXP"
        );
        assert!(validate_totp("không phải base32!").is_err());
    }

    #[test]
    fn save_report_messages() {
        let p = Path::new("vault.pwv.backups");
        assert!(save_report_lines(&SaveReport::default(), p).is_empty());
        let r = SaveReport {
            merged_remote: Some(MergeStats {
                added: 2,
                updated: 1,
                deleted: 0,
            }),
            adopted_remote_password: true,
            backup_failed: true,
        };
        let l = save_report_lines(&r, p);
        assert_eq!(l.len(), 3);
        assert!(l[0].contains("+2 mới, 1 cập nhật, 0 xoá"));
        assert!(l[1].contains("mật khẩu mới"));
        assert!(l[2].contains("vault.pwv.backups"));
    }

    #[test]
    fn sync_report_messages() {
        let p = Path::new("b");
        let l = sync_report_lines(&SyncReport::default(), p);
        assert!(l.last().unwrap().contains("không cần ghi lại"));
        let r = SyncReport {
            merged_remote: None,
            conflicts: vec![
                ConflictOutcome {
                    path: PathBuf::from("vault (1).pwv"),
                    result: Ok(MergeStats::default()),
                    archived: true,
                },
                ConflictOutcome {
                    path: PathBuf::from("vault (2).pwv"),
                    result: Ok(MergeStats::default()),
                    archived: false,
                },
                ConflictOutcome {
                    path: PathBuf::from("vault (3).pwv"),
                    result: Err(CoreError::VaultFileDamaged),
                    archived: false,
                },
            ],
            wrote: true,
            adopted_remote_password: false,
            backup_failed: false,
        };
        let l = sync_report_lines(&r, p).join("\n");
        assert!(l.contains("vault (1).pwv") && l.contains("đã cất vào thư mục sao lưu"));
        assert!(l.contains("vault (2).pwv: +0 mới, 0 cập nhật, 0 xoá — nhưng chưa cất được"));
        assert!(l.contains("Không gộp được vault (3).pwv") && l.contains("để nguyên tại chỗ"));
        assert!(l.contains("Đã ghi lại file kho."));
    }

    #[test]
    fn passwd_report_is_honest_about_old_copies() {
        let r = PasswordChangeReport {
            backups_reencrypted: 7,
            backups_skipped: 2,
            save: SaveReport::default(),
        };
        let l = passwd_report_lines(&r, Path::new("x.backups")).join("\n");
        assert!(l.contains("đã mã hoá lại 7 bản"));
        assert!(l.contains("2 bản KHÔNG mã hoá lại được"));
        assert!(l.contains("mật khẩu CŨ"));
        assert!(l.contains("điện thoại"));
        assert!(l.contains("ngân hàng, email"));
        let l = passwd_report_lines(&PasswordChangeReport::default(), Path::new("x")).join("\n");
        assert!(!l.contains("KHÔNG mã hoá lại được"));
    }

    #[test]
    fn delete_message_points_to_trash_not_backups() {
        let m = deleted_message("Gmail", "aaaa1111-2222");
        assert!(m.contains("thùng rác"));
        assert!(m.contains("pwv trash restore aaaa1111"));
        assert!(!m.contains("sao lưu"));
    }

    #[test]
    fn import_summary_lists_similar_and_bad_totp() {
        let res = ImportResult {
            duplicates: 3,
            skipped: 1,
            similar: vec!["Gmail (2)".into()],
            bad_totp: vec!["Bank".into()],
            detected: "Chrome",
            ..Default::default()
        };
        let l = import_summary_lines(&res, 5).join("\n");
        assert!(l.contains("Đã nhập 5 mục, bỏ qua 3 dòng trùng khớp hoàn toàn, 1 dòng trống"));
        assert!(l.contains("có vẻ trùng — hãy rà lại") && l.contains("• Gmail (2)"));
        assert!(l.contains("mã 2FA không đọc được, đã chép vào ghi chú") && l.contains("• Bank"));
    }

    #[test]
    fn error_advice_is_distinct() {
        let cases = [
            CoreError::PasswordChangedElsewhere,
            CoreError::VaultFileMissing("x".into()),
            CoreError::VaultFileDamaged,
            CoreError::UnsupportedVersion(9),
            CoreError::DifferentVault,
            CoreError::MoveIntoBackups,
        ];
        let texts: Vec<&str> = cases.iter().map(|e| advice(e).unwrap()).collect();
        for (i, a) in texts.iter().enumerate() {
            for b in &texts[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(texts[1].contains("pwv config") && texts[1].contains("KHÔNG tự tạo lại"));
        assert!(texts[2].contains("pwv recover"));
        assert!(texts[3].contains("cập nhật"));
        let msg = format!("{:#}", core_err(CoreError::VaultFileDamaged));
        assert!(msg.contains("pwv recover"));
        assert!(advice(&CoreError::SamePath).is_none());
    }

    #[test]
    fn rollback_warning_text() {
        let w = rollback_warning(&Rollback {
            seen_modified_at: 1_700_000_000_000,
            file_modified_at: 0,
            older_password: true,
        });
        assert!(w.contains("CŨ HƠN"));
        assert!(w.contains("2023-11-14 22:13:20 UTC"));
        assert!(w.contains("master password CŨ"));
    }

    #[test]
    fn clipboard_notice_only_promises_ctrl_c_when_it_works() {
        assert!(clipboard_notice(20, true).contains("Ctrl+C để xoá ngay"));
        let n = clipboard_notice(20, false);
        assert!(!n.contains("Ctrl+C để xoá ngay"));
        assert!(n.contains("đợi"));
        assert!(should_clear(Ok("abc"), "abc"));
        assert!(!should_clear(Ok("khác"), "abc"));
        assert!(!should_clear(
            Err(&arboard::Error::ContentNotAvailable),
            "abc"
        ));
        assert!(should_clear(Err(&arboard::Error::ClipboardOccupied), "abc"));
    }

    #[test]
    fn pick_backup_by_index_or_name() {
        let list = vec![
            BackupFile {
                path: PathBuf::from("d/vault-200.pwv"),
                kind: BackupKind::Auto,
                timestamp: 200,
            },
            BackupFile {
                path: PathBuf::from("d/merged-100-vault (1).pwv"),
                kind: BackupKind::Merged,
                timestamp: 100,
            },
        ];
        assert_eq!(pick_backup(&list, "1").unwrap().timestamp, 200);
        assert_eq!(pick_backup(&list, " 2 ").unwrap().timestamp, 100);
        assert_eq!(
            pick_backup(&list, "merged-100-vault (1).pwv")
                .unwrap()
                .timestamp,
            100
        );
        assert!(pick_backup(&list, "0").is_err());
        assert!(pick_backup(&list, "3").is_err());
        assert!(pick_backup(&list, "khong-co.pwv").is_err());
        let line = backup_line(1, &list[1], &Ok((4, 1)));
        assert!(
            line.contains("bản xung đột đã gộp") && line.contains("4 mục (+1 trong thùng rác)")
        );
        assert!(line.contains("1970-01-01 00:00:00 UTC"));
        assert!(backup_line(2, &list[0], &Err("hỏng".into())).contains("không đọc được: hỏng"));
    }

    #[test]
    fn same_content_ignores_times() {
        let a = entry("id", "A", "u");
        let mut b = a.clone();
        b.updated_at += 1000;
        b.field_times.title += 1000;
        assert!(same_content(&a, &b));
        b.password = "khác".into();
        assert!(!same_content(&a, &b));
    }

    #[test]
    fn yes_answers() {
        for y in ["y", "Y", "yes", "có", "Có", " c \n"] {
            assert!(is_yes(y), "{y}");
        }
        for n in ["", "n", "không", "yy"] {
            assert!(!is_yes(n), "{n}");
        }
    }

    #[test]
    fn detects_signs_of_an_existing_vault() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("vault.pwv");
        assert!(existing_vault_signs(&target).is_empty());
        std::fs::write(d.path().join("notes.txt"), b"x").unwrap();
        assert!(existing_vault_signs(&target).is_empty());
        std::fs::create_dir(backup_dir(&target)).unwrap();
        assert_eq!(existing_vault_signs(&target), vec![backup_dir(&target)]);
        std::fs::write(d.path().join("Passwords.PWV"), b"x").unwrap();
        assert_eq!(existing_vault_signs(&target).len(), 2);
    }
}
