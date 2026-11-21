//! `pwv` — công cụ dòng lệnh cho kho mật khẩu.
//!
//! Nguyên tắc:
//! - Mọi thay đổi đều đi qua [`Vault::transact`] (gộp file trên đĩa trước, hoàn tác nếu ghi lỗi).
//! - Bí mật (mật khẩu, secret 2FA, ghi chú) KHÔNG BAO GIỜ nhận qua tham số dòng lệnh, vì tham số
//!   bị lưu vào lịch sử lệnh của PowerShell/bash — luôn hỏi sau khi lệnh đã chạy.

use std::io::{self, BufRead, IsTerminal, Write};
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
        /// Nhập ghi chú (nhiều dòng, được có dòng trống) sau khi chạy lệnh — hỏi SAU mật khẩu;
        /// kết thúc bằng một dòng chỉ có dấu chấm `.` (hoặc Ctrl+Z rồi Enter trên Windows).
        #[arg(long)]
        notes: bool,
        /// Nhập secret 2FA (otpauth://... hoặc base32) sau khi chạy lệnh — được hỏi ẩn.
        #[arg(long)]
        totp: bool,
        /// Tự tạo mật khẩu ngẫu nhiên thay vì nhập (để trống khi được hỏi mật khẩu cũng được:
        /// pwv sẽ hỏi lại cho chắc).
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
        /// Nhập lại ghi chú (nhiều dòng, được có dòng trống) sau khi chạy lệnh; kết thúc bằng một
        /// dòng chỉ có dấu chấm `.`. Gõ `.` ngay dòng đầu = xoá ghi chú (pwv hỏi lại trước khi xoá).
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
    /// Sao chép vào clipboard, tự xoá sau vài giây: `gen` — mật khẩu vừa tạo; `add`/`edit` — mật
    /// khẩu mới của mục, sau khi đã lưu xong.
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
    let result = run(Cli::parse());
    // Phần thừa của một lần dán (dòng thứ hai trở đi) còn nằm trong bộ đệm bàn phím không được rơi
    // vào shell khi pwv thoát — shell sẽ chạy nó như một lệnh và lưu vào lịch sử. Cả khi lỗi.
    discard_leftover_input();
    if let Err(e) = result {
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
            if !rollback_gate(&v, is_mutating(&cmd))? {
                return Ok(());
            }
            vault_cmd(&mut v, cmd)?;
            remember_seen(&v);
            Ok(())
        }
    }
}

/// Lệnh này có ghi vào kho không (thêm/sửa/xoá, đồng bộ, đổi mật khẩu, chuyển kho...).
fn is_mutating(cmd: &Cmd) -> bool {
    match cmd {
        Cmd::List { .. }
        | Cmd::Show { .. }
        | Cmd::Copy { .. }
        | Cmd::Totp { .. }
        | Cmd::Health { .. }
        | Cmd::Backups => false,
        Cmd::Trash { action } => !matches!(action, None | Some(TrashCmd::List)),
        Cmd::Add { .. }
        | Cmd::Edit { .. }
        | Cmd::Delete { .. }
        | Cmd::Passwd
        | Cmd::Import { .. }
        | Cmd::Sync
        | Cmd::Move { .. }
        | Cmd::Restore { .. } => true,
        // Không mở kho qua `run` (tự xử lý riêng).
        Cmd::Init { .. } | Cmd::Gen(_) | Cmd::Config { .. } | Cmd::Recover { .. } => false,
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
            let (e, m) = resolve(v, &target)?;
            if m == Match::Partial {
                eprintln!("(\"{target}\" khớp một phần với mục dưới đây.)");
            }
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
            let (e, m) = resolve(v, &target)?;
            let value = Zeroizing::new(if username {
                e.username.clone()
            } else {
                e.password.clone()
            });
            eprintln!(
                "Đã chọn: {}{}",
                entry_label(e),
                if m == Match::Partial {
                    format!(" — \"{target}\" chỉ khớp một phần, hãy chắc đây đúng là mục bạn cần")
                } else {
                    String::new()
                }
            );
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
            // Thứ tự: các lời nhắc ẩn trước, ghi chú nhiều dòng SAU CÙNG — một lần dán ghi chú có
            // gì sai cũng không còn lời nhắc mật khẩu nào phía sau để "ăn" phần thừa.
            let (password, generated) = if generate {
                let (pw, bits) = gen.generate()?;
                eprintln!("{}", generated_line(bits));
                (pw, true)
            } else {
                prompt_account_password(&gen)?
            };
            let totp = if totp { prompt_totp()? } else { None };
            let notes = if notes {
                prompt_notes()?
            } else {
                Zeroizing::new(String::new())
            };
            let to_copy = gen.copy.then(|| password.clone());
            let mut e = Entry::new(title.clone());
            e.username = username;
            e.password = password.to_string();
            e.urls = url;
            e.tags = tag;
            e.notes = notes.to_string();
            e.totp = totp.map(|t| t.to_string());
            let id = commit(v, move |v| Ok(v.add(e)))?;
            let short = &id[..8.min(id.len())];
            println!("Đã thêm \"{title}\" ({short}).");
            if generated && to_copy.is_none() {
                println!("Mật khẩu là mật khẩu ngẫu nhiên vừa tạo — sao chép: `pwv copy {short}`.");
            }
            if let Some(pw) = to_copy {
                copy_to_clipboard(&pw)?;
            }
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
            let (e, m) = resolve(v, &target)?;
            let (id, label, had_notes) = (e.id.clone(), entry_label(e), !e.notes.is_empty());
            // Luôn cho thấy mục nào sắp bị sửa TRƯỚC khi hỏi hay đổi gì.
            eprintln!("Đang sửa: {label}");
            if !confirm_pick(&target, e, m, true, "Sửa mục này?")? {
                eprintln!("Chưa thay đổi gì.");
                return Ok(());
            }
            // Các lời nhắc ẩn trước, ghi chú nhiều dòng sau cùng (xem `add`).
            let new_pw = if generate {
                let (pw, bits) = gen.generate()?;
                eprintln!("{}", generated_line(bits));
                Some(pw)
            } else if password {
                let p = prompt_new_secret("Mật khẩu mới: ")?;
                if p.is_none() {
                    eprintln!("Không nhập mật khẩu — giữ nguyên mật khẩu cũ.");
                }
                p
            } else {
                None
            };
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
            let notes = if notes {
                let n = prompt_notes()?;
                if n.is_empty()
                    && had_notes
                    && !confirm("Ghi chú mới để trống — XOÁ ghi chú hiện có của mục này?")?
                {
                    eprintln!("Giữ nguyên ghi chú cũ.");
                    None
                } else {
                    Some(n)
                }
            } else {
                None
            };
            let to_copy = if gen.copy {
                if new_pw.is_none() {
                    eprintln!(
                        "(-c chỉ sao chép mật khẩu MỚI; lần sửa này không đổi mật khẩu nên không sao chép gì.)"
                    );
                }
                new_pw.clone()
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
            if changed {
                println!("Đã cập nhật {label}.");
            } else {
                println!("Không có gì thay đổi ở {label}.");
            }
            if let Some(pw) = to_copy {
                copy_to_clipboard(&pw)?;
            }
            Ok(())
        }
        Cmd::Delete { target, yes } => {
            let (e, m) = resolve(v, &target)?;
            let (id, title) = (e.id.clone(), e.title.clone());
            eprintln!("Mục: {}", entry_label(e));
            if !confirm_pick(
                &target,
                e,
                m,
                yes,
                &format!("Chuyển \"{title}\" vào thùng rác?"),
            )? {
                return Ok(());
            }
            let del = id.clone();
            commit(v, move |v| v.delete(&del))?;
            println!("{}", deleted_message(&title, &id));
            Ok(())
        }
        Cmd::Trash { action } => trash_cmd(v, action.unwrap_or(TrashCmd::List)),
        Cmd::Passwd => {
            let bdir = backup_dir(v.path());
            // Đồng bộ TRƯỚC khi hỏi mật khẩu mới (lõi cũng làm vậy bên trong `change_password`,
            // nhưng không trả kết quả): bản xung đột ghi bằng khoá hiện tại phải được gộp ngay bây
            // giờ, và chủ kho cần thấy kết quả.
            let pre = v.sync().map_err(core_err)?;
            for line in sync_report_lines(&pre, &bdir, false) {
                eprintln!("{line}");
            }
            // Đĩa / thư mục sao lưu đang có vấn đề: lần đổi mật khẩu cũng phải ghi lại mọi bản sao
            // lưu, bản nào ghi lỗi sẽ vẫn mở được bằng mật khẩu sắp bị thay.
            if passwd_disk_problem(&pre) {
                eprintln!("{}", passwd_disk_warning(&bdir));
                if !confirm_required(PASSWD_DISK_QUESTION, PASSWD_DISK_REFUSAL)? {
                    eprintln!("Chưa đổi master password.");
                    return Ok(());
                }
            }
            let (new, same) = prompt_new_master("Master password MỚI: ", Some(v))?;
            eprintln!(
                "Đang thay khoá kho và mã hoá lại kho + các bản sao lưu (Argon2id, có thể mất vài giây)..."
            );
            let r = v
                .change_password(new.as_bytes(), KdfParams::DEFAULT)
                .map_err(core_err)?;
            for line in save_report_lines(&r.save, &bdir) {
                eprintln!("{line}");
            }
            // Bản xung đột còn nằm cạnh kho lúc này (vừa xuất hiện, hoặc chưa cất được) đã thành "bản
            // ghi bằng mật khẩu cũ": đồng bộ thêm một lần để chuyển chúng (nguyên văn — vẫn mở bằng
            // mật khẩu CŨ) vào thư mục sao lưu, và nói thật điều đó trong báo cáo.
            let archived_after = match v.sync() {
                Ok(post) => {
                    if post.unverified {
                        eprintln!("{}", unverified_line());
                    }
                    if post.backup_failed {
                        eprintln!("{}", backup_failed_line(&bdir));
                    }
                    post.conflicts
                        .iter()
                        .filter(|c| {
                            c.archived && matches!(c.result, Err(CoreError::RetiredKeyCopy))
                        })
                        .count()
                }
                Err(e) => {
                    eprintln!(
                        "(Không đồng bộ lại được sau khi đổi mật khẩu: {e} — hãy chạy `pwv sync`.)"
                    );
                    0
                }
            };
            let leftovers = v.conflict_copies();
            for line in passwd_report_lines(&r, same, archived_after, &leftovers, &bdir) {
                println!("{line}");
            }
            Ok(())
        }
        Cmd::Sync => {
            let r = v.sync().map_err(core_err)?;
            for line in sync_report_lines(&r, &backup_dir(v.path()), true) {
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
            let (e, m) = resolve(v, &target)?;
            if m == Match::Partial {
                eprintln!("(\"{target}\" khớp một phần với {}.)", entry_label(e));
            }
            let t = Totp::parse(
                e.totp
                    .as_deref()
                    .ok_or_else(|| anyhow!("\"{}\" chưa có secret 2FA", e.title))?,
            )?;
            let (code, left) = t.now();
            println!("{code}");
            eprintln!("{} — còn hiệu lực {left} giây", entry_label(e));
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
                    v.add_imported(e);
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
                    format_time(e.trashed_at())
                );
            }
            println!();
            println!("Lấy lại: `pwv trash restore <ID|tên>` · Xoá vĩnh viễn: `pwv trash purge <ID|tên>` hoặc `pwv trash empty`.");
            Ok(())
        }
        TrashCmd::Restore { target } => {
            let (e, m) = resolve_trash(v, &target)?;
            let (id, title) = (e.id.clone(), e.title.clone());
            eprintln!("Mục trong thùng rác: {}", entry_label(e));
            if !confirm_pick(&target, e, m, true, "Lấy mục này ra khỏi thùng rác?")? {
                return Ok(());
            }
            commit(v, move |v| v.restore(&id))?;
            println!("Đã lấy \"{title}\" ra khỏi thùng rác.");
            Ok(())
        }
        TrashCmd::Purge { target, yes } => {
            let (e, m) = resolve_trash(v, &target)?;
            let (id, title) = (e.id.clone(), e.title.clone());
            eprintln!("Mục trong thùng rác: {}", entry_label(e));
            if !confirm_pick(
                &target,
                e,
                m,
                yes,
                &format!(
                    "Xoá VĨNH VIỄN \"{title}\"? Mục sẽ bị xoá trên MỌI thiết bị khi đồng bộ và không lấy lại được (trừ khi một bản sao lưu cũ còn giữ nó)."
                ),
            )? {
                return Ok(());
            }
            commit(v, move |v| v.purge(&id))?;
            println!("Đã xoá vĩnh viễn \"{title}\".");
            Ok(())
        }
        TrashCmd::Empty { yes } => {
            // Chỉ xoá ĐÚNG những mục chủ kho thấy lúc xác nhận: trong lúc chờ trả lời, máy khác có
            // thể chuyển thêm mục vào thùng rác (lần ghi sẽ gộp chúng vào trước khi xoá).
            let confirmed: Vec<String> = v.trash().iter().map(|e| e.id.clone()).collect();
            let n = confirmed.len();
            if n == 0 {
                println!("Thùng rác trống.");
                return Ok(());
            }
            for e in v.trash() {
                eprintln!("  {}  {}", short_id(e), truncate(&e.title, 40));
            }
            if !yes
                && !confirm(&format!(
                    "Xoá VĨNH VIỄN {n} mục trên? Các mục sẽ bị xoá trên MỌI thiết bị khi đồng bộ và không lấy lại được."
                ))?
            {
                return Ok(());
            }
            let removed = commit(v, move |v| Ok(v.purge_trashed(&confirmed)))?;
            for line in trash_empty_lines(n, removed, v.trash().len()) {
                println!("{line}");
            }
            Ok(())
        }
    }
}

fn trash_empty_lines(confirmed: usize, removed: usize, left: usize) -> Vec<String> {
    let mut out = vec![format!("Đã xoá vĩnh viễn {removed} mục.")];
    if removed < confirmed {
        out.push(format!(
            "{} mục trong danh sách đã không còn trong thùng rác (máy khác vừa lấy ra hoặc đã xoá) — không đụng tới.",
            confirmed - removed
        ));
    }
    if left > 0 {
        out.push(format!(
            "Thùng rác vẫn còn {left} mục KHÔNG có trong danh sách bạn vừa xác nhận (có thể máy khác vừa \
             chuyển vào) — chúng KHÔNG bị xoá. Xem: `pwv trash`."
        ));
    }
    out
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
    let mut any_old = false;
    for (i, b) in list.iter().enumerate() {
        let count = v
            .read_backup_checked(&b.path)
            .map(|(d, retired)| BackupCount {
                entries: d.entries.len(),
                trash: d.trash.len(),
                retired,
            })
            .map_err(|e| e.to_string());
        any_old |= count
            .as_ref()
            .is_ok_and(|c| backup_from_old_password(b.kind, c.retired));
        println!("{}", backup_line(i + 1, b, &count));
    }
    println!();
    if any_old {
        println!("{}", OLD_PASSWORD_BACKUP_NOTE);
        println!();
    }
    // Chỉ quét ở đây (lệnh này vốn đã đọc mọi bản sao lưu), không quét ở mọi lệnh.
    match v.backups_under_other_password() {
        Ok(0) => {}
        Ok(n) => {
            println!(
                "{}",
                other_password_backups_advice(n, &backup_dir(v.path()))
            );
            println!();
        }
        Err(e) => eprintln!("(Không kiểm tra được thư mục sao lưu: {e})"),
    }
    println!("Lấy lại: `pwv restore --from <số> <ID|tên>` hoặc `pwv restore --from <số> --all`.");
    Ok(())
}

/// Nội dung một bản sao lưu (để liệt kê).
struct BackupCount {
    entries: usize,
    trash: usize,
    /// Chỉ mở được bằng khoá của một master password CŨ.
    retired: bool,
}

/// Nội dung của bản sao lưu đến từ một bản ghi bằng master password CŨ: hoặc file chỉ mở được bằng
/// khoá cũ (`retired`, bất kể tên/loại file — ai có quyền ghi vào thư mục cũng đổi tên được), hoặc
/// bản `oldkey-…` (bản cất nguyên văn; ở bản pwv trước nó được mã hoá lại nên `retired` có thể là
/// false, nhưng nội dung vẫn đến từ một bản ghi bằng khoá cũ — có thể do người biết mật khẩu cũ làm).
fn backup_from_old_password(kind: BackupKind, retired: bool) -> bool {
    retired || kind == BackupKind::OldKey
}

const OLD_PASSWORD_BACKUP_NOTE: &str =
    "⚠  Bản có dấu ⚠: có từ TRƯỚC lần đổi master password gần nhất, hoặc được ghi bằng một master \
     password CŨ. Sau mỗi lần đổi mật khẩu, mọi bản sao lưu cũ hơn đều mang dấu này — thường đó chỉ \
     là lịch sử thật của bạn, hoặc bản do một máy chưa biết mật khẩu mới ghi ra. Nhưng người biết \
     mật khẩu cũ cũng có thể đã đặt hay sửa chúng trước khi bạn đổi. pwv không bao giờ tự dùng những \
     bản này; bạn vẫn lấy lại từng mục được — chỉ khi chắc đó là của bạn, và hãy kiểm tra kỹ (nhất \
     là địa chỉ trang web và số tài khoản).";

const OLD_PASSWORD_RESTORE_WARNING: &str = "⚠  CẢNH BÁO: bản sao lưu này có từ TRƯỚC lần đổi master password gần nhất, hoặc được ghi \
     bằng một master password CŨ. Có thể đó là bản thật của bạn — nhưng ai biết mật khẩu cũ cũng làm \
     ra hoặc sửa được một bản như vậy trong thư mục sao lưu (ví dụ để thay địa chỉ trang web ngân \
     hàng bằng trang giả).\n   Chỉ tiếp tục nếu bạn nhận ra các mục và địa chỉ trang web ở trên.";

fn restore_cmd(
    v: &mut Vault,
    from: &str,
    target: Option<&str>,
    all: bool,
    yes: bool,
) -> Result<()> {
    let list = v.backups();
    let b = pick_backup(&list, from)?.clone();
    let (data, retired) = v.read_backup_checked(&b.path).map_err(core_err)?;
    let from_old_password = backup_from_old_password(b.kind, retired);
    let mut partial = false;
    let olds: Vec<Entry> = if all {
        data.entries
            .iter()
            .filter(|o| v.get(&o.id).is_none_or(|cur| !same_content(cur, o)))
            .cloned()
            .collect()
    } else {
        let t = target.unwrap_or_default();
        let old = match find_target(&data.entries, t) {
            Found::One(e, m) => {
                if m == Match::Partial {
                    eprintln!("{}", partial_match_note(t, e));
                    partial = true;
                }
                e
            }
            Found::None => bail!(
                "bản sao lưu lúc {} không có mục \"{t}\"",
                format_time(b.timestamp)
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
        format_time(b.timestamp),
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
        if from_old_password {
            // Bản này có thể do người khác làm ra: cho thấy địa chỉ trang web sẽ được đưa vào kho.
            for u in &o.urls {
                println!("            trang web: {u}");
            }
        }
    }
    if all {
        println!("(Các mục được thêm sau thời điểm đó không bị ảnh hưởng.)");
    }
    let go = if from_old_password {
        eprintln!("{}", OLD_PASSWORD_RESTORE_WARNING);
        // Không bỏ qua được bằng -y.
        confirm_required(
            "Vẫn lấy lại các mục trên từ bản này?",
            "bản sao lưu này có từ trước lần đổi master password / được ghi bằng mật khẩu cũ nên cần \
             bạn xác nhận trực tiếp ở cửa sổ dòng lệnh (không dùng được -y). Chưa thay đổi gì.",
        )?
    } else if partial {
        confirm_required("Tiếp tục?", &partial_refusal(target.unwrap_or_default()))?
    } else {
        yes || confirm("Tiếp tục?")?
    };
    if !go {
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
        BackupKind::OldKey => "ghi bằng master password cũ (chưa gộp)",
    }
}

fn backup_line(index: usize, b: &BackupFile, count: &Result<BackupCount, String>) -> String {
    let content = match count {
        Ok(c) => {
            let mut s = if c.trash == 0 {
                format!("{} mục", c.entries)
            } else {
                format!("{} mục (+{} trong thùng rác)", c.entries, c.trash)
            };
            if c.retired {
                s.push_str(
                    "  ⚠ từ trước lần đổi mật khẩu / ghi bằng mật khẩu cũ — app không tự dùng",
                );
            } else if b.kind == BackupKind::OldKey {
                s.push_str("  ⚠ nội dung từ bản ghi bằng mật khẩu cũ — app không tự dùng");
            }
            s
        }
        Err(e) => format!("không đọc được: {e}"),
    };
    format!(
        "{index:>3}  {}  {:<20} {content}  [{}]",
        format_time(b.timestamp),
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
    let (pw, _) = prompt_new_master("Master password: ", None)?;
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
    let pw = prompt_hidden("Master password: ")?;
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
            "(Kho được mở nhờ một bản mới hơn của nó (bản xung đột hoặc bản sao lưu) — chạy `pwv sync` \
             để ghi lại file kho.)"
        );
    }
    Ok(v)
}

/// Cảnh báo khi kho vừa mở cũ hơn / không nối tiếp kho máy này từng thấy.
///
/// Lệnh chỉ đọc: in cảnh báo rồi chạy tiếp. Lệnh ghi: DỪNG và hỏi (mặc định: không). Trước đây cảnh
/// báo chỉ in một lần rồi lệnh ghi chạy luôn; lần ghi đó đẩy mốc "đã thấy" lên, nên từ lần sau
/// không lệnh nào cảnh báo nữa và các mục bị thiếu chỉ còn nằm trong bản sao lưu.
/// Đồng ý ⇒ lấy trạng thái hiện tại làm mốc mới (`accept_as_seen`). Không có người để hỏi ⇒ từ chối.
/// Trả về false nếu chủ kho không đồng ý (không làm gì thêm).
fn rollback_gate(v: &Vault, mutating: bool) -> Result<bool> {
    let mut c = Config::load();
    let Some(r) = v.rollback_against(&c) else {
        return Ok(true);
    };
    eprintln!("{}", rollback_warning(&r));
    if !mutating {
        return Ok(true);
    }
    eprintln!();
    if !confirm_required(ROLLBACK_QUESTION, ROLLBACK_REFUSAL)? {
        eprintln!("Đã dừng — chưa thay đổi gì.");
        return Ok(false);
    }
    v.accept_as_seen(&mut c);
    if let Err(e) = c.save() {
        eprintln!("(Không ghi được file cấu hình: {e} — lần sau máy này sẽ cảnh báo lại.)");
    }
    Ok(true)
}

const ROLLBACK_QUESTION: &str =
    "Lệnh này sẽ GHI vào kho. Bạn đã kiểm tra và vẫn muốn tiếp tục với kho \
     này? (y = chấp nhận kho như hiện tại; máy này sẽ thôi cảnh báo về nó)";

const ROLLBACK_REFUSAL: &str = "kho có cảnh báo ở trên nên lệnh ghi vào kho cần bạn xác nhận trực \
     tiếp — hãy chạy lại lệnh trong cửa sổ dòng lệnh (PowerShell). Chưa thay đổi gì.\n   Để xem và \
     lấy lại các mục có thể bị thiếu: `pwv backups` rồi `pwv restore --from <số> --all`.";

fn rollback_warning(r: &Rollback) -> String {
    let mut s = String::new();
    if r.file_modified_at < r.seen_modified_at {
        s.push_str(&format!(
            "⚠  CẢNH BÁO: file kho này CŨ HƠN bản mà máy này đã từng thấy (máy này đã thấy nội dung \
             sửa lúc {}, còn file hiện tại chỉ tới {}).\n   Có thể dịch vụ đồng bộ \
             (Drive/Dropbox/OneDrive) đã khôi phục một bản cũ, hoặc ai đó đã chép đè file cũ lên — \
             các mục thêm/sửa gần đây có thể bị THIẾU.",
            format_time(r.seen_modified_at),
            format_time(r.file_modified_at)
        ));
        if r.older_password {
            s.push_str(
                "\n   File này còn dùng master password CŨ hơn lần đổi mật khẩu gần nhất mà máy này biết.",
            );
        }
    } else if r.older_password {
        s.push_str(
            "⚠  CẢNH BÁO: file kho này dùng master password CŨ hơn lần đổi mật khẩu gần nhất mà máy này \
             biết.\n   Có thể đây là một bản từ TRƯỚC lần đổi đó (dịch vụ đồng bộ khôi phục nhầm, hoặc \
             ai đó chép đè file cũ lên) — những gì thêm/sửa sau lần đổi mật khẩu có thể bị THIẾU.",
        );
    }
    if r.unknown_key {
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str(
            "⚠  CẢNH BÁO: kho vừa mở KHÔNG nối tiếp từ kho mà máy này dùng lần trước — bạn vừa nhập \
             một master password CŨ, hoặc file kho đã bị thay bằng một file khác (người biết mật khẩu \
             cũ làm được việc này).\n   Nếu bạn đã đổi master password: đừng dùng kho này, hãy mở \
             lại bằng mật khẩu HIỆN TẠI. Đừng tin các địa chỉ trang web / mật khẩu trong kho này cho \
             tới khi kiểm tra xong.",
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
    if v.note_seen_in(&mut c) {
        if let Err(e) = c.save() {
            eprintln!("(Không ghi được file cấu hình: {e})");
        }
    }
}

fn recover(path: &Path, yes: bool) -> Result<()> {
    let pw = prompt_hidden("Master password: ")?;
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
    // Hai trường hợp lõi không tự dựng lại mà cần chủ kho chọn rõ ràng (không bỏ qua được bằng -y:
    // chỉ người ngồi trước máy mới quyết được): mật khẩu CŨ, hoặc mật khẩu đúng nhưng chỉ còn các bản
    // có từ TRƯỚC lần đổi mật khẩu.
    let first = Vault::recover_from_backups(path, pw.as_bytes(), OpenOptions::default());
    let (warning, question, refusal) = match &first {
        Err(CoreError::OlderPasswordBackups) => (
            OLDER_PASSWORD_RECOVERY_WARNING,
            "Vẫn dựng lại kho từ các bản sao lưu CŨ này (quay về master password cũ)?",
            "mật khẩu vừa nhập chỉ mở được các bản sao lưu từ TRƯỚC lần đổi master password gần \
             nhất — dựng lại từ chúng cần bạn xác nhận trực tiếp ở cửa sổ dòng lệnh. Chưa thay đổi \
             gì. Tốt nhất: chạy lại `pwv recover` với master password HIỆN TẠI.",
        ),
        Err(CoreError::OnlyPreChangeBackups) => (
            ONLY_PRE_CHANGE_WARNING,
            "Vẫn dựng lại kho từ các bản sao lưu có từ TRƯỚC lần đổi mật khẩu?",
            "chỉ còn các bản sao lưu có từ TRƯỚC lần đổi master password — dựng lại từ chúng cần bạn \
             xác nhận trực tiếp ở cửa sổ dòng lệnh. Chưa thay đổi gì. Trước hết hãy tìm một bản mới \
             hơn trong lịch sử phiên bản / thùng rác của dịch vụ đồng bộ hoặc trên máy khác.",
        ),
        _ => ("", "", ""),
    };
    let pre_change = matches!(first, Err(CoreError::OnlyPreChangeBackups));
    let (mut v, used, newest, older) = match first {
        Ok((v, used, newest)) => (v, used, newest, false),
        Err(CoreError::OlderPasswordBackups | CoreError::OnlyPreChangeBackups) => {
            eprintln!("{warning}");
            if !confirm_required(question, refusal)? {
                eprintln!("Chưa thay đổi gì.");
                return Ok(());
            }
            let (v, used, newest) =
                Vault::recover_from_backups_opts(path, pw.as_bytes(), OpenOptions::default(), true)
                    .map_err(core_err)?;
            (v, used, newest, !pre_change)
        }
        Err(e) => return Err(core_err(e)),
    };
    // Lõi chỉ biết những gì có trong thư mục sao lưu (con số `key_changed_at` trong đó ai cũng sửa
    // được). Máy này còn nhớ khoá nó đã dùng: nếu kho vừa dựng dùng mật khẩu CŨ hơn, hoặc không nối
    // tiếp khoá đó, thì mật khẩu vừa nhập rất có thể là mật khẩu cũ (hoặc các bản sao lưu đã bị thay)
    // ⇒ hỏi như trên trước khi ghi bất cứ thứ gì. Kiểm tra cả khi chỉ còn bản `pre_change`: một bản
    // cũ được chép lại vào thư mục sao lưu vẫn mang gói khoá của mật khẩu CŨ (cli-fix-review#1).
    let mut stale = None;
    let older = older
        || match v.rollback_against(&Config::load()) {
            Some(r) if r.older_password || r.unknown_key => {
                eprintln!("{OLDER_THAN_THIS_PC_WARNING}");
                if !confirm_required(
                    "Vẫn dựng lại kho từ các bản sao lưu này?",
                    "máy này đã từng dùng một master password MỚI HƠN mật khẩu vừa nhập — dựng lại kho \
                     cần bạn xác nhận trực tiếp ở cửa sổ dòng lệnh. Chưa thay đổi gì. Tốt nhất: chạy lại \
                     `pwv recover` với master password HIỆN TẠI.",
                )? {
                    eprintln!(
                        "Chưa thay đổi gì. Hãy chạy lại `pwv recover` và nhập master password HIỆN TẠI."
                    );
                    return Ok(());
                }
                true
            }
            Some(r) if r.file_modified_at < r.seen_modified_at => {
                stale = Some(r);
                false
            }
            _ => false,
        };
    // Cùng khoá, chỉ là CŨ HƠN nội dung máy này từng thấy: thường do các bản sao lưu mới hơn chưa
    // đồng bộ về máy này. Hỏi trước khi ghi (không bỏ qua được bằng -y); chỉ sau khi ghi xong mới
    // lấy trạng thái này làm mốc mới (`accept_as_seen` ở dưới).
    if let Some(r) = &stale {
        eprintln!("{}", stale_recovery_warning(r));
        if !confirm_required(STALE_RECOVERY_QUESTION, STALE_RECOVERY_REFUSAL)? {
            eprintln!("Chưa thay đổi gì.");
            return Ok(());
        }
    }
    println!(
        "Tìm thấy {} mục (+{} trong thùng rác), gộp từ {used} file sao lưu; bản sao lưu mới nhất \
         dùng được tạo lúc {}, nội dung sửa lần cuối lúc {}.",
        v.entries().len(),
        v.trash().len(),
        format_time(newest),
        format_time(v.modified_at())
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
    if older {
        eprintln!(
            "⚠  Kho dựng lại dùng master password bạn vừa nhập (cũ hơn mật khẩu máy này từng dùng), và chỉ có dữ liệu tới lần đổi \
             mật khẩu đó. Hãy kiểm tra các mục quan trọng, rồi nên đổi master password (`pwv passwd`)."
        );
    }
    if pre_change {
        eprintln!(
            "⚠  Kho được dựng lại từ các bản sao lưu có từ TRƯỚC lần đổi master password: những gì \
             thêm/sửa sau lần đổi không có ở đây. Hãy kiểm tra lại ĐỊA CHỈ TRANG WEB và mật khẩu của các \
             tài khoản quan trọng (ngân hàng, email) trước khi dùng — nếu mật khẩu cũ từng bị lộ, nội \
             dung các bản đó có thể đã bị sửa."
        );
    } else if stale.is_some() {
        eprintln!(
            "(Kho dựng lại cũ hơn bản máy này từng thấy — hãy kiểm tra xem có mục nào bị thiếu. Nếu \
             sau này các bản mới hơn đồng bộ về, lấy lại từng mục bằng `pwv backups` rồi \
             `pwv restore --from <số> <mục>`.)"
        );
    }
    v.accept_as_seen(&mut c);
    if let Err(e) = c.save() {
        eprintln!("(Không ghi được file cấu hình: {e})");
    }
    Ok(())
}

const OLDER_PASSWORD_RECOVERY_WARNING: &str = "⚠  Mật khẩu bạn vừa nhập có vẻ là một master password CŨ: nó chỉ mở được các bản sao lưu tạo \
     TRƯỚC lần đổi master password gần nhất, còn thư mục sao lưu có bản dùng một master password đặt \
     SAU đó.\n   Nếu dựng lại kho từ các bản đó: kho quay về mật khẩu cũ này, và MỌI thứ đã thêm/sửa \
     sau lần đổi mật khẩu sẽ KHÔNG có trong kho dựng lại.\n   Nên làm: trả lời N, rồi chạy lại \
     `pwv recover` với master password HIỆN TẠI (mật khẩu đặt gần đây nhất). Nếu một máy tính / điện \
     thoại khác vẫn mở được kho, hãy dùng máy đó.\n   Chỉ trả lời y nếu bạn chắc chắn không còn cách \
     nào mở bằng mật khẩu hiện tại.";

/// Chỉ nói điều đã biết chắc: mật khẩu này mở được các bản có từ TRƯỚC một lần đổi master password,
/// và không mở được bản nào ghi sau lần đổi đó. KHÔNG khẳng định đó là mật khẩu hiện tại, cũng không
/// khẳng định các bản mới hơn đã mất (có thể chúng chưa đồng bộ về, hoặc dùng một mật khẩu khác).
const ONLY_PRE_CHANGE_WARNING: &str = "⚠  Mật khẩu bạn vừa nhập chỉ mở được các bản sao lưu có từ TRƯỚC lần đổi master password gần \
     nhất: không bản sao lưu nào ghi SAU lần đổi đó mở được bằng mật khẩu này. Có thể các bản mới hơn \
     đã mất hoặc chưa đồng bộ về máy này — hoặc chúng dùng một master password khác (mới hơn).\n   pwv \
     không tự dùng các bản này: nếu bạn đổi mật khẩu vì nghi nó đã bị lộ, người biết mật khẩu cũ có \
     thể đã sửa chúng trước khi bạn đổi (ví dụ thay địa chỉ trang web ngân hàng).\n   Nên làm trước: \
     thử lại với master password đặt gần đây nhất; tìm một bản mới hơn của file kho trong lịch sử \
     phiên bản / thùng rác của Google Drive, Dropbox, OneDrive, hoặc trên máy tính / điện thoại khác. \
     Chỉ trả lời y nếu không còn bản nào khác.";

const STALE_RECOVERY_QUESTION: &str = "Vẫn dựng lại kho từ các bản sao lưu CŨ HƠN này?";

const STALE_RECOVERY_REFUSAL: &str = "kho dựng lại cũ hơn nội dung máy này đã từng thấy — dựng lại cần \
     bạn xác nhận trực tiếp ở cửa sổ dòng lệnh (không dùng được -y). Chưa thay đổi gì. Hãy đợi dịch \
     vụ đồng bộ tải xong thư mục sao lưu rồi chạy lại `pwv recover`.";

/// Kho dựng lại dùng đúng khoá máy này biết, nhưng nội dung cũ hơn nội dung máy này đã từng thấy.
fn stale_recovery_warning(r: &Rollback) -> String {
    format!(
        "⚠  Kho dựng lại CŨ HƠN nội dung mà máy này đã từng thấy: máy này đã thấy nội dung sửa lúc \
         {}, còn kho dựng lại chỉ tới {}. Những gì thêm/sửa sau thời điểm đó sẽ KHÔNG có trong kho \
         dựng lại.\n   Có thể các bản sao lưu mới hơn chưa đồng bộ về máy này. Nên làm trước: đợi \
         Google Drive / Dropbox / OneDrive đồng bộ xong rồi chạy lại `pwv recover`; xem máy tính / \
         điện thoại khác còn mở được kho không; hoặc tìm một bản mới hơn của file kho trong lịch sử \
         phiên bản trên trang web của dịch vụ đồng bộ.",
        format_time(r.seen_modified_at),
        format_time(r.file_modified_at)
    )
}

const OLDER_THAN_THIS_PC_WARNING: &str = "⚠  Máy này đã từng mở kho này bằng một master password MỚI HƠN mật khẩu bạn vừa nhập (hoặc \
     các bản sao lưu tìm được không nối tiếp kho mà máy này dùng lần trước).\n   Nếu dựng lại từ \
     chúng: kho quay về mật khẩu vừa nhập, và những gì thêm/sửa sau đó có thể KHÔNG có trong kho dựng \
     lại; nếu ai đó biết mật khẩu cũ đã đặt các bản này vào, kho dựng lại là kho của họ.\n   Nên làm: \
     trả lời N, rồi chạy lại `pwv recover` với master password HIỆN TẠI.";

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
    if r.old_key_archived {
        out.push(
            "⚠  File kho trên đĩa được ghi bằng một master password CŨ nên KHÔNG được gộp vào thay đổi \
             vừa rồi: nó đã được cất vào thư mục sao lưu, rồi file kho được ghi lại từ bản bạn đang mở."
                .to_string(),
        );
        out.push(old_key_explanation(true));
    }
    if r.backup_failed {
        out.push(backup_failed_line(backups));
    }
    if r.unverified {
        out.push(unverified_line());
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

/// Ý nghĩa của "bản ghi bằng master password cũ" và cách xem lại nó. `main_file`: chính file kho
/// là bản đó (một máy chưa biết mật khẩu mới đã ghi đè lên nó).
fn old_key_explanation(main_file: bool) -> String {
    let mut s = String::from(
        "   Nghĩa là: một máy chưa biết lần đổi master password gần nhất đã ghi bản đó — HOẶC ai đó \
         biết mật khẩu cũ đã đặt nó vào.",
    );
    s.push_str(
        " Vì vậy pwv không tự gộp nó; nó được chuyển NGUYÊN VĂN vào thư mục sao lưu (tên `oldkey-…`, \
         vẫn chỉ mở được bằng mật khẩu CŨ), có ghi chú \"ghi bằng master password cũ\".\n   Nếu trên \
         máy kia bạn đã thêm/sửa gì cần giữ: xem `pwv backups`, rồi lấy từng mục bằng \
         `pwv restore --from <số> <mục>` (kiểm tra kỹ địa chỉ trang web). Trên máy kia, hãy mở khoá \
         bằng master password MỚI.",
    );
    if main_file {
        s.push_str(
            " Nếu máy kia đã ghi ĐÈ lên file kho: kho bạn đang mở được lấy từ bản mới nhất dùng mật \
             khẩu hiện tại (bản sao lưu hoặc bản xung đột), nên không mất gì đã lưu bằng mật khẩu đó.",
        );
    }
    s
}

fn unverified_line() -> String {
    "⚠  Đã ghi file kho nhưng đọc lại không kiểm tra được (thường do phần mềm diệt virus hoặc dịch \
     vụ đồng bộ đang giữ file). Thay đổi KHÔNG bị huỷ — nó đã được ghi ra file kho và (nếu chép được) \
     vào thư mục sao lưu. Lát nữa hãy chạy `pwv sync` để kiểm tra lại; nếu thông báo này cứ lặp lại, \
     có phần mềm nào đó đang giữ file kho."
        .to_string()
}

/// `verbose = false`: chỉ những gì đáng báo (dùng trước khi đổi mật khẩu).
fn sync_report_lines(r: &SyncReport, backups: &Path, verbose: bool) -> Vec<String> {
    let mut out = Vec::new();
    match &r.merged_remote {
        Some(s) => out.push(format!(
            "Đã nạp thay đổi từ máy khác: {}.",
            merge_stats_text(s)
        )),
        None if verbose => {
            out.push("File kho trên đĩa không có thay đổi mới từ máy khác.".to_string())
        }
        None => {}
    }
    let mut retired_archived = 0;
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
            // Không in lời nhắn của lỗi: nó nói "đã cất vào thư mục sao lưu", sai khi chưa cất được.
            Err(CoreError::RetiredKeyCopy) if c.archived => {
                retired_archived += 1;
                out.push(format!(
                    "⚠  {name}: được ghi bằng master password CŨ nên KHÔNG được gộp — đã cất vào thư \
                     mục sao lưu (ghi chú \"ghi bằng master password cũ\") và gỡ khỏi chỗ cũ."
                ));
            }
            Err(CoreError::RetiredKeyCopy) => out.push(format!(
                "⚠  {name}: được ghi bằng master password CŨ nên KHÔNG được gộp, và chưa cất được vào \
                 thư mục sao lưu — vẫn để nguyên tại chỗ; lần đồng bộ sau sẽ thử lại."
            )),
            Err(e) if c.archived => out.push(format!(
                "⚠  Không gộp {name}: {e} — đã cất vào thư mục sao lưu."
            )),
            Err(e) => out.push(format!(
                "⚠  Không gộp được {name}: {e} — để nguyên tại chỗ."
            )),
        }
    }
    // Số bản khoá cũ được cất = file kho chính (nếu có) + các bản xung đột ở trên.
    let main_file = r.old_key_archived > retired_archived;
    if main_file {
        out.push(
            "⚠  File kho trên đĩa được ghi bằng master password CŨ nên KHÔNG được gộp: nó đã được cất \
             vào thư mục sao lưu, rồi file kho được ghi lại từ bản bạn đang mở."
                .to_string(),
        );
    }
    if r.old_key_archived > 0 {
        out.push(old_key_explanation(main_file));
    }
    if r.adopted_remote_password {
        out.push(adopted_password_line());
    }
    if r.backup_failed {
        out.push(backup_failed_line(backups));
    }
    if r.unverified {
        out.push(unverified_line());
    }
    if verbose {
        out.push(if r.wrote && r.unverified {
            "Đã ghi lại file kho (chưa kiểm tra lại được — xem cảnh báo ở trên).".to_string()
        } else if r.wrote {
            "Đã ghi lại file kho.".to_string()
        } else {
            "File kho đã đầy đủ — không cần ghi lại.".to_string()
        });
    }
    out
}

/// `archived_after`: số bản xung đột (ghi bằng khoá vừa bị thay) được cất ngay sau khi đổi, đã mã
/// hoá lại bằng mật khẩu mới. `leftovers`: các bản cùng kho vẫn còn nằm cạnh file kho.
/// `same`: master password mới chính là mật khẩu hiện tại (chỉ thay khoá mã hoá).
fn passwd_report_lines(
    r: &PasswordChangeReport,
    same: bool,
    archived_after: usize,
    leftovers: &[PathBuf],
    backups: &Path,
) -> Vec<String> {
    let mut out = vec![if same {
        "Mật khẩu giữ nguyên; khoá mã hoá đã được thay mới — một mật khẩu CŨ KHÁC (đổi bằng bản \
         0.1.x) không còn mở được kho và các bản sao lưu đã mã hoá lại."
            .to_string()
    } else {
        "Đã đổi master password và thay khoá mã hoá của kho.".to_string()
    }];
    if r.save.unverified {
        out.push(if same {
            "⚠  File kho với khoá mới đã được ghi nhưng CHƯA đọc lại kiểm tra được. Hãy chạy \
             `pwv sync` ngay (mở khoá bằng chính master password này)."
                .to_string()
        } else {
            "⚠  File kho với mật khẩu mới đã được ghi nhưng CHƯA đọc lại kiểm tra được. Hãy chạy \
             `pwv sync` ngay, mở khoá bằng mật khẩu MỚI. Nếu mật khẩu mới bị báo sai, thử mật khẩu cũ \
             (có thể máy khác vừa ghi đè) rồi đổi lại."
                .to_string()
        });
    }
    let mut b = if same {
        format!(
            "Bản sao lưu trên máy này: đã mã hoá lại {} bản bằng khoá mới (vẫn mở bằng master \
             password hiện tại; một mật khẩu cũ khác không còn đọc được chúng). Các bản đó vẫn dùng \
             được để lấy lại từng mục bằng tay (`pwv restore`), nhưng từ nay app không bao giờ tự dùng \
             chúng nữa — `pwv backups` sẽ đánh dấu ⚠ \"từ trước lần đổi mật khẩu\"",
            r.backups_reencrypted
        )
    } else {
        format!(
            "Bản sao lưu trên máy này: đã mã hoá lại {} bản bằng mật khẩu mới (mật khẩu cũ không còn \
             đọc được chúng). Các bản đó vẫn dùng được để lấy lại từng mục bằng tay (`pwv restore`), \
             nhưng từ nay app không bao giờ tự dùng chúng nữa — `pwv backups` sẽ đánh dấu ⚠ \"từ trước \
             lần đổi mật khẩu\"",
            r.backups_reencrypted
        )
    };
    if r.backups_skipped > 0 {
        b.push_str(&format!(
            "; {} bản để nguyên: không phải file kho / lớn quá 64 MiB, hoặc chỉ mở được \
             bằng một master password CŨ HƠN nữa (từ trước lần đổi trước, bản `oldkey-…` đã cất, hoặc do \
             người khác đặt vào) — những bản đó vẫn mở được bằng mật khẩu cũ tương ứng, nhưng không bao \
             giờ được tự gộp vào kho (xem `pwv backups`, trong {})",
            r.backups_skipped,
            backups.display()
        ));
    }
    b.push('.');
    out.push(b);
    if !r.backups_failed.is_empty() {
        out.push(format!(
            "⚠  {} bản sao lưu không đọc hoặc không ghi lại được (lỗi đĩa, hoặc file đang bị dịch vụ \
             đồng bộ / phần mềm diệt virus giữ): {}. Các bản này VẪN có thể mở bằng {}. Hãy xoá các \
             file đó trong thư mục sao lưu nếu mật khẩu cũ có thể đã lộ: {}",
            r.backups_failed.len(),
            r.backups_failed.join(", "),
            if same {
                "khoá cũ — tức cả bằng một mật khẩu cũ khác (đổi bằng bản 0.1.x), nếu nó từng mở được kho"
            } else {
                "master password vừa bị thay"
            },
            backups.display()
        ));
    }
    if archived_after > 0 {
        out.push(format!(
            "⚠  {archived_after} bản xung đột có từ trước lần đổi này đã được chuyển NGUYÊN VĂN vào thư \
             mục sao lưu (tên `oldkey-…`): chúng VẪN mở được bằng mật khẩu CŨ. Nếu mật khẩu cũ có thể \
             đã lộ và bạn không cần lấy lại gì từ chúng, hãy xoá các file `oldkey-…` đó trong {}.",
            backups.display()
        ));
    }
    if !leftovers.is_empty() {
        let names: Vec<String> = leftovers
            .iter()
            .map(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default()
            })
            .collect();
        out.push(format!(
            "⚠  Cạnh file kho vẫn còn {} bản của kho này chưa cất được: {}. Bản nào được ghi trước lần \
             đổi này vẫn mở được bằng mật khẩu CŨ — chạy `pwv sync` để thử cất lại, hoặc tự xoá chúng.",
            leftovers.len(),
            names.join(", ")
        ));
    }
    out.push(String::new());
    out.push(if same {
        "⚠  Lưu ý: những bản sao ĐÃ RỜI KHỎI máy này vẫn dùng khoá cũ — mở được bằng master password \
         hiện tại và bằng mật khẩu cũ (đổi bằng bản 0.1.x) — và chứa dữ liệu tại thời điểm đó:"
            .to_string()
    } else {
        "⚠  Lưu ý: những bản sao ĐÃ RỜI KHỎI máy này vẫn mở được bằng mật khẩu CŨ và chứa dữ liệu tại thời điểm đó:"
            .to_string()
    });
    out.push(
        "   • lịch sử phiên bản và thùng rác trên cloud (Google Drive, Dropbox, OneDrive);"
            .to_string(),
    );
    out.push("   • bản offline trên điện thoại;".to_string());
    out.push(
        "   • các bản `oldkey-…` (ghi bằng mật khẩu cũ, chưa gộp) trong thư mục sao lưu — pwv giữ chúng nguyên văn;"
            .to_string(),
    );
    out.push("   • các máy tính khác chưa đồng bộ.".to_string());
    out.push(
        "   Nếu mật khẩu cũ có thể đã bị lộ, hãy đổi mật khẩu của các tài khoản quan trọng (ngân hàng, email)."
            .to_string(),
    );
    out.push(if same {
        "Các thiết bị khác vẫn mở khoá bằng chính master password này. Một máy chưa biết lần thay khoá \
         này mà ghi vào kho thì bản nó ghi KHÔNG được gộp, mà được cất vào thư mục sao lưu (xem \
         `pwv backups`)."
            .to_string()
    } else {
        "Các thiết bị khác sẽ hỏi mật khẩu mới ở lần mở khoá tới. Một máy chưa biết lần đổi này mà ghi \
         vào kho thì bản nó ghi KHÔNG được gộp, mà được cất vào thư mục sao lưu (xem `pwv backups`)."
            .to_string()
    });
    out
}

/// Lần đồng bộ ngay trước khi đổi mật khẩu cho thấy đĩa có vấn đề (không chép được bản sao lưu,
/// hoặc đọc lại file vừa ghi không khớp).
fn passwd_disk_problem(pre: &SyncReport) -> bool {
    pre.backup_failed || pre.unverified
}

fn passwd_disk_warning(backups: &Path) -> String {
    format!(
        "⚠  Đĩa hoặc thư mục sao lưu đang có vấn đề (xem cảnh báo ở trên). Đổi master password cũng \
         phải ghi lại mọi bản sao lưu trong {} bằng mật khẩu mới — bản nào ghi lỗi sẽ VẪN mở được \
         bằng mật khẩu cũ. Nên làm trước: kiểm tra dung lượng đĩa, đợi dịch vụ đồng bộ / phần mềm \
         diệt virus thôi giữ file, chạy `pwv sync` cho tới khi hết cảnh báo, rồi mới đổi mật khẩu.",
        backups.display()
    )
}

const PASSWD_DISK_QUESTION: &str = "Vẫn đổi master password ngay bây giờ?";

const PASSWD_DISK_REFUSAL: &str =
    "đĩa hoặc thư mục sao lưu đang có vấn đề nên đổi master password cần \
     bạn xác nhận trực tiếp ở cửa sổ dòng lệnh. Chưa đổi gì.";

/// Lời khuyên khi có bản sao lưu dùng một master password KHÁC mà vẫn mở ra được khoá hiện tại
/// (thường do đã đổi mật khẩu bằng bản 0.1.x, bản đó đổi mật khẩu mà giữ nguyên khoá mã hoá).
fn other_password_backups_advice(n: usize, backups: &Path) -> String {
    format!(
        "⚠  LỜI KHUYÊN: {n} bản sao lưu trong {} dùng một master password KHÁC mật khẩu bạn vừa nhập \
         nhưng vẫn mở ra được khoá mã hoá HIỆN TẠI của kho (thường do lần đổi master password trước \
         đây được làm bằng bản pwv 0.1.x — bản đó đổi mật khẩu mà giữ nguyên khoá). Ai biết mật khẩu \
         cũ đó và có một bản sao của thư mục đồng bộ thì đọc được cả kho hiện tại.\n   Cách sửa: \
         chạy `pwv passwd` MỘT lần, trên MỘT máy (khoá app trên các máy khác trong lúc đó). Nếu mật \
         khẩu hiện tại vẫn an toàn, bạn có thể nhập lại chính nó làm mật khẩu mới: pwv giữ nguyên mật \
         khẩu, chỉ thay khoá mã hoá và mã hoá lại các bản sao lưu — kể cả khi mật khẩu đó chưa đạt \
         chính sách mới (khi đó pwv nhắc bạn đổi sang mật khẩu mạnh hơn sau). (Bản cũ trong lịch sử \
         phiên bản trên cloud thì pwv không với tới được.)",
        backups.display()
    )
}

fn deleted_message(title: &str, id: &str) -> String {
    let short = &id[..8.min(id.len())];
    format!(
        "Đã chuyển \"{title}\" vào thùng rác. Lấy lại: `pwv trash restore {short}` · Xoá vĩnh viễn: `pwv trash purge {short}`."
    )
}

fn import_summary_lines(res: &ImportResult, imported: usize) -> Vec<String> {
    let mut out = vec![format!(
        "Định dạng: {}. Đã nhập {imported} mục, bỏ qua {} dòng trùng khớp hoàn toàn (với mục đã có \
         hoặc với dòng khác trong file), {} dòng trống.",
        res.detected, res.duplicates, res.skipped
    )];
    if imported > 0 {
        out.push(
            "Mục nhập từ file được coi là \"chưa sửa lần nào\": nhập cùng file này trên máy khác không \
             sinh mục trùng khi đồng bộ, và không đè lên những gì bạn đã sửa ở bất kỳ máy nào. (Nhập \
             lại trên CHÍNH máy này một mục bạn đã sửa sẽ thêm một bản nữa — hãy rà lại.)"
                .to_string(),
        );
    }
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
        // Chỉ còn đến từ việc tạo lại file kho đã biến mất (`pwv recover`): KHÔNG có gì bị hoàn tác.
        CoreError::WriteVerifyFailed => {
            "File kho vừa được tạo lại nhưng đọc lại không khớp (thường do phần mềm diệt virus hoặc dịch \
             vụ đồng bộ đang giữ file). Không có gì bị huỷ hay xoá: trước khi ghi, bản dựng lại đã được \
             chép vào thư mục sao lưu (nếu chép được). Đợi một lát rồi chạy lại `pwv recover`: nếu file \
             kho mở được bình thường thì đã xong; nếu không, pwv sẽ dựng lại lần nữa."
        }
        CoreError::NoUsableBackup => {
            "Không có gì bị ghi hay xoá. Cách lấy lại:\n   • Trang web Google Drive / Dropbox / OneDrive: \
             mở file kho → Lịch sử phiên bản (Manage versions) → tải một bản cũ hơn về máy, rồi chạy \
             `pwv config <file-vừa-tải>`.\n   • Thùng rác của dịch vụ đồng bộ (nếu file bị xoá).\n   \
             • Một máy tính / điện thoại khác còn mở được kho.\n   • Nếu thư mục sao lưu chưa đồng bộ \
             xong về máy này, đợi rồi chạy lại `pwv recover`."
        }
        CoreError::OnlyPreChangeBackups => {
            "Mật khẩu vừa nhập chỉ mở được các bản sao lưu có từ TRƯỚC lần đổi master password gần \
             nhất. Hãy thử lại với master password đặt gần đây nhất, và tìm một bản mới hơn của file kho \
             trong lịch sử phiên bản / thùng rác của Google Drive, Dropbox, OneDrive, hoặc trên máy khác. \
             Nếu không còn: chạy `pwv recover` trong cửa sổ dòng lệnh và xác nhận dựng lại từ các bản \
             cũ đó."
        }
        CoreError::OlderPasswordBackups => {
            "Dựng lại từ các bản đó sẽ đưa kho về master password CŨ và mất mọi thay đổi sau lần đổi \
             mật khẩu. Hãy chạy lại `pwv recover` với master password HIỆN TẠI."
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

/// Mục được tìm thấy bằng cách nào.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    /// Tiền tố ID (≥ 4 ký tự), đúng một mục.
    Id,
    /// Tiêu đề trùng khớp (không phân biệt hoa thường).
    Title,
    /// Chỉ khớp MỘT PHẦN (một đoạn của tiêu đề, username, URL hay tag): dễ trúng nhầm mục khác,
    /// ví dụ `pwv edit vcb -g` trúng một mục có "vcb" trong username.
    Partial,
}

enum Found<'a> {
    One(&'a Entry, Match),
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
            return Found::One(by_id[0], Match::Id);
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
        return Found::One(exact[0], Match::Title);
    }
    match found.len() {
        0 => Found::None,
        1 => Found::One(found[0], Match::Partial),
        _ => Found::Many(found),
    }
}

/// "Gmail công việc (bbbb2222)".
fn entry_label(e: &Entry) -> String {
    format!("{} ({})", e.title, short_id(e))
}

fn partial_match_note(target: &str, e: &Entry) -> String {
    format!(
        "Lưu ý: \"{target}\" không phải ID hay tên đầy đủ — nó chỉ khớp MỘT PHẦN với \"{}\" (username: \
         {}, trang web: {}).",
        e.title,
        if e.username.is_empty() { "—" } else { &e.username },
        e.urls.first().map(String::as_str).unwrap_or("—")
    )
}

fn partial_refusal(target: &str) -> String {
    format!(
        "\"{target}\" chỉ khớp một phần với tên mục nên cần bạn xác nhận trực tiếp ở cửa sổ dòng \
         lệnh — hoặc dùng ID (xem `pwv list`) hay tên đầy đủ của mục. Chưa thay đổi gì."
    )
}

/// Xác nhận một thao tác sửa trên mục `e` (đã in tên mục ở trên). `yes` (cờ `-y`, hoặc lệnh không
/// có câu hỏi riêng) bỏ qua câu hỏi — TRỪ KHI mục chỉ khớp một phần: khi đó luôn phải hỏi trực
/// tiếp người dùng.
fn confirm_pick(target: &str, e: &Entry, m: Match, yes: bool, question: &str) -> Result<bool> {
    if m == Match::Partial {
        eprintln!("{}", partial_match_note(target, e));
        return confirm_required(question, &partial_refusal(target));
    }
    if yes {
        return Ok(true);
    }
    confirm(question)
}

fn print_ambiguous(found: &[&Entry]) {
    eprintln!("Có {} mục khớp:", found.len());
    for e in found {
        eprintln!("  {}  {}  ({})", short_id(e), e.title, e.username);
    }
}

/// Tìm trong các mục đang dùng.
fn resolve<'a>(v: &'a Vault, target: &str) -> Result<(&'a Entry, Match)> {
    match find_target(v.entries(), target) {
        Found::One(e, m) => Ok((e, m)),
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
fn resolve_trash<'a>(v: &'a Vault, target: &str) -> Result<(&'a Entry, Match)> {
    match find_target(v.trash(), target) {
        Found::One(e, m) => Ok((e, m)),
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

/// Như [`format_utc`], nhưng mốc ≤ 1000 ms (0 = "chưa biết", 1 = mục nhập từ CSV — xem
/// `IMPORTED_AT` của lõi) hiện là "—" thay vì một ngày năm 1970 vô nghĩa.
fn format_time(ms: i64) -> String {
    if ms <= 1000 {
        "—".to_string()
    } else {
        format_utc(ms)
    }
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
    // Chữ còn sót trong bộ đệm bàn phím (ví dụ phần thừa của một lần dán) không được tự trả lời
    // câu hỏi này.
    discard_pending_input();
    eprint!("{msg}");
    io::stderr().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    discard_leftover_input();
    Ok(s)
}

fn confirm(msg: &str) -> Result<bool> {
    let a = prompt_line(&format!("{msg} [y/N] "))?;
    Ok(is_yes(&a))
}

/// Câu hỏi có/không mà CHỈ người ngồi trước bàn phím được trả lời (không nhận câu trả lời qua
/// đường ống / file, không bỏ qua được bằng `-y`). Không có cửa sổ dòng lệnh ⇒ dừng với `refusal`.
fn confirm_required(question: &str, refusal: &str) -> Result<bool> {
    let interactive = io::stdin().is_terminal();
    if interactive {
        discard_pending_input();
        eprint!("{question} [y/N] ");
        io::stderr().flush()?;
    }
    let answer = ask_yes_no_from(&mut io::stdin().lock(), interactive)?;
    discard_leftover_input();
    match answer {
        Some(yes) => Ok(yes),
        None => bail!("{refusal}"),
    }
}

/// Đọc một câu trả lời có/không (mặc định: KHÔNG). `None` = không có người để hỏi.
fn ask_yes_no_from(r: &mut impl BufRead, interactive: bool) -> io::Result<Option<bool>> {
    if !interactive {
        return Ok(None);
    }
    let mut a = String::new();
    r.read_line(&mut a)?;
    Ok(Some(is_yes(&a)))
}

fn is_yes(a: &str) -> bool {
    matches!(
        a.trim().to_lowercase().as_str(),
        "y" | "yes" | "c" | "có" | "co"
    )
}

/// Ghi chú kết thúc thế nào.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotesEnd {
    /// Một dòng chỉ có dấu chấm `.`.
    Dot,
    /// Hết dữ liệu (Ctrl+Z rồi Enter trên Windows, Ctrl+D trên máy khác, hoặc hết file).
    Eof,
}

/// Đọc ghi chú nhiều dòng cho tới một dòng chỉ có `.` hoặc hết dữ liệu (EOF).
///
/// Dòng trống là MỘT PHẦN của ghi chú. (Trước đây ghi chú dừng ở dòng trống đầu tiên: khi dán mã
/// khôi phục chia thành nhiều đoạn, phần sau dòng trống nằm lại trong bộ đệm bàn phím, bị lời nhắc
/// mật khẩu ẩn đọc làm mật khẩu, còn phần sót lại thì shell chạy như một lệnh và lưu vào lịch sử.)
/// Các dòng trống ở cuối được bỏ đi.
fn read_notes_from(r: &mut impl BufRead) -> io::Result<(Zeroizing<String>, NotesEnd)> {
    let mut out = Zeroizing::new(String::with_capacity(4096));
    let mut line = Zeroizing::new(String::with_capacity(1024));
    let mut first = true;
    let end = loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break NotesEnd::Eof;
        }
        let l = line.trim_end_matches(['\n', '\r']);
        if l.trim() == "." {
            break NotesEnd::Dot;
        }
        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(l);
    };
    // Bỏ các dòng trống ở cuối (giữ nguyên dòng cuối có chữ, kể cả khoảng trắng của nó).
    let (mut keep, mut pos) = (0, 0);
    for l in out.split('\n') {
        if !l.trim().is_empty() {
            keep = pos + l.len();
        }
        pos += l.len() + 1;
    }
    out.truncate(keep);
    Ok((out, end))
}

fn notes_prompt_text() -> String {
    format!(
        "Nhập ghi chú (nhiều dòng, được có dòng trống). Kết thúc bằng một dòng chỉ có dấu chấm `.` \
         rồi Enter, hoặc {}:",
        if cfg!(windows) {
            "Ctrl+Z rồi Enter"
        } else {
            "Ctrl+D"
        }
    )
}

fn prompt_notes() -> Result<Zeroizing<String>> {
    discard_pending_input();
    eprintln!("{}", notes_prompt_text());
    let (notes, _) = read_notes_from(&mut io::stdin().lock())?;
    // Những gì còn sót sau dấu `.` (phần thừa của một lần dán) không được rơi vào shell khi pwv
    // thoát — shell sẽ chạy chúng như lệnh và lưu vào lịch sử.
    discard_pending_input();
    Ok(notes)
}

/// Hỏi một bí mật, ẩn khi gõ (đọc thẳng từ cửa sổ dòng lệnh, không qua stdin).
///
/// Xả bộ đệm bàn phím TRƯỚC khi hỏi (chữ còn sót lại — phần thừa của một lần dán — không được
/// thành mật khẩu) và SAU khi đọc: `rpassword` dừng ở dấu xuống dòng đầu tiên, nên các dòng sau của
/// một lần dán nhiều dòng (mã PIN, mã khôi phục...) sẽ nằm lại và bị shell chạy như một lệnh, lưu
/// vào lịch sử lệnh.
fn prompt_hidden(msg: &str) -> Result<Zeroizing<String>> {
    discard_pending_input();
    let read = rpassword::prompt_password(msg).map(Zeroizing::new);
    READ_FROM_TERMINAL.store(true, std::sync::atomic::Ordering::Relaxed);
    term::flush_input();
    match read {
        Ok(s) => Ok(s),
        Err(_) if !term::has_terminal() => bail!("{}", no_terminal_message(msg)),
        Err(e) => Err(anyhow!(e).context("không đọc được mật khẩu từ cửa sổ dòng lệnh")),
    }
}

/// Không có cửa sổ dòng lệnh (chạy từ Task Scheduler, một lối tắt không có console, `setsid`...):
/// nói rõ thay vì in lỗi của hệ điều hành ("No such device or address (os error 6)").
fn no_terminal_message(prompt: &str) -> String {
    let what = if prompt.starts_with("Master password") {
        "master password"
    } else {
        "mật khẩu (ẩn khi gõ)"
    };
    format!(
        "pwv cần một cửa sổ dòng lệnh để hỏi {what} — hãy chạy lệnh trong PowerShell / Terminal \
         (pwv không nhận mật khẩu qua đường ống hay file)."
    )
}

/// Đã có lần đọc thẳng từ cửa sổ dòng lệnh (lời nhắc ẩn) trong lần chạy này.
static READ_FROM_TERMINAL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Xả những gì đang chờ trong bộ đệm bàn phím của cửa sổ dòng lệnh (chưa được chương trình đọc).
fn discard_pending_input() {
    term::flush_input();
}

/// Như [`discard_pending_input`], dùng SAU một lần đọc và khi thoát: chỉ khi pwv thật sự đọc từ cửa
/// sổ dòng lệnh (stdin là cửa sổ dòng lệnh, hoặc đã có lời nhắc ẩn). Chạy với stdin là đường ống /
/// file (script, test) mà không hỏi gì ẩn thì không đụng tới cửa sổ dòng lệnh nào. (Xả bộ đệm của
/// cửa sổ dòng lệnh không bao giờ lấy mất dữ liệu của một đường ống.)
fn discard_leftover_input() {
    if io::stdin().is_terminal() || READ_FROM_TERMINAL.load(std::sync::atomic::Ordering::Relaxed) {
        term::flush_input();
    }
}

/// Unix: `tcflush(TCIFLUSH)` trên `/dev/tty` — đúng thiết bị mà `rpassword` đọc mật khẩu.
/// Khai báo trực tiếp hàm của thư viện C (đã được link sẵn) để không phải thêm crate `libc`.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod term {
    use std::ffi::c_int;
    use std::os::fd::AsRawFd;

    extern "C" {
        fn tcflush(fd: c_int, queue_selector: c_int) -> c_int;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TCIFLUSH: c_int = 0;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const TCIFLUSH: c_int = 1;

    /// Có terminal điều khiển (`/dev/tty` mở được) — nơi `rpassword` đọc mật khẩu.
    pub fn has_terminal() -> bool {
        std::fs::File::open("/dev/tty").is_ok()
    }

    pub fn flush_input() {
        // Không có terminal điều khiển (chạy từ script, dịch vụ) ⇒ không có gì để xả.
        if let Ok(tty) = std::fs::File::open("/dev/tty") {
            // SAFETY: fd hợp lệ trong suốt lời gọi (`tty` còn sống); tcflush không giữ con trỏ nào.
            unsafe {
                tcflush(tty.as_raw_fd(), TCIFLUSH);
            }
        }
    }
}

/// Windows: `FlushConsoleInputBuffer` trên `CONIN$` — bộ đệm bàn phím của cửa sổ console, nơi
/// `rpassword` đọc mật khẩu (kể cả khi stdin bị chuyển hướng).
#[cfg(windows)]
mod term {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::System::Console::FlushConsoleInputBuffer;

    /// Có cửa sổ console (`CONIN$` mở được) — nơi `rpassword` đọc mật khẩu.
    pub fn has_terminal() -> bool {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
            .is_ok()
    }

    pub fn flush_input() {
        // Cần quyền ghi trên handle bộ đệm nhập của console.
        if let Ok(con) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
        {
            // SAFETY: handle hợp lệ trong suốt lời gọi (`con` còn sống).
            unsafe {
                FlushConsoleInputBuffer(con.as_raw_handle() as _);
            }
        }
    }
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
mod term {
    pub fn has_terminal() -> bool {
        true
    }

    pub fn flush_input() {}
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
        let s =
            prompt_hidden("Secret 2FA (otpauth://... hoặc base32, ẩn khi gõ; Enter để bỏ qua): ")?;
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
///
/// `current` (khi đổi mật khẩu): nhập lại ĐÚNG master password hiện tại được chấp nhận kể cả khi nó
/// chưa đạt chính sách mới — đó là thay khoá mã hoá, không phải chọn mật khẩu mới (lời khuyên của
/// `pwv backups` cho kho từng đổi mật khẩu ở bản 0.1.x). Khi đó chỉ cảnh báo. Trả về (mật khẩu, có
/// phải chính mật khẩu hiện tại không).
fn prompt_new_master(msg: &str, current: Option<&Vault>) -> Result<(Zeroizing<String>, bool)> {
    loop {
        let a = prompt_hidden(msg)?;
        if a.is_empty() {
            bail!("không được để trống");
        }
        let c = check_master_password(&a);
        // Một lượt Argon2 (như khi mở khoá).
        let same = current.is_some_and(|v| v.verify_password(a.as_bytes()));
        if same {
            eprintln!("{SAME_MASTER_NOTE}");
            if !c.ok {
                eprintln!("{}", same_master_weak_warning(&c.message));
            }
        } else if !c.ok {
            eprintln!("Chưa dùng được: {}", c.message);
            eprintln!(
                "Gợi ý: chạy `pwv gen -p -w 6` để lấy một cụm 6 từ ngẫu nhiên, rồi viết ra giấy."
            );
            continue;
        }
        let b = prompt_hidden("Nhập lại: ")?;
        if *a != *b {
            eprintln!("Hai lần nhập không khớp, thử lại.");
            continue;
        }
        return Ok((a, same));
    }
}

const SAME_MASTER_NOTE: &str =
    "(Đây là master password hiện tại: pwv giữ nguyên mật khẩu, chỉ thay \
     khoá mã hoá mới và mã hoá lại kho cùng các bản sao lưu.)";

fn same_master_weak_warning(reason: &str) -> String {
    format!(
        "⚠  Mật khẩu hiện tại chưa đạt chính sách của bản pwv này: {reason}\n   Lần này pwv vẫn giữ nó \
         (chỉ thay khoá mã hoá), nhưng hãy sớm đổi sang một mật khẩu mạnh hơn: chạy lại `pwv passwd` \
         và nhập một cụm 5–6 từ ngẫu nhiên (ví dụ từ `pwv gen -p -w 6`)."
    )
}

/// Nhập mật khẩu tài khoản 2 lần (cảnh báo nếu yếu). Để trống = `None`.
fn prompt_new_secret(msg: &str) -> Result<Option<Zeroizing<String>>> {
    loop {
        let a = prompt_hidden(msg)?;
        if a.is_empty() {
            return Ok(None);
        }
        let b = prompt_hidden("Nhập lại: ")?;
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

/// Mật khẩu cho mục mới: nhập (2 lần), hoặc — chỉ khi chủ kho trả lời rõ "có" — tạo ngẫu nhiên.
/// Trả về (mật khẩu, có phải vừa tự tạo không).
fn prompt_account_password(gen: &GenArgs) -> Result<(Zeroizing<String>, bool)> {
    loop {
        if let Some(p) = prompt_new_secret("Mật khẩu của tài khoản (ẩn khi gõ): ")? {
            return Ok((p, false));
        }
        // Trước đây để trống = lặng lẽ tạo mật khẩu ngẫu nhiên: một dòng trống còn sót lại từ lần
        // dán ghi chú là đủ để mật khẩu thật bị thay bằng một mật khẩu không ai biết.
        if confirm("Để trống. Tạo mật khẩu ngẫu nhiên?")? {
            let (pw, bits) = gen.generate()?;
            eprintln!("{}", generated_line(bits));
            return Ok((pw, true));
        }
        eprintln!(
            "Hãy nhập mật khẩu của tài khoản (hoặc để trống rồi trả lời y để tạo ngẫu nhiên)."
        );
    }
}

fn generated_line(bits: f64) -> String {
    format!("Đã tạo mật khẩu ngẫu nhiên (≈ {bits:.0} bit) — đây là mật khẩu sẽ được lưu.")
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
            Found::One(e, _) => e,
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

    fn notes(input: &str) -> (String, NotesEnd, String) {
        let mut r = io::Cursor::new(input.to_string());
        let (n, end) = read_notes_from(&mut r).unwrap();
        let mut rest = String::new();
        io::Read::read_to_string(&mut r, &mut rest).unwrap();
        (n.to_string(), end, rest)
    }

    #[test]
    fn notes_reader_keeps_blank_lines_and_stops_only_at_dot_or_eof() {
        // Đúng đoạn dán của reviewer: dòng trống là một phần của ghi chú.
        let (n, end, rest) =
            notes("Recovery codes:\n\ncode-1111\ncode-2222\n\ncode-3333\n.\nsau dấu chấm\n");
        assert_eq!(n, "Recovery codes:\n\ncode-1111\ncode-2222\n\ncode-3333");
        assert_eq!(end, NotesEnd::Dot);
        assert_eq!(rest, "sau dấu chấm\n", "không đọc quá dòng `.`");
        // Hết dữ liệu (Ctrl+D / Ctrl+Z) cũng kết thúc; CRLF của Windows được bỏ.
        let (n, end, _) = notes("mã khôi phục: 1234\r\n\r\ndòng 3\r\n");
        assert_eq!(n, "mã khôi phục: 1234\n\ndòng 3");
        assert_eq!(end, NotesEnd::Eof);
        let (n, end, _) = notes("chỉ một dòng, không xuống dòng");
        assert_eq!(
            (n.as_str(), end),
            ("chỉ một dòng, không xuống dòng", NotesEnd::Eof)
        );
        // `.` ngay dòng đầu (kể cả có khoảng trắng / CRLF) = ghi chú rỗng.
        assert_eq!(notes(" . \r\nkhông đọc\n").0, "");
        assert_eq!(notes("").0, "");
        assert_eq!(notes("\n\n\n").0, "");
        // Dòng trống ở cuối bị bỏ; thụt lề và dòng trống ở giữa giữ nguyên; dòng có dấu chấm
        // cùng chữ khác không phải dòng kết thúc.
        let (n, _, _) = notes("  thụt lề\n   \n..\nhết.\n\n  \n.\n");
        assert_eq!(n, "  thụt lề\n   \n..\nhết.");
        // Khoảng trắng cuối dòng có chữ cuối cùng được giữ.
        assert_eq!(notes("a  \n\n.\n").0, "a  ");
    }

    #[test]
    fn notes_prompt_explains_how_to_finish() {
        let t = notes_prompt_text();
        assert!(t.contains("dòng trống") && t.contains("dấu chấm `.`"));
        assert!(t.contains(if cfg!(windows) {
            "Ctrl+Z rồi Enter"
        } else {
            "Ctrl+D"
        }));
    }

    #[test]
    fn yes_no_needs_a_person_and_defaults_to_no() {
        let ask = |s: &str, i| ask_yes_no_from(&mut io::Cursor::new(s.to_string()), i).unwrap();
        assert_eq!(
            ask("y\n", false),
            None,
            "không có cửa sổ dòng lệnh: không được tự trả lời"
        );
        assert_eq!(ask("y\n", true), Some(true));
        assert_eq!(ask("có\r\n", true), Some(true));
        assert_eq!(ask("\n", true), Some(false));
        assert_eq!(ask("", true), Some(false), "hết dữ liệu = không");
        assert_eq!(ask("n\n", true), Some(false));
        assert_eq!(ask("yes please\n", true), Some(false));
    }

    #[test]
    fn mutating_commands_are_classified() {
        let m = |args: &[&str]| {
            let cli =
                Cli::try_parse_from(std::iter::once("pwv").chain(args.iter().copied())).unwrap();
            is_mutating(&cli.cmd)
        };
        for ro in [
            &["list"][..],
            &["ls", "x"],
            &["show", "x"],
            &["copy", "x"],
            &["totp", "x"],
            &["health", "--offline"],
            &["backups"],
            &["trash"],
            &["trash", "list"],
        ] {
            assert!(!m(ro), "{ro:?}");
        }
        for rw in [
            &["add", "x"][..],
            &["edit", "x", "-g"],
            &["delete", "x"],
            &["trash", "restore", "x"],
            &["trash", "purge", "x"],
            &["trash", "empty"],
            &["passwd"],
            &["import", "a.csv"],
            &["sync"],
            &["move", "b.pwv"],
            &["restore", "--from", "1", "--all"],
        ] {
            assert!(m(rw), "{rw:?}");
        }
    }

    #[test]
    fn copy_flag_is_accepted_by_add_and_edit() {
        let cli = Cli::try_parse_from(["pwv", "add", "Bank", "-g", "-c"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Add { generate: true, gen, .. } if gen.copy));
        let cli = Cli::try_parse_from(["pwv", "edit", "bank", "-g", "--copy"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Edit { generate: true, gen, .. } if gen.copy));
        assert!(generated_line(80.0).contains("≈ 80 bit"));
    }

    #[test]
    fn match_kind_tells_partial_matches_apart() {
        let mut vcb = entry("aaaa1111-x", "Vietcombank", "an");
        vcb.urls = vec!["https://vcbdigibank.vietcombank.com.vn".into()];
        let list = vec![vcb, entry("bbbb2222-x", "Gmail", "an.vcb@gmail.com")];
        assert!(matches!(
            find_target(&list, "aaaa"),
            Found::One(_, Match::Id)
        ));
        assert!(matches!(
            find_target(&list, "GMAIL"),
            Found::One(_, Match::Title)
        ));
        // "digibank" chỉ khớp URL của một mục.
        assert!(
            matches!(find_target(&list, "digibank"), Found::One(e, Match::Partial) if e.title == "Vietcombank")
        );
        assert!(matches!(find_target(&list, "vcb"), Found::Many(_)));
        let note = partial_match_note("digibank", &list[0]);
        assert!(
            note.contains("MỘT PHẦN")
                && note.contains("Vietcombank")
                && note.contains("vcbdigibank")
        );
        assert!(partial_match_note("x", &entry("cccc3333", "X", ""))
            .contains("username: —, trang web: —"));
        assert!(partial_refusal("digibank").contains("pwv list"));
        assert_eq!(entry_label(&list[1]), "Gmail (bbbb2222)");
    }

    #[test]
    fn times_up_to_one_second_are_unknown() {
        assert_eq!(format_time(0), "—");
        assert_eq!(format_time(1), "—", "IMPORTED_AT của mục nhập từ CSV");
        assert_eq!(format_time(1000), "—");
        assert_eq!(format_time(-5), "—");
        assert_eq!(format_time(1001), "1970-01-01 00:00:01 UTC");
        assert_eq!(format_time(1_700_000_000_123), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn trash_empty_reports_items_not_confirmed() {
        let l = trash_empty_lines(3, 3, 0);
        assert_eq!(l, vec!["Đã xoá vĩnh viễn 3 mục.".to_string()]);
        let l = trash_empty_lines(3, 2, 1).join("\n");
        assert!(l.contains("Đã xoá vĩnh viễn 2 mục."));
        assert!(l.contains("1 mục trong danh sách đã không còn"));
        assert!(l.contains("vẫn còn 1 mục KHÔNG có trong danh sách") && l.contains("KHÔNG bị xoá"));
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
            ..Default::default()
        };
        let l = save_report_lines(&r, p);
        assert_eq!(l.len(), 3);
        assert!(l[0].contains("+2 mới, 1 cập nhật, 0 xoá"));
        assert!(l[1].contains("mật khẩu mới"));
        assert!(l[2].contains("vault.pwv.backups"));
        let r = SaveReport {
            old_key_archived: true,
            unverified: true,
            ..Default::default()
        };
        let l = save_report_lines(&r, p).join("\n");
        assert!(l.contains("master password CŨ") && l.contains("KHÔNG được gộp"));
        assert!(l.contains("ai đó biết mật khẩu cũ") && l.contains("pwv backups"));
        assert!(l.contains("pwv restore --from"));
        assert!(
            l.contains("Thay đổi KHÔNG bị huỷ") && l.contains("pwv sync") && l.contains("lặp lại")
        );
    }

    #[test]
    fn sync_report_messages() {
        let p = Path::new("b");
        let l = sync_report_lines(&SyncReport::default(), p, true);
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
            ..Default::default()
        };
        let l = sync_report_lines(&r, p, true).join("\n");
        assert!(l.contains("vault (1).pwv") && l.contains("đã cất vào thư mục sao lưu"));
        assert!(l.contains("vault (2).pwv: +0 mới, 0 cập nhật, 0 xoá — nhưng chưa cất được"));
        assert!(l.contains("Không gộp được vault (3).pwv") && l.contains("để nguyên tại chỗ"));
        assert!(l.contains("Đã ghi lại file kho."));
        assert!(!l.contains("master password CŨ"));
    }

    #[test]
    fn sync_report_words_old_password_copies_correctly() {
        let p = Path::new("b");
        let r = SyncReport {
            conflicts: vec![
                ConflictOutcome {
                    path: PathBuf::from("vault (4).pwv"),
                    result: Err(CoreError::RetiredKeyCopy),
                    archived: true,
                },
                ConflictOutcome {
                    path: PathBuf::from("vault (5).pwv"),
                    result: Err(CoreError::RetiredKeyCopy),
                    archived: false,
                },
                ConflictOutcome {
                    path: PathBuf::from("vault (6).pwv"),
                    result: Err(CoreError::CopyUsesOtherPassword),
                    archived: false,
                },
            ],
            // (4) + file kho chính
            old_key_archived: 2,
            wrote: true,
            unverified: true,
            ..Default::default()
        };
        let lines = sync_report_lines(&r, p, true);
        let l = lines.join("\n");
        let line_of = |name: &str| lines.iter().find(|x| x.contains(name)).unwrap().clone();
        let l4 = line_of("vault (4).pwv");
        assert!(l4.contains("master password CŨ") && l4.contains("đã cất vào thư mục sao lưu"));
        assert!(
            !l4.contains("để nguyên"),
            "bản đã cất không được gọi là \"để nguyên tại chỗ\""
        );
        let l5 = line_of("vault (5).pwv");
        assert!(l5.contains("chưa cất được") && l5.contains("để nguyên tại chỗ"));
        assert!(!l5.contains("đã cất vào"), "{l5}");
        let l6 = line_of("vault (6).pwv");
        assert!(l6.contains("mật khẩu chính khác") && l6.contains("để nguyên tại chỗ"));
        // File kho chính cũng là bản khoá cũ ⇒ có dòng riêng, và lời giải thích chỉ in một lần.
        assert!(l.contains("File kho trên đĩa được ghi bằng master password CŨ"));
        assert_eq!(l.matches("Nghĩa là:").count(), 1);
        assert!(l.contains("ghi ĐÈ lên file kho") && l.contains("NGUYÊN VĂN"));
        assert!(
            !l.contains("mã hoá lại"),
            "bản oldkey-… được cất nguyên văn"
        );
        assert!(l.contains("pwv backups") && l.contains("pwv restore --from"));
        assert!(l.contains("đọc lại không kiểm tra được") && l.contains("chưa kiểm tra lại được"));
        // Chỉ bản xung đột là bản khoá cũ ⇒ không nói file kho chính là bản khoá cũ.
        let r = SyncReport {
            conflicts: vec![ConflictOutcome {
                path: PathBuf::from("vault (4).pwv"),
                result: Err(CoreError::RetiredKeyCopy),
                archived: true,
            }],
            old_key_archived: 1,
            ..Default::default()
        };
        let l = sync_report_lines(&r, p, true).join("\n");
        assert!(!l.contains("File kho trên đĩa được ghi"));
        assert!(l.contains("Nghĩa là:"));
        assert!(!l.contains("ghi ĐÈ lên file kho"));
        // Không chi tiết: không có dòng "không có thay đổi" / "không cần ghi lại".
        assert!(sync_report_lines(&SyncReport::default(), p, false).is_empty());
    }

    #[test]
    fn passwd_report_is_honest_about_old_copies() {
        let r = PasswordChangeReport {
            backups_reencrypted: 7,
            backups_skipped: 2,
            save: SaveReport::default(),
            ..Default::default()
        };
        let l = passwd_report_lines(&r, false, 0, &[], Path::new("x.backups")).join("\n");
        assert!(l.contains("đã mã hoá lại 7 bản"));
        assert!(l.contains("lấy lại từng mục bằng tay") && l.contains("không bao giờ tự dùng"));
        assert!(
            l.contains("2 bản để nguyên")
                && l.contains("CŨ HƠN nữa")
                && l.contains("không bao giờ được tự gộp")
        );
        assert!(l.contains("mật khẩu CŨ"));
        assert!(l.contains("điện thoại"));
        assert!(l.contains("ngân hàng, email"));
        assert!(!l.contains("CHƯA đọc lại") && !l.contains("Cạnh file kho"));
        let l = passwd_report_lines(
            &PasswordChangeReport::default(),
            false,
            0,
            &[],
            Path::new("x"),
        )
        .join("\n");
        assert!(!l.contains("để nguyên"));
        // Ghi chưa xác minh, bản xung đột vừa cất, bản còn sót cạnh kho.
        let r = PasswordChangeReport {
            save: SaveReport {
                unverified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let left = [PathBuf::from("d/vault (1).pwv")];
        let l = passwd_report_lines(&r, false, 2, &left, Path::new("x")).join("\n");
        assert!(l.contains("CHƯA đọc lại kiểm tra được") && l.contains("pwv sync"));
        assert!(
            l.contains("2 bản xung đột có từ trước lần đổi này")
                && l.contains("VẪN mở được bằng mật khẩu CŨ")
        );
        assert!(
            !l.contains("mã hoá lại bằng mật khẩu mới)"),
            "bản cất nguyên văn không được mã hoá lại"
        );
        assert!(
            l.contains("vẫn còn 1 bản") && l.contains("vault (1).pwv") && l.contains("mật khẩu CŨ")
        );
    }

    /// cli-fix-review#3: bản sao lưu ghi lại thất bại được nêu tên riêng, và nói thật rằng chúng vẫn
    /// mở được bằng mật khẩu vừa bị thay.
    #[test]
    fn passwd_report_names_backups_that_could_not_be_rewritten() {
        let r = PasswordChangeReport {
            backups_reencrypted: 3,
            backups_skipped: 1,
            backups_failed: vec!["vault-1700.pwv".into(), "merged-1800-vault (1).pwv".into()],
            ..Default::default()
        };
        let lines = passwd_report_lines(&r, false, 0, &[], Path::new("d/vault.pwv.backups"));
        let failed = lines
            .iter()
            .find(|l| l.contains("không đọc hoặc không ghi lại được"))
            .expect("thiếu dòng về bản đọc / ghi lỗi");
        assert!(failed.contains("2 bản sao lưu"));
        assert!(failed.contains("vault-1700.pwv") && failed.contains("merged-1800-vault (1).pwv"));
        assert!(failed.contains("VẪN có thể mở bằng master password vừa bị thay"));
        assert!(
            failed.contains("xoá các file đó") && failed.contains("nếu mật khẩu cũ có thể đã lộ")
        );
        assert!(failed.contains("d/vault.pwv.backups"));
        // Câu "để nguyên" (không phải của kho này / khoá cũ hơn) vẫn giữ, không tên, và không còn
        // nói "không đọc được" (bản không đọc được giờ nằm trong danh sách có tên ở trên).
        let skipped = lines
            .iter()
            .find(|l| l.contains("1 bản để nguyên"))
            .unwrap();
        assert!(skipped.contains("CŨ HƠN nữa") && !skipped.contains("vault-1700.pwv"));
        assert!(!skipped.contains("không đọc được"));
        let l = passwd_report_lines(
            &PasswordChangeReport::default(),
            false,
            0,
            &[],
            Path::new("x"),
        )
        .join("\n");
        assert!(!l.contains("không ghi lại được"));
        // Trước khi đổi: đồng bộ báo lỗi đĩa ⇒ phải hỏi.
        assert!(!passwd_disk_problem(&SyncReport::default()));
        for r in [
            SyncReport {
                backup_failed: true,
                ..Default::default()
            },
            SyncReport {
                unverified: true,
                ..Default::default()
            },
        ] {
            assert!(passwd_disk_problem(&r));
        }
        let w = passwd_disk_warning(Path::new("d/vault.pwv.backups"));
        assert!(w.contains("d/vault.pwv.backups") && w.contains("VẪN mở được bằng mật khẩu cũ"));
        assert!(!w.contains("     ") && !PASSWD_DISK_QUESTION.is_empty());
    }

    /// fix2-cli-policy#3: nhập lại chính mật khẩu hiện tại ⇒ báo cáo nói thật: mật khẩu giữ nguyên,
    /// chỉ khoá được thay; không nói "mật khẩu cũ không còn đọc được".
    #[test]
    fn passwd_report_for_a_key_renewal_with_the_same_password() {
        let r = PasswordChangeReport {
            backups_reencrypted: 4,
            backups_failed: vec!["vault-1.pwv".into()],
            ..Default::default()
        };
        let l = passwd_report_lines(&r, true, 0, &[], Path::new("b")).join("\n");
        assert!(l.starts_with(
            "Mật khẩu giữ nguyên; khoá mã hoá đã được thay mới — một mật khẩu CŨ KHÁC (đổi bằng bản \
             0.1.x) không còn mở được kho và các bản sao lưu đã mã hoá lại."
        ));
        assert!(!l.contains("Đã đổi master password"));
        assert!(!l.contains("mật khẩu cũ không còn đọc được chúng"));
        assert!(!l.contains("hỏi mật khẩu mới"));
        assert!(
            l.contains("đã mã hoá lại 4 bản bằng khoá mới (vẫn mở bằng master password hiện tại")
        );
        assert!(l.contains("vault-1.pwv") && !l.contains("master password vừa bị thay"));
        assert!(l.contains("vẫn mở khoá bằng chính master password này"));
        let w = same_master_weak_warning("Quá dễ đoán.");
        assert!(w.contains("Quá dễ đoán.") && w.contains("pwv passwd") && w.contains("pwv gen -p"));
        assert!(!w.contains("     ") && !SAME_MASTER_NOTE.contains("     "));
        for l in passwd_report_lines(&r, true, 1, &[PathBuf::from("v (1).pwv")], Path::new("b")) {
            assert!(!l.contains("     "), "{l}");
        }
    }

    /// compat-upgrade#2: lời khuyên đổi mật khẩu một lần cho kho từng đổi mật khẩu ở bản 0.1.x.
    #[test]
    fn other_password_backups_advice_text() {
        let a = other_password_backups_advice(3, Path::new("d/vault.pwv.backups"));
        assert!(a.starts_with("⚠  LỜI KHUYÊN: 3 bản sao lưu"));
        assert!(a.contains("pwv passwd") && a.contains("MỘT lần") && a.contains("MỘT máy"));
        assert!(a.contains("khoá app trên các máy khác"));
        assert!(a.contains("nhập lại chính nó làm mật khẩu mới"));
        assert!(a.contains("giữ nguyên mật khẩu") && a.contains("chưa đạt chính sách mới"));
        assert!(!a.contains("     "));
    }

    /// cli-fix-review#4.
    #[test]
    fn missing_terminal_is_explained() {
        let m = no_terminal_message("Master password: ");
        assert!(m.starts_with("pwv cần một cửa sổ dòng lệnh để hỏi master password"));
        assert!(!m.contains("     "));
        assert!(no_terminal_message("Mật khẩu mới: ").contains("để hỏi mật khẩu (ẩn khi gõ)"));
    }

    #[test]
    fn stale_recovery_warning_shows_both_dates() {
        let w = stale_recovery_warning(&Rollback {
            seen_modified_at: 1_700_000_500_000,
            file_modified_at: 1_700_000_000_123,
            older_password: false,
            unknown_key: false,
        });
        assert!(w.contains("2023-11-14 22:21:40 UTC") && w.contains("2023-11-14 22:13:20 UTC"));
        assert!(w.contains("chưa đồng bộ") && w.contains("lịch sử phiên bản"));
        assert!(!w.contains("     "));
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
        assert!(l.contains("Đã nhập 5 mục, bỏ qua 3 dòng trùng khớp hoàn toàn (với mục đã có"));
        assert!(l.contains(", 1 dòng trống."));
        assert!(l.contains("có vẻ trùng — hãy rà lại") && l.contains("• Gmail (2)"));
        assert!(l.contains("mã 2FA không đọc được, đã chép vào ghi chú") && l.contains("• Bank"));
        assert!(l.contains("không đè lên những gì bạn đã sửa"));
        assert!(!import_summary_lines(&res, 0)
            .join("\n")
            .contains("không đè lên"));
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
        // Không còn hứa "đã hoàn tác" — lần ghi đó (tạo lại file kho) không hoàn tác gì.
        let w = advice(&CoreError::WriteVerifyFailed).unwrap();
        assert!(
            !w.contains("hoàn tác")
                && w.contains("pwv recover")
                && w.contains("Không có gì bị huỷ")
        );
        let n = advice(&CoreError::NoUsableBackup).unwrap();
        assert!(n.contains("Lịch sử phiên bản") && n.contains("máy tính / điện thoại khác"));
        assert!(advice(&CoreError::OlderPasswordBackups)
            .unwrap()
            .contains("HIỆN TẠI"));
        assert!(OLDER_PASSWORD_RECOVERY_WARNING.contains("MỌI thứ đã thêm/sửa sau lần đổi"));
        for t in [
            OLDER_PASSWORD_RECOVERY_WARNING,
            OLDER_THAN_THIS_PC_WARNING,
            ROLLBACK_QUESTION,
            ROLLBACK_REFUSAL,
            OLD_PASSWORD_BACKUP_NOTE,
            OLD_PASSWORD_RESTORE_WARNING,
        ] {
            // Một dòng nối chuỗi viết sai (thiếu `\` cuối dòng) để lại một dãy khoảng trắng giữa câu.
            assert!(!t.contains("     "), "{t}");
        }
        assert!(OLDER_THAN_THIS_PC_WARNING.contains("MỚI HƠN"));
        // cli-fix-review#1: không khẳng định mật khẩu vừa nhập là mật khẩu hiện tại, cũng không khẳng
        // định các bản mới hơn đã mất — chỉ nói điều đã biết.
        assert!(
            !ONLY_PRE_CHANGE_WARNING.contains("ĐÚNG")
                && !ONLY_PRE_CHANGE_WARNING.contains("đã mất —")
                && ONLY_PRE_CHANGE_WARNING.contains("TRƯỚC lần đổi master password")
                && ONLY_PRE_CHANGE_WARNING.contains("không bản sao lưu nào ghi SAU lần đổi đó")
                && ONLY_PRE_CHANGE_WARNING.contains("lịch sử phiên bản")
        );
        let p = advice(&CoreError::OnlyPreChangeBackups).unwrap();
        assert!(!p.contains("là đúng") && p.contains("TRƯỚC") && p.contains("pwv recover"));
        for t in [
            ONLY_PRE_CHANGE_WARNING,
            STALE_RECOVERY_QUESTION,
            STALE_RECOVERY_REFUSAL,
            PASSWD_DISK_REFUSAL,
        ] {
            assert!(!t.contains("     "), "{t}");
        }
        assert!(OLDER_PASSWORD_RECOVERY_WARNING.contains("có vẻ là một master password CŨ"));
        assert!(OLDER_THAN_THIS_PC_WARNING.contains("HIỆN TẠI"));
    }

    #[test]
    fn rollback_warning_text() {
        let w = rollback_warning(&Rollback {
            seen_modified_at: 1_700_000_000_000,
            file_modified_at: 0,
            older_password: true,
            unknown_key: false,
        });
        assert!(w.contains("CŨ HƠN"));
        assert!(w.contains("2023-11-14 22:13:20 UTC"));
        assert!(w.contains("master password CŨ"));
        // Chỉ khoá lạ (mốc thời gian trong file không cũ hơn): không được nói "file CŨ HƠN".
        let w = rollback_warning(&Rollback {
            seen_modified_at: 5,
            file_modified_at: 9,
            older_password: false,
            unknown_key: true,
        });
        assert!(!w.contains("CŨ HƠN") && w.contains("KHÔNG nối tiếp"));
        // Chỉ mật khẩu cũ hơn (nội dung không cũ hơn): không được nói "file CŨ HƠN bản đã thấy" với
        // hai mốc thời gian mâu thuẫn nhau.
        let w = rollback_warning(&Rollback {
            seen_modified_at: 1_700_000_000_000,
            file_modified_at: 1_700_000_500_000,
            older_password: true,
            unknown_key: false,
        });
        assert!(!w.contains("CŨ HƠN bản") && w.contains("master password CŨ hơn lần đổi"));
        assert!(w.contains("pwv backups"));
        // Mốc 0 (chưa biết) không hiện thành năm 1970.
        let w = rollback_warning(&Rollback {
            seen_modified_at: 1_700_000_000_000,
            file_modified_at: 0,
            older_password: false,
            unknown_key: false,
        });
        assert!(w.contains("chỉ tới —") && !w.contains("1970"));
        assert!(
            ROLLBACK_REFUSAL.contains("pwv backups") && ROLLBACK_REFUSAL.contains("pwv restore")
        );
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
        let count = |retired| {
            Ok(BackupCount {
                entries: 4,
                trash: 1,
                retired,
            })
        };
        let line = backup_line(1, &list[1], &count(false));
        assert!(
            line.contains("bản xung đột đã gộp") && line.contains("4 mục (+1 trong thùng rác)")
        );
        assert!(
            line.contains("  —  "),
            "mốc 100 ms không được hiện thành năm 1970: {line}"
        );
        assert!(!line.contains('⚠'));
        assert!(backup_line(2, &list[0], &Err("hỏng".into())).contains("không đọc được: hỏng"));
        // Bản chỉ mở được bằng khoá cũ (bất kể loại), và bản `oldkey-…` của bản pwv trước (đã mã
        // hoá lại nên không còn cờ `retired`, nhưng nội dung từ khoá cũ).
        assert!(backup_line(1, &list[0], &count(true))
            .contains("⚠ từ trước lần đổi mật khẩu / ghi bằng mật khẩu cũ — app không tự dùng"));
        let oldkey = BackupFile {
            path: PathBuf::from("d/oldkey-300-vault.pwv"),
            kind: BackupKind::OldKey,
            timestamp: 1_700_000_000_000,
        };
        let line = backup_line(3, &oldkey, &count(false));
        assert!(line.contains("ghi bằng master password cũ (chưa gộp)") && line.contains('⚠'));
        assert!(line.contains("2023-11-14"));
        assert!(backup_from_old_password(BackupKind::OldKey, false));
        assert!(backup_from_old_password(BackupKind::Auto, true));
        assert!(!backup_from_old_password(BackupKind::Merged, false));
        assert!(OLD_PASSWORD_RESTORE_WARNING.contains("master password CŨ"));
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
