//! Chạy `pwv` thật trong một cửa sổ dòng lệnh giả (pseudo-terminal) — các lời nhắc ẩn của
//! `rpassword` đọc thẳng từ `/dev/tty`, nên không thể cho qua stdin như một đường ống.
//!
//! Chỉ chạy trên Linux (pty qua các hàm POSIX của thư viện C, không thêm crate nào).
//! `PWV_TEST_BIN=<đường-dẫn>` chạy các test này với một bản `pwv` khác (ví dụ bản cũ, để thấy test
//! hỏng trên mã cũ).
#![cfg(target_os = "linux")]

use std::ffi::{c_char, c_int, c_ulong, CStr};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pwv_vault_core::{Config, CreateOptions, Entry, KdfParams, Vault};

extern "C" {
    fn posix_openpt(flags: c_int) -> c_int;
    fn grantpt(fd: c_int) -> c_int;
    fn unlockpt(fd: c_int) -> c_int;
    fn ptsname_r(fd: c_int, buf: *mut c_char, len: usize) -> c_int;
    fn setsid() -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

const O_RDWR: c_int = 2;
const O_NOCTTY: c_int = 0o400;
const O_NONBLOCK: c_int = 0o4000;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const TIOCSCTTY: c_ulong = 0x540E;
const TIMEOUT: Duration = Duration::from_secs(90);

fn pwv_bin() -> PathBuf {
    std::env::var_os("PWV_TEST_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_pwv")))
}

/// Thư mục tạm của một test: kho, cấu hình (`XDG_CONFIG_HOME`) và HOME riêng.
struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Sandbox {
        let s = Sandbox {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir_all(s.config_dir().join("pwv")).unwrap();
        fs::create_dir_all(s.dir.path().join("home")).unwrap();
        s
    }

    fn vault(&self) -> PathBuf {
        self.dir.path().join("vault.pwv")
    }

    fn config_dir(&self) -> PathBuf {
        self.dir.path().join("cfg")
    }

    /// Ghi mốc "máy này đã thấy" của kho `v` vào file cấu hình mà `pwv` sẽ đọc.
    fn remember_seen(&self, v: &Vault) {
        let mut c = Config::default();
        v.note_seen_in(&mut c);
        fs::write(
            self.config_dir().join("pwv").join("config.json"),
            serde_json::to_vec(&c).unwrap(),
        )
        .unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(pwv_bin());
        cmd.arg("--vault")
            .arg(self.vault())
            .args(args)
            .env("XDG_CONFIG_HOME", self.config_dir())
            .env("HOME", self.dir.path().join("home"))
            .env_remove("PWV_VAULT");
        cmd
    }

    /// Chạy `pwv` với một cửa sổ dòng lệnh giả làm terminal điều khiển (stdin/stdout/stderr).
    fn spawn(&self, args: &[&str]) -> Session {
        Session::spawn(self.command(args))
    }
}

struct Session {
    master: File,
    /// Giữ đầu "slave" mở sau khi `pwv` thoát để đọc được những gì còn trong bộ đệm bàn phím.
    slave: File,
    out: Arc<Mutex<Vec<u8>>>,
    cursor: usize,
    child: Child,
}

impl Session {
    fn spawn(mut cmd: Command) -> Session {
        // SAFETY: các lời gọi POSIX với fd vừa mở; buffer đủ dài cho ptsname_r.
        let (master, slave) = unsafe {
            let m = posix_openpt(O_RDWR | O_NOCTTY);
            assert!(m >= 0, "posix_openpt");
            assert_eq!(grantpt(m), 0);
            assert_eq!(unlockpt(m), 0);
            let mut buf = [0 as c_char; 128];
            assert_eq!(ptsname_r(m, buf.as_mut_ptr(), buf.len()), 0);
            let name = CStr::from_ptr(buf.as_ptr()).to_str().unwrap().to_string();
            let slave = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(O_NOCTTY)
                .open(name)
                .unwrap();
            (File::from_raw_fd(m), slave)
        };
        cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        // SAFETY: chỉ gọi các hàm async-signal-safe giữa fork và exec.
        unsafe {
            cmd.pre_exec(|| {
                if setsid() < 0 || ioctl(0, TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let out = Arc::new(Mutex::new(Vec::new()));
        let (sink, mut reader) = (out.clone(), master.try_clone().unwrap());
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Session {
            master,
            slave,
            out,
            cursor: 0,
            child,
        }
    }

    fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned()
    }

    /// Đợi `pat` xuất hiện (sau lần khớp trước). Hỏng test (kèm toàn bộ màn hình) nếu `pwv` thoát
    /// hoặc hết giờ mà chưa thấy.
    fn expect(&mut self, pat: &str) {
        let deadline = Instant::now() + TIMEOUT;
        let mut exited_at = None;
        loop {
            let text = self.out.lock().unwrap().clone();
            if let Some(i) = find(&text[self.cursor..], pat.as_bytes()) {
                self.cursor += i + pat.len();
                return;
            }
            if exited_at.is_none() && self.child.try_wait().unwrap().is_some() {
                exited_at = Some(Instant::now());
            }
            // Cho luồng đọc thêm chút thời gian lấy nốt chữ cuối cùng.
            let gave_up = exited_at.is_some_and(|t| t.elapsed() > Duration::from_millis(500));
            assert!(
                !gave_up && Instant::now() < deadline,
                "không thấy {pat:?}. Màn hình:\n{}",
                String::from_utf8_lossy(&text)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn send(&mut self, s: &str) {
        self.master.write_all(s.as_bytes()).unwrap();
        self.master.flush().unwrap();
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                std::thread::sleep(Duration::from_millis(100));
                return st;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("pwv không thoát. Màn hình:\n{}", self.transcript());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Những gì còn nằm trong bộ đệm bàn phím sau khi `pwv` thoát — shell sẽ đọc và CHẠY chúng.
    fn leftover_input(&mut self) -> String {
        let fd = self.slave.as_raw_fd();
        // SAFETY: fd hợp lệ (`self.slave` còn sống).
        unsafe {
            let fl = fcntl(fd, F_GETFL);
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        }
        let mut buf = [0u8; 4096];
        match self.slave.read(&mut buf) {
            Ok(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => String::new(),
            Err(e) => panic!("{e}"),
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

const KDF: KdfParams = KdfParams::MINIMUM;

fn create(path: &Path, pw: &str) -> Vault {
    Vault::create(
        path,
        pw.as_bytes(),
        CreateOptions {
            kdf: KDF,
            allow_weak_kdf: false,
        },
    )
    .unwrap()
}

fn add(v: &mut Vault, title: &str) {
    // Mốc thời gian theo ms: tách các lần ghi để "cũ hơn / mới hơn" rõ ràng.
    std::thread::sleep(Duration::from_millis(5));
    v.transact(|v| Ok(v.add(Entry::new(title)))).unwrap();
}

fn backup_files(vault: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(pwv_vault_core::fsutil::backup_dir(vault))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    v
}

/// cli-fix-review#2: các dòng sau của một lần dán nhiều dòng vào lời nhắc ẩn không được nằm lại
/// trong bộ đệm bàn phím (shell sẽ chạy chúng như lệnh và lưu vào lịch sử) — khi lệnh thành công
/// cũng như khi lỗi.
#[test]
fn lines_pasted_after_a_hidden_prompt_never_reach_the_shell() {
    let sb = Sandbox::new();
    let pw = "ngua-pin-kep-dung-bien-xanh-42";
    let mut v = create(&sb.vault(), pw);
    add(&mut v, "Ngân hàng A");

    let mut s = sb.spawn(&["list"]);
    s.expect("Master password: ");
    s.send(&format!("{pw}\nPIN-9876-SECRET\n"));
    assert!(s.wait().success(), "{}", s.transcript());
    assert!(s.transcript().contains("Ngân hàng A"));
    assert_eq!(
        s.leftover_input(),
        "",
        "phần thừa của lần dán còn chờ shell đọc"
    );

    // Mật khẩu sai ⇒ lỗi, thoát với mã 1 — phần thừa cũng phải bị xả.
    let mut s = sb.spawn(&["list"]);
    s.expect("Master password: ");
    s.send("sai-mat-khau\nPIN-1234-SECRET\n");
    assert_eq!(s.wait().code(), Some(1));
    assert_eq!(s.leftover_input(), "");
}

/// cli-fix-review#4: không có cửa sổ dòng lệnh ⇒ giải thích bằng tiếng Việt, không in lỗi của hệ
/// điều hành; mã thoát vẫn là 1.
#[test]
fn without_a_terminal_the_error_says_a_terminal_is_needed() {
    let sb = Sandbox::new();
    create(&sb.vault(), "ngua-pin-kep-dung-bien-xanh-42");
    let mut cmd = sb.command(&["list"]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setsid là async-signal-safe. Phiên mới không có terminal điều khiển.
    unsafe {
        cmd.pre_exec(|| {
            if setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains("pwv cần một cửa sổ dòng lệnh để hỏi master password"),
        "{err}"
    );
    assert!(!err.contains("os error"), "{err}");
}

/// cli-fix-review#1: mật khẩu CŨ chỉ mở được các bản `pre_change` (một bản cũ được chép lại vào thư
/// mục sao lưu) — máy này đã dùng một mật khẩu MỚI HƠN ⇒ phải hỏi riêng câu đó (không bỏ qua được
/// bằng -y), trả lời N ⇒ không ghi gì.
#[test]
fn recover_with_an_older_password_than_this_pc_knows_is_stopped_on_the_pre_change_path() {
    let sb = Sandbox::new();
    let (p0, p1, p2) = (
        "ngua-pin-kep-dung-bien-xanh-40",
        "ngua-pin-kep-dung-bien-xanh-41",
        "ngua-pin-kep-dung-bien-xanh-42",
    );
    let mut v = create(&sb.vault(), p0);
    add(&mut v, "A");
    v.change_password(p1.as_bytes(), KDF).unwrap();
    // Các bản có từ trước lần đổi sang p1: mã hoá lại bằng p1, có dấu `pre_change`.
    let replay: Vec<(PathBuf, Vec<u8>)> = backup_files(&sb.vault())
        .into_iter()
        .filter(|p| Vault::peek(p).is_ok_and(|i| i.pre_change))
        .map(|p| {
            let b = fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
    assert!(!replay.is_empty());
    v.change_password(p2.as_bytes(), KDF).unwrap();
    add(&mut v, "B");
    sb.remember_seen(&v);
    // Chỉ còn các bản p1 được chép lại; file kho bị cắt cụt.
    for p in backup_files(&sb.vault()) {
        fs::remove_file(p).unwrap();
    }
    for (p, b) in &replay {
        fs::write(p, b).unwrap();
    }
    fs::write(sb.vault(), b"").unwrap();

    let mut s = sb.spawn(&["recover", "-y"]);
    s.expect("Master password: ");
    s.send(&format!("{p1}\n"));
    s.expect("TRƯỚC lần đổi");
    s.expect("[y/N] ");
    s.send("y\n");
    s.expect("MỚI HƠN mật khẩu bạn vừa nhập");
    s.expect("[y/N] ");
    s.send("n\n");
    assert!(s.wait().success(), "{}", s.transcript());
    assert!(s.transcript().contains("Chưa thay đổi gì"));
    assert_eq!(fs::read(sb.vault()).unwrap(), b"", "không được ghi gì");
    let t = s.transcript();
    assert!(!t.contains("là ĐÚNG") && t.contains("chỉ mở được các bản sao lưu có từ TRƯỚC"));
}

/// Kho dựng lại dùng đúng khoá nhưng CŨ HƠN nội dung máy này đã thấy (bản sao lưu mới nhất chưa
/// đồng bộ về): in hai mốc, hỏi trước khi ghi (không bỏ qua được bằng -y); N ⇒ không ghi gì.
#[test]
fn recover_from_stale_backups_asks_first_and_writes_nothing_on_no() {
    let sb = Sandbox::new();
    let pw = "ngua-pin-kep-dung-bien-xanh-42";
    let mut v = create(&sb.vault(), pw);
    add(&mut v, "A");
    add(&mut v, "B");
    sb.remember_seen(&v);
    drop(v);
    // Bản sao lưu mới nhất (có B) chưa về máy này, file kho bị xoá.
    let newest = pwv_vault_core::fsutil::list_backups(&sb.vault())
        .into_iter()
        .max_by_key(|b| b.timestamp)
        .unwrap();
    fs::remove_file(&newest.path).unwrap();
    fs::remove_file(sb.vault()).unwrap();

    let mut s = sb.spawn(&["recover", "-y"]);
    s.expect("Master password: ");
    s.send(&format!("{pw}\n"));
    s.expect("CŨ HƠN nội dung mà máy này đã từng thấy: máy này đã thấy nội dung sửa lúc 20");
    s.expect("còn kho dựng lại chỉ tới 20");
    s.expect("chưa đồng bộ về máy này");
    s.expect("[y/N] ");
    s.send("n\n");
    assert!(s.wait().success(), "{}", s.transcript());
    assert!(!sb.vault().exists(), "không được ghi gì");
    assert!(!s.transcript().contains("Đã ghi kho"));

    // Trả lời y ⇒ ghi, rồi mới lấy trạng thái này làm mốc mới: lần mở sau không cảnh báo nữa.
    let mut s = sb.spawn(&["recover", "-y"]);
    s.expect("Master password: ");
    s.send(&format!("{pw}\n"));
    s.expect("CŨ HƠN nội dung");
    s.expect("[y/N] ");
    s.send("y\n");
    s.expect("Đã ghi kho");
    assert!(s.wait().success(), "{}", s.transcript());
    let v = Vault::open(sb.vault(), pw.as_bytes()).unwrap();
    let cfg: Config =
        serde_json::from_slice(&fs::read(sb.config_dir().join("pwv").join("config.json")).unwrap())
            .unwrap();
    assert!(v.rollback_against(&cfg).is_none());
    assert_eq!(v.entries().len(), 1);
}

/// fix2-cli-policy#5: phần thừa của một lần dán vào lời nhắc ẩn CUỐI CÙNG của một lệnh ghi
/// ("Nhập lại:" của `add`) và vào một câu hỏi [y/N] cũng không được rơi vào shell.
#[test]
fn lines_pasted_at_the_last_prompt_of_add_or_at_a_yes_no_question_never_reach_the_shell() {
    let sb = Sandbox::new();
    let pw = "ngua-pin-kep-dung-bien-xanh-42";
    let mut v = create(&sb.vault(), pw);
    add(&mut v, "Cũ");
    drop(v);

    let mut s = sb.spawn(&["add", "Ngân hàng B"]);
    s.expect("Master password: ");
    s.send(&format!("{pw}\n"));
    s.expect("Mật khẩu của tài khoản (ẩn khi gõ): ");
    s.send("Real-Bank-Pw-1!\n");
    s.expect("Nhập lại: ");
    s.send("Real-Bank-Pw-1!\nPIN-9876-SECRET\n");
    assert!(s.wait().success(), "{}", s.transcript());
    assert!(s.transcript().contains("Đã thêm \"Ngân hàng B\""));
    assert_eq!(s.leftover_input(), "");
    let v = Vault::open(sb.vault(), pw.as_bytes()).unwrap();
    let e = v
        .entries()
        .iter()
        .find(|e| e.title == "Ngân hàng B")
        .unwrap();
    assert_eq!(e.password, "Real-Bank-Pw-1!");
    drop(v);

    let mut s = sb.spawn(&["delete", "Cũ"]);
    s.expect("Master password: ");
    s.send(&format!("{pw}\n"));
    s.expect("[y/N] ");
    s.send("y\nrm -rf ~/PIN-1234\n");
    assert!(s.wait().success(), "{}", s.transcript());
    assert!(s.transcript().contains("vào thùng rác"));
    assert_eq!(s.leftover_input(), "");
}

/// fix2-cli-policy#3: `pwv passwd` nhập lại đúng mật khẩu hiện tại (lời khuyên của `pwv backups`
/// cho kho từng đổi mật khẩu ở bản 0.1.x) được chấp nhận kể cả khi mật khẩu đó chưa đạt chính sách
/// mới, có cảnh báo, và báo cáo nói thật rằng mật khẩu giữ nguyên.
#[test]
fn passwd_with_the_current_password_renews_the_key_even_if_it_fails_todays_policy() {
    let sb = Sandbox::new();
    // Một mật khẩu bản 0.1.x từng nhận, nay bị chính sách từ chối.
    let pw = "nguyenvanan1990";
    let mut v = create(&sb.vault(), pw);
    add(&mut v, "A");
    let old_tag = v.key_tag();
    drop(v);

    let mut s = sb.spawn(&["passwd"]);
    s.expect("Master password: ");
    s.send(&format!("{pw}\n"));
    s.expect("Master password MỚI: ");
    s.send(&format!("{pw}\n"));
    s.expect("Đây là master password hiện tại");
    s.expect("chưa đạt chính sách");
    s.expect("Nhập lại: ");
    s.send(&format!("{pw}\n"));
    s.expect("Mật khẩu giữ nguyên; khoá mã hoá đã được thay mới");
    assert!(s.wait().success(), "{}", s.transcript());
    let t = s.transcript();
    assert!(!t.contains("Chưa dùng được") && !t.contains("mật khẩu cũ không còn đọc được"));
    let v = Vault::open(sb.vault(), pw.as_bytes()).unwrap();
    assert_ne!(v.key_tag(), old_tag, "khoá mã hoá phải được thay");
    assert_eq!(v.entries().len(), 1);

    // Một mật khẩu MỚI khác mà yếu thì vẫn bị từ chối như trước.
    let mut s = sb.spawn(&["passwd"]);
    s.expect("Master password: ");
    s.send(&format!("{pw}\n"));
    s.expect("Master password MỚI: ");
    s.send("tranvanbinh12031985\n");
    s.expect("Chưa dùng được");
    s.expect("Master password MỚI: ");
    s.send("\n");
    assert_eq!(s.wait().code(), Some(1));
}
