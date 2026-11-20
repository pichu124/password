//! Test tích hợp cho kho: tạo/mở/lưu, sai mật khẩu, sửa file, đồng bộ nhiều máy qua thư mục
//! Google Drive / Dropbox / OneDrive, hỏng file, đổi master password, sao lưu, chuyển kho.
//!
//! Nhiều test ở đây tái hiện đúng các lỗi mà đợt rà soát bảo mật tìm thấy ở bản 0.1.2.

use std::fs;
use std::path::{Path, PathBuf};

use pwv_vault_core::fsutil::{backup_dir, list_backups};
use pwv_vault_core::{
    format, BackupKind, CreateOptions, Entry, Error, KdfParams, OpenOptions, Vault,
};

const PW: &[u8] = b"master password dai va kho doan 123!";

fn opts() -> CreateOptions {
    CreateOptions {
        kdf: KdfParams::INSECURE_TEST,
        allow_weak_kdf: true,
    }
}

/// Mở kho test (tham số Argon2 rất thấp ⇒ phải cho phép rõ ràng).
fn open(p: &Path, pw: &[u8]) -> Result<Vault, Error> {
    Vault::open_with(
        p,
        pw,
        OpenOptions {
            allow_weak_kdf: true,
        },
    )
}

fn open_bytes(bytes: &[u8], pw: &[u8]) -> Result<Vault, Error> {
    Vault::open_bytes_with(
        "content://x/vault.pwv",
        bytes,
        pw,
        OpenOptions {
            allow_weak_kdf: true,
        },
    )
}

fn login(title: &str, user: &str, pw: &str) -> Entry {
    let mut e = Entry::new(title);
    e.username = user.into();
    e.password = pw.into();
    e
}

fn new_vault(d: &tempfile::TempDir) -> (PathBuf, Vault) {
    let p = d.path().join("vault.pwv");
    let v = Vault::create(&p, PW, opts()).unwrap();
    (p, v)
}

fn titles(v: &Vault) -> Vec<String> {
    let mut t: Vec<String> = v.entries().iter().map(|e| e.title.clone()).collect();
    t.sort();
    t
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Chép một file mẫu vào thư mục tạm để test được phép ghi đè.
fn fixture_copy(d: &tempfile::TempDir, name: &str, as_name: &str) -> PathBuf {
    let p = d.path().join(as_name);
    fs::copy(fixture(name), &p).unwrap();
    p
}

// ----------------------------------------------------------------------------- cơ bản

#[test]
fn create_add_save_reopen() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    let id = v.add(login("Gmail", "toi@gmail.com", "S3cret!"));
    assert!(v.has_unsaved_changes());
    v.save().unwrap();
    assert!(!v.has_unsaved_changes());
    drop(v);

    let v = open(&p, PW).unwrap();
    assert_eq!(v.entries().len(), 1);
    let e = v.get(&id).unwrap();
    assert_eq!(e.username, "toi@gmail.com");
    assert_eq!(e.password, "S3cret!");
    assert!(v.verify_password(PW));
    assert!(!v.verify_password(b"sai"));
    assert_eq!(fs::read(&p).unwrap()[4..6], [2, 0], "ghi ra định dạng v2");
}

#[test]
fn create_refuses_to_overwrite_and_weak_kdf() {
    let d = tempfile::tempdir().unwrap();
    let (p, _v) = new_vault(&d);
    assert!(matches!(
        Vault::create(&p, PW, opts()),
        Err(Error::AlreadyExists(_))
    ));
    let weak = CreateOptions {
        kdf: KdfParams::INSECURE_TEST,
        allow_weak_kdf: false,
    };
    assert!(matches!(
        Vault::create(d.path().join("b.pwv"), PW, weak),
        Err(Error::InvalidKdfParams)
    ));
    assert!(!d.path().join("b.pwv").exists());
}

/// Lỗi 0.1.2: mức sàn Argon2 chỉ được kiểm tra khi tạo, không kiểm tra khi mở.
#[test]
fn opening_refuses_weak_or_absurd_kdf_parameters() {
    let d = tempfile::tempdir().unwrap();
    let (p, _v) = new_vault(&d);
    // Bản phát hành (không bật allow_weak_kdf) từ chối kho có tham số dưới mức sàn.
    assert!(matches!(Vault::open(&p, PW), Err(Error::InvalidKdfParams)));
    assert!(open(&p, PW).is_ok());

    // File bị sửa header để bắt máy chạy Argon2 4 GiB × 100 vòng: bị từ chối ngay, không treo máy.
    let bytes = fs::read(&p).unwrap();
    let header_len = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
    let header = std::str::from_utf8(&bytes[10..10 + header_len]).unwrap();
    assert!(header.contains("\"m_kib\":8,\"t\":1"), "{header}");
    let evil = header.replace("\"m_kib\":8,\"t\":1", "\"m_kib\":4194304,\"t\":100");
    let mut out = bytes[..6].to_vec();
    out.extend_from_slice(&(evil.len() as u32).to_le_bytes());
    out.extend_from_slice(evil.as_bytes());
    out.extend_from_slice(&bytes[10 + header_len..]);
    fs::write(&p, &out).unwrap();
    let t = std::time::Instant::now();
    assert!(matches!(open(&p, PW), Err(Error::InvalidKdfParams)));
    assert!(t.elapsed().as_secs() < 2);
}

#[test]
fn wrong_password_fails() {
    let d = tempfile::tempdir().unwrap();
    let (p, _v) = new_vault(&d);
    assert!(matches!(open(&p, b"wrong"), Err(Error::Decrypt)));
}

/// Lỗi 0.1.2: mật khẩu có dấu gõ bằng bàn phím khác (dựng sẵn / tổ hợp) bị báo sai.
#[test]
fn vietnamese_master_password_works_in_both_unicode_forms() {
    let nfc = "m\u{1ead}t kh\u{1ea9}u k\u{1ebf}t h\u{1ee3}p 42";
    let nfd = "ma\u{323}\u{302}t kha\u{302}\u{309}u ke\u{302}\u{301}t ho\u{31b}\u{323}p 42";
    assert_ne!(nfc.as_bytes(), nfd.as_bytes());
    let d = tempfile::tempdir().unwrap();
    // Tạo bằng kiểu gõ này, mở bằng kiểu gõ kia — cả hai chiều.
    for (create_with, open_with) in [(nfc, nfd), (nfd, nfc)] {
        let p = d.path().join(format!("{}.pwv", create_with.len()));
        Vault::create(&p, create_with.as_bytes(), opts()).unwrap();
        assert!(open(&p, open_with.as_bytes()).is_ok());
        assert!(open(&p, create_with.as_bytes()).is_ok());
        assert!(open(&p, "mat khau ket hop 42".as_bytes()).is_err());
    }
    // Kho do bản 0.1.2 tạo (không chuẩn hoá) bằng kiểu gõ tổ hợp vẫn mở được bằng cả hai kiểu.
    let old = fixture("v1-mixed.pwv");
    assert!(Vault::open(&old, nfc.as_bytes()).is_ok());
    assert!(Vault::open(&old, nfd.as_bytes()).is_ok());
}

#[test]
fn no_plaintext_on_disk() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    v.add(login("Vietcombank", "nguyenvana", "MatKhauNganHang"));
    v.save().unwrap();
    let bytes = fs::read(&p).unwrap();
    for needle in ["Vietcombank", "nguyenvana", "MatKhauNganHang"] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "lộ '{needle}' trong file"
        );
    }
    // Kích thước được đệm lên bội số 4 KiB (che số lượng mục một cách tương đối).
    let small = bytes.len();
    for i in 0..3 {
        v.add(login(&format!("site{i}"), "u", "p"));
    }
    v.save().unwrap();
    assert_eq!(fs::read(&p).unwrap().len(), small);
}

#[test]
fn every_single_byte_flip_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    v.add(login("A", "a", "a"));
    v.save().unwrap();
    let orig = fs::read(&p).unwrap();
    // Thử lật 1 bit ở nhiều vị trí khác nhau (header, nonce, ciphertext, tag).
    let step = (orig.len() / 200).max(1);
    for i in (0..orig.len()).step_by(step).chain([orig.len() - 1]) {
        let mut bad = orig.clone();
        bad[i] ^= 0x01;
        fs::write(&p, &bad).unwrap();
        assert!(open(&p, PW).is_err(), "không phát hiện sửa đổi ở byte {i}");
    }
    // Cắt cụt file.
    fs::write(&p, &orig[..orig.len() / 2]).unwrap();
    assert!(open(&p, PW).is_err());
}

#[test]
fn rejects_garbage_files() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("x.pwv");
    for junk in [
        &b""[..],
        b"PWV1",
        b"hello world, not a vault",
        &[0xFFu8; 100][..],
    ] {
        fs::write(&p, junk).unwrap();
        assert!(open(&p, PW).is_err());
    }
    // header_len khổng lồ
    let mut b = b"PWV1\x02\x00".to_vec();
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&p, &b).unwrap();
    assert!(matches!(open(&p, PW), Err(Error::BadFormat)));
    // Phiên bản định dạng của tương lai: báo rõ để người dùng cập nhật app.
    fs::write(&p, b"PWV1\x03\x00\x00\x00\x00\x00").unwrap();
    assert!(matches!(open(&p, PW), Err(Error::UnsupportedVersion(3))));
}

// ----------------------------------------------------------------------------- sửa / xoá

#[test]
fn update_keeps_password_history_and_delete_goes_to_trash() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    let id = v.add(login("Bank", "u", "old-pass"));
    v.update(&id, |e| e.password = "new-pass".into()).unwrap();
    let e = v.get(&id).unwrap();
    assert_eq!(e.password, "new-pass");
    assert_eq!(e.password_history[0].password, "old-pass");

    v.delete(&id).unwrap();
    assert!(v.get(&id).is_none());
    assert_eq!(v.trash().len(), 1);
    assert!(matches!(v.delete(&id), Err(Error::EntryNotFound(_))));
    v.save().unwrap();
    // Thùng rác được lưu lại và khôi phục được sau khi mở lại.
    let mut v = open(&p, PW).unwrap();
    assert!(v.entries().is_empty());
    assert_eq!(v.get_trashed(&id).unwrap().password, "new-pass");
    v.restore(&id).unwrap();
    assert_eq!(v.get(&id).unwrap().password_history[0].password, "old-pass");
    // Xoá vĩnh viễn.
    v.delete(&id).unwrap();
    assert_eq!(v.empty_trash(), 1);
    v.save().unwrap();
    let v = open(&p, PW).unwrap();
    assert!(v.entries().is_empty() && v.trash().is_empty());
}

#[test]
fn transaction_rolls_back_when_the_edit_fails() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    let (id, _) = v.transact(|v| Ok(v.add(login("A", "a", "a")))).unwrap();
    let r: Result<((), _), _> = v.transact(|v| {
        v.add(login("B", "b", "b"));
        v.update(&id, |e| e.password = "changed".into())?;
        Err(Error::EntryNotFound("giả lập lỗi giữa chừng".into()))
    });
    assert!(r.is_err());
    assert_eq!(titles(&v), ["A"], "mọi thay đổi trong giao dịch lỗi bị huỷ");
    assert_eq!(v.get(&id).unwrap().password, "a");
    assert!(!v.has_unsaved_changes());
    assert_eq!(titles(&open(&p, PW).unwrap()), ["A"]);
}

// ----------------------------------------------------------------------------- master password

/// Lỗi 0.1.2: đổi master password chỉ gói lại cùng một khoá kho ⇒ ai biết mật khẩu CŨ và giữ một
/// bản sao cũ (thư mục sao lưu, lịch sử phiên bản của Drive) vẫn đọc được dữ liệu MỚI.
#[test]
fn changing_master_password_rotates_the_vault_key() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    v.add(login("Trước khi đổi", "x", "old-secret"));
    v.save().unwrap();
    v.add(login("Trước khi đổi 2", "x", "old-secret-2"));
    v.save().unwrap();
    // Kẻ tấn công đã chép sẵn một bản của file kho (từ cloud) trước khi chủ kho đổi mật khẩu.
    let stolen = d.path().join("stolen-copy.bin");
    fs::copy(&p, &stolen).unwrap();
    assert!(!list_backups(&p).is_empty());

    let report = v
        .change_password(b"mat khau moi", KdfParams::INSECURE_TEST)
        .unwrap();
    assert!(report.backups_reencrypted >= 2, "{report:?}");
    assert_eq!(report.backups_skipped, 0);
    v.transact(|v| Ok(v.add(login("Sau khi đổi", "bank", "POST-CHANGE-SECRET"))))
        .unwrap();

    // Mật khẩu cũ không còn mở được file kho lẫn bất kỳ bản sao lưu nào.
    assert!(matches!(open(&p, PW), Err(Error::Decrypt)));
    for b in list_backups(&p) {
        assert!(
            open(&b.path, PW).is_err(),
            "{:?} còn mở được bằng mật khẩu cũ",
            b.path
        );
        assert!(open(&b.path, b"mat khau moi").is_ok());
    }
    // Bản đã bị chép trộm vẫn mở được bằng mật khẩu cũ (không thể thu hồi), nhưng khoá lấy từ nó
    // KHÔNG giải mã được file kho hiện tại: máy "kẻ tấn công" thấy file mới là thứ không đọc nổi.
    let mut attacker = open(&stolen, PW).unwrap();
    assert_eq!(attacker.entries().len(), 2);
    assert!(attacker.merge_file(&p).is_err());
    assert!(!attacker
        .entries()
        .iter()
        .any(|e| e.password == "POST-CHANGE-SECRET"));

    // Mật khẩu mới mở được, dữ liệu đủ.
    let v2 = open(&p, b"mat khau moi").unwrap();
    assert_eq!(v2.entries().len(), 3);
    assert!(v2.verify_password(b"mat khau moi") && !v2.verify_password(PW));
}

#[test]
fn other_device_is_told_to_re_enter_the_password_after_a_change() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut a) = new_vault(&d);
    a.add(login("Chung", "c", "c"));
    a.save().unwrap();
    let mut b = open(&p, PW).unwrap();
    let phone_bytes = fs::read(&p).unwrap();
    let mut phone = open_bytes(&phone_bytes, PW).unwrap();

    a.change_password(b"new", KdfParams::INSECURE_TEST).unwrap();

    // Máy B còn giữ khoá cũ: mọi thao tác đọc/ghi đều báo đúng nguyên nhân, không ghi đè gì cả.
    let before = fs::read(&p).unwrap();
    assert!(matches!(b.sync(), Err(Error::PasswordChangedElsewhere)));
    assert!(matches!(
        b.transact(|v| Ok(v.add(login("B", "b", "b")))),
        Err(Error::PasswordChangedElsewhere)
    ));
    assert_eq!(
        titles(&b),
        ["Chung"],
        "thay đổi chưa ghi được thì không hiện trong danh sách"
    );
    assert!(matches!(
        b.move_to(d.path().join("elsewhere.pwv")),
        Err(Error::PasswordChangedElsewhere)
    ));
    assert_eq!(fs::read(&p).unwrap(), before);
    // Điện thoại (chỉ đọc) cũng vậy.
    assert!(matches!(
        phone.replace_from_bytes(&before),
        Err(Error::PasswordChangedElsewhere)
    ));
    // Nhập mật khẩu mới là dùng tiếp được.
    let mut b = open(&p, b"new").unwrap();
    b.transact(|v| Ok(v.add(login("B", "b", "b")))).unwrap();
    assert_eq!(titles(&open(&p, b"new").unwrap()), ["B", "Chung"]);
}

/// Máy A đổi mật khẩu đúng lúc máy B (chưa biết) vừa ghi file ⇒ dịch vụ đồng bộ giữ cả hai file.
/// Máy nào cũng phải gộp được, không mất gì, và kết thúc với mật khẩu mới.
#[test]
fn password_change_racing_with_an_edit_on_another_device() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut a) = new_vault(&d);
    a.add(login("Chung", "c", "c"));
    a.save().unwrap();
    let base = fs::read(&p).unwrap();

    // Máy B sửa trên bản cũ (ở thư mục riêng của nó)…
    let b_file = d.path().join("may-b").join("vault.pwv");
    fs::create_dir_all(b_file.parent().unwrap()).unwrap();
    fs::write(&b_file, &base).unwrap();
    let mut b = open(&b_file, PW).unwrap();
    b.transact(|v| Ok(v.add(login("Từ B", "b", "b")))).unwrap();
    // …trong khi máy A đổi mật khẩu và thêm mục.
    a.change_password(b"new", KdfParams::INSECURE_TEST).unwrap();
    a.transact(|v| Ok(v.add(login("Từ A", "a", "a")))).unwrap();
    let a_version = fs::read(&p).unwrap();
    let b_version = fs::read(&b_file).unwrap();

    // Tình huống 1: file chính là bản của A, bản của B thành bản xung đột (dùng khoá cũ).
    let conflict = d.path().join("vault (1).pwv");
    fs::write(&conflict, &b_version).unwrap();
    let r = a.sync().unwrap();
    assert_eq!(r.conflicts.len(), 1);
    assert!(r.conflicts[0].result.is_ok() && r.conflicts[0].archived && r.wrote);
    assert_eq!(titles(&a), ["Chung", "Từ A", "Từ B"]);
    assert!(!conflict.exists());

    // Tình huống 2 (trên máy B): file chính là bản của B (mật khẩu cũ), bản của A là bản xung đột.
    let d2 = tempfile::tempdir().unwrap();
    let main = d2.path().join("vault.pwv");
    fs::write(&main, &b_version).unwrap();
    fs::write(d2.path().join("vault-DESKTOP-A.pwv"), &a_version).unwrap();
    let mut b = open(&main, PW).unwrap();
    assert!(matches!(b.sync(), Err(Error::PasswordChangedElsewhere)));
    drop(b);
    // Người dùng nhập mật khẩu MỚI: không mở được file chính, nhưng mở được qua bản xung đột.
    let mut b = open(&main, b"new").unwrap();
    assert_eq!(titles(&b), ["Chung", "Từ A", "Từ B"]);
    assert!(b.has_unsaved_changes());
    let r = b.sync().unwrap();
    assert!(r.wrote && r.conflicts.iter().all(|c| c.archived));
    assert!(open(&main, PW).is_err());
    assert_eq!(open(&main, b"new").unwrap().entries().len(), 3);
    assert!(b.conflict_copies().is_empty());
}

/// Tương thích với bản 0.1.2 đang chạy ở máy khác: nó "đổi mật khẩu" bằng cách gói lại cùng một
/// khoá kho. Máy mới phải nhận header đó (để hai máy dùng chung một mật khẩu), không báo lỗi.
#[test]
fn legacy_password_change_by_an_old_app_version_is_adopted() {
    let d = tempfile::tempdir().unwrap();
    let p = fixture_copy(&d, "v1-rewrap-before.pwv", "vault.pwv");
    let mut v = Vault::open(&p, b"mat khau cu 0.1.2").unwrap();
    assert_eq!(titles(&v), ["Có từ đầu"]);
    // Dịch vụ đồng bộ mang về bản mà máy kia (0.1.2) đã đổi mật khẩu và thêm mục.
    fs::copy(fixture("v1-rewrap-after.pwv"), &p).unwrap();
    let (_, report) = v
        .transact(|v| Ok(v.add(login("Thêm ở máy mới", "x", "x"))))
        .unwrap();
    assert!(report.adopted_remote_password);
    assert!(Vault::open(&p, b"mat khau cu 0.1.2").is_err());
    let v = Vault::open(&p, b"mat khau moi 0.1.2").unwrap();
    assert_eq!(v.entries().len(), 3);
}

// ----------------------------------------------------------------------------- đồng bộ

/// Mô phỏng hai máy Windows cùng mở một file trong thư mục đồng bộ.
#[test]
fn two_devices_sync_without_losing_data() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut setup) = new_vault(&d);
    let shared = setup.add(login("Shared", "s", "v1"));
    let to_delete = setup.add(login("Old", "o", "o"));
    setup.save().unwrap();
    drop(setup);

    let mut pc = open(&p, PW).unwrap();
    let mut laptop = open(&p, PW).unwrap();

    // PC: thêm mục, đổi mật khẩu mục chung, rồi lưu.
    let pc_only = pc.add(login("PC only", "a", "a"));
    pc.update(&shared, |e| e.password = "from-pc".into())
        .unwrap();
    assert!(pc.save().unwrap().merged_remote.is_none());

    // Laptop (chưa thấy thay đổi của PC): thêm mục, xoá mục, sửa GHI CHÚ của mục chung.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let laptop_only = laptop.add(login("Laptop only", "b", "b"));
    laptop.delete(&to_delete).unwrap();
    laptop
        .update(&shared, |e| e.notes = "ghi chú từ laptop".into())
        .unwrap();
    assert!(laptop.changed_on_disk().unwrap());
    let report = laptop.save().unwrap();
    assert!(
        report.merged_remote.is_some(),
        "phải phát hiện thay đổi từ PC"
    );

    let v = open(&p, PW).unwrap();
    assert!(v.get(&pc_only).is_some());
    assert!(v.get(&laptop_only).is_some());
    assert!(v.get(&to_delete).is_none());
    assert!(v.get_trashed(&to_delete).is_some(), "xoá = vào thùng rác");
    let s = v.get(&shared).unwrap();
    // Lỗi 0.1.2: bản sửa ghi chú (muộn hơn) của laptop đè mất mật khẩu mới của PC.
    assert_eq!(s.password, "from-pc");
    assert_eq!(s.notes, "ghi chú từ laptop");
    assert!(s.password_history.iter().any(|h| h.password == "v1"));

    // PC nạp lại và thấy đủ, không cần ghi gì thêm.
    let r = pc.sync().unwrap();
    assert!(r.merged_remote.is_some() && !r.wrote);
    assert!(pc.get(&laptop_only).is_some());
    assert!(pc.get(&to_delete).is_none());
    assert_eq!(pc.get(&shared).unwrap().notes, "ghi chú từ laptop");
}

/// Lỗi 0.1.2: dịch vụ đồng bộ thay file bằng bản của máy kia (thiếu mục máy này vừa lưu); app gộp
/// vào RAM nhưng không bao giờ ghi lại ⇒ mục đó biến mất khi khoá app.
#[test]
fn sync_writes_back_what_the_file_on_disk_is_missing() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut pc1) = new_vault(&d);
    pc1.add(login("base", "x", "x"));
    pc1.save().unwrap();
    let old_file = fs::read(&p).unwrap();

    pc1.transact(|v| Ok(v.add(login("X-from-pc1", "x", "x"))))
        .unwrap();
    // "Máy 2" sửa trên bản cũ, rồi dịch vụ đồng bộ lấy bản của máy 2 đè lên (ghi-sau-thắng).
    let other = d.path().join("pc2").join("vault.pwv");
    fs::create_dir_all(other.parent().unwrap()).unwrap();
    fs::write(&other, &old_file).unwrap();
    let mut pc2 = open(&other, PW).unwrap();
    pc2.transact(|v| Ok(v.add(login("Y-from-pc2", "y", "y"))))
        .unwrap();
    fs::copy(&other, &p).unwrap();

    let r = pc1.sync().unwrap();
    assert!(r.merged_remote.unwrap().added == 1 && r.wrote);
    drop(pc1); // khoá app
    assert_eq!(
        titles(&open(&p, PW).unwrap()),
        ["X-from-pc1", "Y-from-pc2", "base"]
    );

    // Không có chuyện hai máy ghi đè qua lại mãi: máy 2 đọc file đã gộp và không còn gì để ghi.
    fs::copy(&p, &other).unwrap();
    let r = pc2.sync().unwrap();
    assert!(r.merged_remote.is_some() && !r.wrote);
    let mut pc1 = open(&p, PW).unwrap();
    fs::copy(&other, &p).unwrap();
    let r = pc1.sync().unwrap();
    assert!(r.merged_remote.is_none() && !r.wrote);
}

#[test]
fn merge_conflict_copies_of_drive_dropbox_onedrive() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    v.add(login("Base", "b", "b"));
    v.save().unwrap();
    // Mỗi dịch vụ đặt tên bản xung đột một kiểu; OneDrive thêm tên máy (0.1.2 chỉ nhận tên máy
    // viết HOA không dấu). Bản mới nhận diện theo nội dung header, không theo tên.
    for (name, title) in [
        ("vault (1).pwv", "Từ Drive"),
        (
            "vault (Binh's conflicted copy 2026-11-20).pwv",
            "Từ Dropbox",
        ),
        ("vault-Binh-Laptop.pwv", "Từ OneDrive"),
        ("vault-MÁY-BÌNH.PWV", "Từ OneDrive 2"),
    ] {
        let c = d.path().join(name);
        fs::copy(&p, &c).unwrap();
        let mut other = open(&c, PW).unwrap();
        other.add(login(title, "x", "x"));
        other.save().unwrap();
        // Lưu bản xung đột tạo ra thư mục sao lưu riêng của nó — dọn đi cho giống thực tế.
        let _ = fs::remove_dir_all(backup_dir(&c));
    }
    // Kho KHÁC nằm cùng thư mục, và file rác trùng kiểu tên: không bị đụng tới.
    let foreign = d.path().join("kho-khac.pwv");
    Vault::create(&foreign, PW, opts()).unwrap();
    fs::write(d.path().join("vault (2).pwv"), b"rac").unwrap();

    let mut v = open(&p, PW).unwrap();
    assert_eq!(v.conflict_copies().len(), 4);
    let r = v.sync().unwrap();
    assert_eq!(r.conflicts.len(), 4);
    assert!(r.conflicts.iter().all(|c| c.result.is_ok() && c.archived));
    assert!(r.wrote);
    assert_eq!(
        titles(&v),
        [
            "Base",
            "Từ Drive",
            "Từ Dropbox",
            "Từ OneDrive",
            "Từ OneDrive 2"
        ]
    );
    assert!(
        v.conflict_copies().is_empty(),
        "đã chuyển vào thư mục sao lưu"
    );
    assert_eq!(
        list_backups(&p)
            .iter()
            .filter(|b| b.kind == BackupKind::Merged)
            .count(),
        4
    );
    assert!(foreign.exists() && d.path().join("vault (2).pwv").exists());
    assert_eq!(open(&p, PW).unwrap().entries().len(), 5);
    // Không gộp được file của kho khác.
    assert!(matches!(v.merge_file(&foreign), Err(Error::DifferentVault)));
}

/// Lỗi 0.1.2: bản xung đột bị chuyển khỏi thư mục TRƯỚC khi kho được ghi; ghi lỗi là mất dấu.
#[test]
fn conflict_copy_stays_in_place_until_the_vault_is_saved() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    v.add(login("Base", "b", "b"));
    v.save().unwrap();
    let conflict = d.path().join("vault (1).pwv");
    fs::copy(&p, &conflict).unwrap();
    {
        let mut other = open(&conflict, PW).unwrap();
        other.add(login("NewBankPw", "c", "c"));
        other.save().unwrap();
    }
    // File chính hỏng (đồng bộ dở) ⇒ không ghi được ⇒ bản xung đột phải còn nguyên tại chỗ.
    let good = fs::read(&p).unwrap();
    fs::write(&p, &good[..good.len() / 2]).unwrap();
    assert!(matches!(v.sync(), Err(Error::VaultFileDamaged)));
    assert!(conflict.exists());
    // Đồng bộ xong (file chính lành lại): lần sau gộp bình thường.
    fs::write(&p, &good).unwrap();
    let r = v.sync().unwrap();
    assert!(r.wrote && r.conflicts[0].archived);
    assert!(!conflict.exists());
    assert_eq!(titles(&open(&p, PW).unwrap()), ["Base", "NewBankPw"]);
}

/// Lỗi 0.1.2: nhập cùng một file CSV trên hai máy trước khi chúng kịp đồng bộ ⇒ mọi mục bị nhân đôi.
#[test]
fn importing_the_same_csv_on_two_devices_does_not_duplicate_entries() {
    use pwv_vault_core::import::import_csv;
    let csv = "name,url,username,password,note\n\
               VCB,https://vcb.com.vn,nguyenvana,pw-vcb,\n\
               Gmail,https://mail.google.com,toi@gmail.com,pw-gmail,ghi chú\n\
               ,,,,mã khôi phục 1111\n";
    let d = tempfile::tempdir().unwrap();
    let (p, mut pc) = new_vault(&d);
    pc.save().unwrap();
    let laptop_file = d.path().join("laptop").join("vault.pwv");
    fs::create_dir_all(laptop_file.parent().unwrap()).unwrap();
    fs::copy(&p, &laptop_file).unwrap();
    let mut laptop = open(&laptop_file, PW).unwrap();

    for v in [&mut pc, &mut laptop] {
        v.transact(|v| {
            let res = import_csv(csv.as_bytes(), v.entries()).unwrap();
            assert_eq!(res.entries.len(), 3);
            for e in res.entries {
                v.add(e);
            }
            Ok(())
        })
        .unwrap();
    }
    // Dịch vụ đồng bộ mang file của laptop về làm bản xung đột trên PC.
    fs::copy(&laptop_file, d.path().join("vault (1).pwv")).unwrap();
    pc.sync().unwrap();
    assert_eq!(pc.entries().len(), 3, "{:?}", titles(&pc));
    // Nhập lại lần nữa trên chính máy đó: toàn bộ là trùng.
    let again = import_csv(csv.as_bytes(), pc.entries()).unwrap();
    assert_eq!((again.entries.len(), again.duplicates), (0, 3));
    // Mục đã bị xoá vĩnh viễn mà nhập lại thì thành mục mới (id cũ không bao giờ được dùng lại).
    let gmail = pc
        .entries()
        .iter()
        .find(|e| e.title == "Gmail")
        .unwrap()
        .id
        .clone();
    pc.transact(|v| v.purge(&gmail)).unwrap();
    let res = import_csv(csv.as_bytes(), pc.entries()).unwrap();
    assert_eq!(res.entries.len(), 1);
    assert_eq!(res.entries[0].id, gmail, "id suy ra từ nội dung");
    let (new_id, _) = pc
        .transact(|v| Ok(v.add(res.entries.into_iter().next().unwrap())))
        .unwrap();
    assert_ne!(new_id, gmail);
    assert_eq!(pc.entries().len(), 3);
}

// ----------------------------------------------------------------------------- file trên đĩa có vấn đề

/// Lỗi 0.1.2: file trên đĩa hỏng ⇒ mọi lần lưu đều lỗi với thông báo "sai mật khẩu", thay đổi chỉ
/// nằm trong RAM (vẫn hiện trong danh sách!) rồi mất khi app tự khoá; không có cách nào ghi ra.
#[test]
fn damaged_file_on_disk_is_reported_and_can_be_replaced_on_request() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    v.transact(|v| Ok(v.add(login("A", "a", "a")))).unwrap();
    let good = fs::read(&p).unwrap();

    for damaged in [
        Vec::new(),                      // 0 byte (đồng bộ dở)
        good[..good.len() / 2].to_vec(), // cụt một nửa
        {
            let mut b = good.clone(); // một bit bị lật ở phần thân
            let i = b.len() - 100;
            b[i] ^= 1;
            b
        },
    ] {
        fs::write(&p, &damaged).unwrap();
        let r = v.transact(|v| Ok(v.add(login("B", "b", "b"))));
        assert!(matches!(r, Err(Error::VaultFileDamaged)), "{r:?}");
        assert_eq!(
            titles(&v),
            ["A"],
            "mục chưa ghi được không được hiện như đã lưu"
        );
        assert!(matches!(v.sync(), Err(Error::VaultFileDamaged)));
        assert_eq!(fs::read(&p).unwrap(), damaged, "không tự ý ghi đè");
    }

    // Người dùng xác nhận "ghi đè bằng bản đang mở": file hỏng được CẤT vào thư mục sao lưu.
    let archived = v
        .force_write()
        .unwrap()
        .expect("file hỏng phải được cất đi");
    assert!(archived.exists());
    assert_eq!(
        list_backups(&p)
            .iter()
            .filter(|b| b.kind == BackupKind::Damaged)
            .count(),
        1
    );
    v.transact(|v| Ok(v.add(login("B", "b", "b")))).unwrap();
    assert_eq!(titles(&open(&p, PW).unwrap()), ["A", "B"]);
    // File lành: force_write không cất gì cả.
    assert!(v.force_write().unwrap().is_none());
}

/// Lỗi 0.1.2: file biến mất (máy kia đã chuyển kho đi nơi khác) ⇒ máy này âm thầm tạo lại file ở
/// chỗ cũ ⇒ kho bị tách đôi mà không ai hay.
#[test]
fn missing_file_is_never_silently_recreated() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    v.transact(|v| Ok(v.add(login("A", "a", "a")))).unwrap();
    fs::remove_file(&p).unwrap();

    assert!(matches!(
        v.transact(|v| Ok(v.add(login("B", "b", "b")))),
        Err(Error::VaultFileMissing(_))
    ));
    assert!(matches!(v.sync(), Err(Error::VaultFileMissing(_))));
    assert!(matches!(v.save(), Err(Error::VaultFileMissing(_))));
    assert!(!p.exists());
    assert_eq!(titles(&v), ["A"]);
    // Chỉ khi người dùng chọn "tạo lại ở đây".
    assert!(v.force_write().unwrap().is_none());
    assert_eq!(titles(&open(&p, PW).unwrap()), ["A"]);
}

#[test]
fn foreign_or_newer_files_are_never_overwritten() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    v.transact(|v| Ok(v.add(login("A", "a", "a")))).unwrap();
    let mine = fs::read(&p).unwrap();

    // Kho khác xuất hiện ở đúng đường dẫn này (máy thứ hai bấm "Tạo kho mới" trước khi đồng bộ xong).
    let other = d.path().join("other.pwv");
    Vault::create(&other, PW, opts()).unwrap();
    fs::copy(&other, &p).unwrap();
    let foreign = fs::read(&p).unwrap();
    assert!(matches!(
        v.transact(|v| Ok(v.add(login("B", "b", "b")))),
        Err(Error::DifferentVault)
    ));
    assert!(matches!(v.force_write(), Err(Error::DifferentVault)));
    assert_eq!(fs::read(&p).unwrap(), foreign);

    // File do bản app MỚI HƠN ghi (số phiên bản định dạng lớn hơn): không đụng vào.
    let mut newer = mine.clone();
    newer[4] = 3;
    fs::write(&p, &newer).unwrap();
    assert!(matches!(v.save(), Err(Error::UnsupportedVersion(3))));
    assert!(matches!(v.force_write(), Err(Error::UnsupportedVersion(3))));
    assert_eq!(fs::read(&p).unwrap(), newer);

    // Vẫn cứu được bản đang mở bằng cách lưu ra chỗ khác; chỗ cũ giữ nguyên.
    let rescue = d.path().join("rescue").join("vault.pwv");
    let r = v.move_to(&rescue).unwrap();
    assert!(r.rescued && !r.old_removed && !r.backups_moved);
    assert_eq!(fs::read(&p).unwrap(), newer);
    assert_eq!(titles(&open(&rescue, PW).unwrap()), ["A"]);
}

// ----------------------------------------------------------------------------- sao lưu

/// Lỗi 0.1.2: chỉ giữ 10 bản gần nhất ⇒ 10 lần bấm ★ là xoá sạch mọi trạng thái cũ.
#[test]
fn backups_survive_many_trivial_saves_and_can_be_restored_from() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    let bank = v.add(login("Bank", "u", "bank-password"));
    let other = v.add(login("Other", "o", "o"));
    v.save().unwrap();
    v.transact(|v| v.update(&bank, |e| e.notes = "mã khôi phục 1234".into()))
        .unwrap();
    // Sửa nhầm rồi xoá vĩnh viễn…
    v.transact(|v| {
        v.update(&bank, |e| {
            e.password = "mistake".into();
            e.notes.clear();
        })
    })
    .unwrap();
    v.transact(|v| v.purge(&bank)).unwrap();
    // …rồi 30 lần lưu lặt vặt.
    for i in 0..30 {
        v.transact(|v| v.update(&other, |e| e.favorite = i % 2 == 0))
            .unwrap();
    }
    assert!(v.get(&bank).is_none());

    let backups = v.backups();
    assert!(backups.len() <= 12, "vẫn có giới hạn: {}", backups.len());
    assert!(backups.iter().all(|b| b.kind == BackupKind::Auto));
    // Trong cùng một ngày chỉ giữ 10 bản gần nhất, nên bản có "Bank" đã bị xoay vòng ở đây —
    // việc giữ bản cuối của từng NGÀY/THÁNG được kiểm tra ở fsutil::tests. Ở đây kiểm tra đường
    // khôi phục: đọc một bản sao lưu và đưa một mục trở lại.
    let newest = &backups[0];
    let data = v.read_backup(&newest.path).unwrap();
    assert!(data.get(&other).is_some());

    // Khôi phục "Other" về phiên bản trong bản sao lưu cũ nhất còn giữ.
    let oldest = backups.last().unwrap();
    let old = v.read_backup(&oldest.path).unwrap();
    let wanted = old.get(&other).unwrap().clone();
    v.transact(|v| {
        v.update(&other, |e| e.password = "changed-later".into())?;
        Ok(())
    })
    .unwrap();
    let (changed, _) = v.transact(|v| Ok(v.reinstate(&wanted))).unwrap();
    assert!(changed);
    let e = v.get(&other).unwrap();
    assert_eq!(e.password, "o");
    assert_eq!(e.password_history[0].password, "changed-later");

    // Chỉ đọc được file nằm trong thư mục sao lưu của chính kho này.
    assert!(v.read_backup(&p).is_err());
    assert!(v
        .read_backup(&backup_dir(&p).join("..").join("vault.pwv"))
        .is_err());
}

/// Khôi phục từ bản sao lưu là "một lần sửa mới" nên lan sang máy khác thay vì bị gộp ngược lại
/// (lỗi 0.1.2: chép đè file sao lưu lên file kho thì máy đang mở sẽ gộp và xoá lại ngay).
#[test]
fn restoring_from_a_backup_propagates_to_other_devices() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut pc) = new_vault(&d);
    let id = pc.add(login("Bank", "u", "good-password"));
    pc.save().unwrap();
    let mut laptop = open(&p, PW).unwrap();
    pc.transact(|v| v.delete(&id)).unwrap();
    pc.transact(|v| v.purge(&id)).unwrap();
    laptop.sync().unwrap();
    assert!(laptop.entries().is_empty());

    // Trên PC: lấy lại "Bank" từ bản sao lưu.
    let backup = pc
        .backups()
        .into_iter()
        .find(|b| pc.read_backup(&b.path).is_ok_and(|d| d.get(&id).is_some()))
        .expect("phải còn bản sao lưu chứa mục đã xoá");
    let old = pc
        .read_backup(&backup.path)
        .unwrap()
        .get(&id)
        .unwrap()
        .clone();
    pc.transact(|v| Ok(v.reinstate(&old))).unwrap();
    assert_eq!(titles(&pc), ["Bank"]);
    // Laptop (đang mở, còn nhớ lệnh xoá) đồng bộ: mục quay lại chứ không bị xoá lần nữa.
    laptop.sync().unwrap();
    assert_eq!(titles(&laptop), ["Bank"]);
    assert_eq!(laptop.entries()[0].password, "good-password");
    pc.sync().unwrap();
    assert_eq!(titles(&pc), ["Bank"]);
}

/// Kho đang KHOÁ mà file chính hỏng hẳn: dựng lại từ thư mục sao lưu (bản 0.1.2 chỉ báo lỗi và
/// để người dùng tự mò vào thư mục sao lưu chép file).
#[test]
fn recover_from_backups_when_the_main_file_is_destroyed() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    for t in ["A", "B", "C"] {
        v.transact(|v| Ok(v.add(login(t, "u", "p")))).unwrap();
    }
    drop(v);
    // Chưa có gì hỏng thì khôi phục vẫn chạy được (và gộp cả file chính khi ghi).
    let good = fs::read(&p).unwrap();
    fs::write(&p, b"\0\0\0 rac").unwrap();
    assert!(open(&p, PW).is_err());
    let o = OpenOptions {
        allow_weak_kdf: true,
    };
    assert!(matches!(
        Vault::recover_from_backups(&p, b"sai mat khau", o),
        Err(Error::Decrypt)
    ));
    let (mut r, used, newest) = Vault::recover_from_backups(&p, PW, o).unwrap();
    assert!(used >= 1 && newest > 0);
    // Bản sao lưu mới nhất luôn là bản sao của chính file kho ⇒ không mất cả lần sửa cuối ("C").
    // (Bản 0.1.2 chỉ sao lưu TRƯỚC mỗi lần ghi nên luôn thiếu lần sửa cuối.)
    assert_eq!(titles(&r), ["A", "B", "C"]);
    let archived = r.force_write().unwrap().expect("file hỏng được cất đi");
    assert_eq!(fs::read(&archived).unwrap(), b"\0\0\0 rac");
    assert_eq!(titles(&open(&p, PW).unwrap()), ["A", "B", "C"]);

    // Nếu file chính thật ra vẫn lành (người dùng bấm nhầm): không mất gì, không cất gì.
    fs::write(&p, &good).unwrap();
    let (mut r, _, _) = Vault::recover_from_backups(&p, PW, o).unwrap();
    assert!(r.force_write().unwrap().is_none());
    assert_eq!(titles(&open(&p, PW).unwrap()), ["A", "B", "C"]);

    // Không có thư mục sao lưu: báo lỗi rõ ràng.
    let lonely = d.path().join("khong-co-sao-luu.pwv");
    assert!(Vault::recover_from_backups(&lonely, PW, o).is_err());
}

// ----------------------------------------------------------------------------- chuyển kho

#[test]
fn move_vault_to_another_folder() {
    let d = tempfile::tempdir().unwrap();
    let old = d.path().join("Documents").join("vault.pwv");
    fs::create_dir_all(old.parent().unwrap()).unwrap();
    let mut v = Vault::create(&old, PW, opts()).unwrap();
    let id = v.add(login("Gmail", "u", "p1"));
    v.save().unwrap();
    v.update(&id, |e| e.password = "p2".into()).unwrap();
    v.save().unwrap(); // tạo thư mục sao lưu ở chỗ cũ
    assert!(!list_backups(&old).is_empty());

    let new = d.path().join("Dropbox").join("Passwords").join("vault.pwv");
    let r = v.move_to(&new).unwrap();
    assert!(r.old_removed && r.backups_moved && !r.rescued);
    assert!(!old.exists());
    assert!(!backup_dir(&old).exists());
    assert!(!list_backups(&new).is_empty());
    assert_eq!(v.path(), new.as_path());

    // Kho ở chỗ mới mở được, dữ liệu đủ, và lưu tiếp vào chỗ mới.
    v.add(login("Sau khi chuyển", "a", "a"));
    v.save().unwrap();
    let reopened = open(&new, PW).unwrap();
    assert_eq!(reopened.entries().len(), 2);
    assert_eq!(reopened.get(&id).unwrap().password, "p2");
    assert!(!old.exists(), "không được ghi lại file ở chỗ cũ");
}

#[test]
fn move_refuses_existing_target_and_same_path() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    assert!(matches!(v.move_to(&p), Err(Error::SamePath)));
    let other = d.path().join("khac.pwv");
    fs::write(&other, b"x").unwrap();
    assert!(matches!(v.move_to(&other), Err(Error::AlreadyExists(_))));
    assert!(p.exists(), "kho cũ phải còn nguyên");
    assert_eq!(fs::read(&other).unwrap(), b"x", "không ghi đè file có sẵn");
}

/// Lỗi nặng nhất của 0.1.2: chọn đích nằm trong thư mục sao lưu của chính kho ⇒ kho và MỌI bản sao
/// lưu bị xoá sạch, app vẫn báo "đã chuyển thành công".
#[test]
fn moving_into_the_vaults_own_backup_folder_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut v) = new_vault(&d);
    for i in 0..3 {
        v.transact(|v| Ok(v.add(login(&format!("e{i}"), "u", "p"))))
            .unwrap();
    }
    let backups_before = list_backups(&p).len();
    assert!(backups_before >= 2);
    let before = fs::read(&p).unwrap();
    for target in [
        backup_dir(&p).join("vault.pwv"),
        backup_dir(&p).join("sub").join("kho.pwv"),
        backup_dir(&p)
            .join("..")
            .join("vault.pwv.backups")
            .join("x.pwv"),
    ] {
        assert!(
            matches!(v.move_to(&target), Err(Error::MoveIntoBackups)),
            "{target:?}"
        );
        assert!(!target.exists());
    }
    assert_eq!(fs::read(&p).unwrap(), before);
    assert_eq!(list_backups(&p).len(), backups_before);
    assert_eq!(v.path(), p.as_path());
    assert_eq!(open(&p, PW).unwrap().entries().len(), 3);
}

// ----------------------------------------------------------------------------- điện thoại (chỉ đọc)

#[test]
fn read_only_open_and_reload() {
    let d = tempfile::tempdir().unwrap();
    let (p, mut pc) = new_vault(&d);
    pc.add(login("A", "a", "a"));
    pc.save().unwrap();

    let mut phone = open_bytes(&fs::read(&p).unwrap(), PW).unwrap();
    assert!(phone.is_read_only());
    assert_eq!(phone.entries().len(), 1);
    assert!(matches!(phone.save(), Err(Error::ReadOnly)));
    assert!(matches!(phone.sync(), Err(Error::ReadOnly)));
    assert!(matches!(phone.force_write(), Err(Error::ReadOnly)));
    assert!(matches!(
        phone.transact(|v| Ok(v.add(login("x", "x", "x")))),
        Err(Error::ReadOnly)
    ));
    assert!(matches!(
        phone.move_to(d.path().join("x.pwv")),
        Err(Error::ReadOnly)
    ));
    assert!(phone.conflict_copies().is_empty());
    assert!(open_bytes(&fs::read(&p).unwrap(), b"sai").is_err());

    // Máy tính thêm mục; điện thoại tải lại không cần mật khẩu.
    let older = fs::read(&p).unwrap();
    pc.add(login("B", "b", "b"));
    pc.save().unwrap();
    assert!(phone.replace_from_bytes(&fs::read(&p).unwrap()).unwrap());
    assert_eq!(phone.entries().len(), 2);
    assert!(
        !phone.replace_from_bytes(&fs::read(&p).unwrap()).unwrap(),
        "không đổi ⇒ false"
    );
    // Lỗi 0.1.2: chọn nhầm một bản CŨ (bản sao lưu, bản xung đột) thì điện thoại quay về dữ liệu
    // cũ mà vẫn báo "đã tải bản mới nhất". Giờ dữ liệu được gộp nên không bao giờ đi lùi.
    assert!(!phone.replace_from_bytes(&older).unwrap());
    assert_eq!(phone.entries().len(), 2);

    // Không nhận file của kho khác.
    let other = d.path().join("other.pwv");
    Vault::create(&other, PW, opts()).unwrap();
    assert!(matches!(
        phone.replace_from_bytes(&fs::read(&other).unwrap()),
        Err(Error::DifferentVault)
    ));
}

// ----------------------------------------------------------------------------- tương thích ngược

/// File do bản phát hành 0.1.2 tạo ra (định dạng v1, tham số Argon2 mặc định 256 MiB) phải mở được
/// mãi mãi. File này nằm trong repo: nếu test này đỏ thì người dùng thật sẽ không mở được kho.
#[test]
fn golden_vault_written_by_release_0_1_2_still_opens() {
    let d = tempfile::tempdir().unwrap();
    let p = fixture_copy(&d, "v1-golden-0.1.2.pwv", "vault.pwv");
    let original = fs::read(&p).unwrap();
    assert_eq!(original[4..6], [1, 0], "file mẫu là định dạng v1");
    assert!(matches!(
        Vault::open(&p, b"golden-old-password"),
        Err(Error::Decrypt)
    ));
    let mut v = Vault::open(&p, "golden-new-password-äö-ngựa".as_bytes()).unwrap();
    assert_eq!(v.kdf_params(), KdfParams::DEFAULT);
    assert_eq!(v.vault_id(), "ec415505-afd0-48cd-b5b5-ef15fd6586b1");
    assert_eq!(v.key_changed_at(), 1_795_174_570_118);
    assert_eq!(v.modified_at(), 1_795_174_570_117);
    assert_eq!(titles(&v), ["Email", "Ngân hàng Việt"]);
    const BANK: &str = "c60fd36c-b38b-43bf-a91f-91becc844f04";
    const EMAIL: &str = "280ec92e-1b0f-4169-bb3b-19117ca84698";
    let bank = v.get(BANK).unwrap();
    assert_eq!(bank.username, "nguyễn văn a");
    assert_eq!(bank.password, "Mật-khẩu-2-🔐");
    assert_eq!(bank.password_history.len(), 1);
    assert_eq!(bank.password_history[0].password, "Mật-khẩu-1-🔐");
    assert_eq!(bank.urls, ["https://bank.example.vn/login"]);
    assert_eq!(bank.notes, "Số tài khoản: 0123456789\nDòng 2");
    assert_eq!(bank.tags, ["Ngân hàng"]);
    assert!(bank.favorite);
    assert_eq!(
        (bank.created_at, bank.updated_at),
        (1_795_174_570_116, 1_795_174_570_117)
    );
    let email = v.get(EMAIL).unwrap();
    assert_eq!(email.password, "correct horse battery staple");
    assert!(email.totp.as_deref().unwrap().contains("JBSWY3DPEHPK3PXP"));
    // Mục thứ ba đã bị xoá ở bản 0.1.2 (tombstone): không ở danh sách, không ở thùng rác.
    assert!(v.get("64ae35aa-8053-49bf-9eee-f811b15fa059").is_none());
    assert!(v.trash().is_empty());

    // Chỉ mở/đồng bộ thì KHÔNG ghi gì (không tự nâng cấp định dạng khi chưa cần).
    let r = v.sync().unwrap();
    assert!(!r.wrote);
    assert_eq!(fs::read(&p).unwrap(), original);
    // Sửa một mục ⇒ file được ghi ở định dạng v2, bản v1 nằm trong thư mục sao lưu.
    v.transact(|v| v.update(EMAIL, |e| e.favorite = true))
        .unwrap();
    let upgraded = fs::read(&p).unwrap();
    assert_eq!(upgraded[4..6], [2, 0]);
    // Thư mục sao lưu giữ cả bản v1 gốc (chép TRƯỚC khi ghi đè) lẫn bản vừa ghi.
    let backups = list_backups(&p);
    assert_eq!(backups.len(), 2);
    assert_eq!(fs::read(&backups[0].path).unwrap(), upgraded);
    assert_eq!(fs::read(&backups[1].path).unwrap(), original);
    let v = Vault::open(&p, "golden-new-password-äö-ngựa".as_bytes()).unwrap();
    assert_eq!(v.get(BANK).unwrap().password, "Mật-khẩu-2-🔐");
    assert!(v.get(EMAIL).unwrap().favorite);
}

#[test]
fn v1_file_with_tombstones_and_history_upgrades_cleanly() {
    let d = tempfile::tempdir().unwrap();
    let p = fixture_copy(&d, "v1-mixed.pwv", "vault.pwv");
    let nfc = "m\u{1ead}t kh\u{1ea9}u k\u{1ebf}t h\u{1ee3}p 42";
    let mut v = Vault::open(&p, nfc.as_bytes()).unwrap();
    assert_eq!(titles(&v), ["Email", "Ngân hàng Việt"]);
    let bank = v
        .entries()
        .iter()
        .find(|e| e.title == "Ngân hàng Việt")
        .unwrap()
        .clone();
    assert_eq!(bank.password, "Mật-khẩu-2-🔐");
    assert_eq!(bank.password_history[0].password, "Mật-khẩu-1-🔐");
    // Mục đã xoá ở bản 0.1.2 (tombstone) không quay lại, kể cả khi gộp với bản cũ còn chứa nó.
    v.transact(|v| v.update(&bank.id, |e| e.notes.push_str("\nthêm")))
        .unwrap();
    let v = Vault::open(&p, nfc.as_bytes()).unwrap();
    assert_eq!(v.entries().len(), 2);
    assert!(v.trash().is_empty());
    let raw_bytes = fs::read(&p).unwrap();
    assert!(format::parse(&raw_bytes).is_ok());
}
