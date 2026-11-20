//! Test tích hợp cho kho: tạo/mở/lưu, sai mật khẩu, sửa file, đồng bộ hai máy qua "Google Drive".

use std::fs;

use pwv_vault_core::{CreateOptions, Entry, Error, KdfParams, Vault};

const PW: &[u8] = b"master password dai va kho doan 123!";

fn opts() -> CreateOptions {
    CreateOptions {
        kdf: KdfParams::INSECURE_TEST,
        allow_weak_kdf: true,
    }
}

fn login(title: &str, user: &str, pw: &str) -> Entry {
    let mut e = Entry::new(title);
    e.username = user.into();
    e.password = pw.into();
    e
}

#[test]
fn create_add_save_reopen() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut v = Vault::create(&p, PW, opts()).unwrap();
    let id = v.add(login("Gmail", "toi@gmail.com", "S3cret!"));
    v.save().unwrap();
    drop(v);

    let v = Vault::open(&p, PW).unwrap();
    assert_eq!(v.entries().len(), 1);
    let e = v.get(&id).unwrap();
    assert_eq!(e.username, "toi@gmail.com");
    assert_eq!(e.password, "S3cret!");
    assert!(v.verify_password(PW));
    assert!(!v.verify_password(b"sai"));
}

#[test]
fn create_refuses_to_overwrite_and_weak_kdf() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    Vault::create(&p, PW, opts()).unwrap();
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
}

#[test]
fn wrong_password_fails() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    Vault::create(&p, PW, opts()).unwrap();
    assert!(matches!(Vault::open(&p, b"wrong"), Err(Error::Decrypt)));
}

#[test]
fn no_plaintext_on_disk() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut v = Vault::create(&p, PW, opts()).unwrap();
    v.add(login("Vietcombank", "nguyenvana", "MatKhauNganHang"));
    v.save().unwrap();
    let bytes = fs::read(&p).unwrap();
    for needle in ["Vietcombank", "nguyenvana", "MatKhauNganHang"] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "lộ '{needle}' trong file"
        );
    }
    // Kích thước được đệm lên bội số 4 KiB (không lộ số mục).
    let small = bytes.len();
    for i in 0..5 {
        v.add(login(&format!("site{i}"), "u", "p"));
    }
    v.save().unwrap();
    assert_eq!(fs::read(&p).unwrap().len(), small);
}

#[test]
fn every_single_byte_flip_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut v = Vault::create(&p, PW, opts()).unwrap();
    v.add(login("A", "a", "a"));
    v.save().unwrap();
    let orig = fs::read(&p).unwrap();
    // Thử lật 1 bit ở nhiều vị trí khác nhau (header, nonce, ciphertext, tag).
    let step = (orig.len() / 200).max(1);
    for i in (0..orig.len()).step_by(step).chain([orig.len() - 1]) {
        let mut bad = orig.clone();
        bad[i] ^= 0x01;
        fs::write(&p, &bad).unwrap();
        assert!(
            Vault::open(&p, PW).is_err(),
            "không phát hiện sửa đổi ở byte {i}"
        );
    }
    // Cắt cụt file.
    fs::write(&p, &orig[..orig.len() / 2]).unwrap();
    assert!(Vault::open(&p, PW).is_err());
}

#[test]
fn update_keeps_password_history_and_delete_works() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut v = Vault::create(&p, PW, opts()).unwrap();
    let id = v.add(login("Bank", "u", "old-pass"));
    v.update(&id, |e| e.password = "new-pass".into()).unwrap();
    let e = v.get(&id).unwrap();
    assert_eq!(e.password, "new-pass");
    assert_eq!(e.password_history[0].password, "old-pass");
    v.delete(&id).unwrap();
    assert!(v.get(&id).is_none());
    assert!(matches!(v.delete(&id), Err(Error::EntryNotFound(_))));
}

#[test]
fn change_master_password() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut v = Vault::create(&p, PW, opts()).unwrap();
    v.add(login("X", "x", "x"));
    v.change_password_insecure_for_tests(b"mat khau moi", KdfParams::INSECURE_TEST)
        .unwrap();
    v.save().unwrap();
    assert!(Vault::open(&p, PW).is_err());
    let v = Vault::open(&p, b"mat khau moi").unwrap();
    assert_eq!(v.entries().len(), 1);
}

/// Mô phỏng hai máy Windows cùng mở một file trong thư mục Google Drive.
#[test]
fn two_devices_sync_without_losing_data() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut setup = Vault::create(&p, PW, opts()).unwrap();
    let shared = setup.add(login("Shared", "s", "v1"));
    let to_delete = setup.add(login("Old", "o", "o"));
    setup.save().unwrap();
    drop(setup);

    let mut pc = Vault::open(&p, PW).unwrap();
    let mut laptop = Vault::open(&p, PW).unwrap();

    // PC: thêm mục, sửa mục chung, rồi lưu.
    let pc_only = pc.add(login("PC only", "a", "a"));
    pc.update(&shared, |e| e.password = "from-pc".into())
        .unwrap();
    assert!(pc.save().unwrap().merged_remote.is_none());

    // Laptop (chưa thấy thay đổi của PC): thêm mục, xoá mục, sửa mục chung muộn hơn.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let laptop_only = laptop.add(login("Laptop only", "b", "b"));
    laptop.delete(&to_delete).unwrap();
    laptop
        .update(&shared, |e| e.password = "from-laptop".into())
        .unwrap();
    assert!(laptop.changed_on_disk().unwrap());
    let report = laptop.save().unwrap();
    assert!(
        report.merged_remote.is_some(),
        "phải phát hiện thay đổi từ PC"
    );

    let v = Vault::open(&p, PW).unwrap();
    assert!(v.get(&pc_only).is_some());
    assert!(v.get(&laptop_only).is_some());
    assert!(v.get(&to_delete).is_none());
    let s = v.get(&shared).unwrap();
    assert_eq!(s.password, "from-laptop");
    // Mật khẩu của bên "thua" không bị mất mà nằm trong lịch sử.
    assert!(s.password_history.iter().any(|h| h.password == "from-pc"));

    // PC nạp lại và thấy đủ.
    pc.reload().unwrap();
    assert!(pc.get(&laptop_only).is_some());
    assert!(pc.get(&to_delete).is_none());
}

#[test]
fn password_changed_on_other_device_is_adopted() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    Vault::create(&p, PW, opts()).unwrap();
    let mut a = Vault::open(&p, PW).unwrap();
    let mut b = Vault::open(&p, PW).unwrap();
    a.change_password_insecure_for_tests(b"new", KdfParams::INSECURE_TEST)
        .unwrap();
    a.save().unwrap();
    b.add(login("B", "b", "b"));
    let r = b.save().unwrap();
    assert!(r.adopted_remote_password);
    let v = Vault::open(&p, b"new").unwrap();
    assert_eq!(v.entries().len(), 1);
    assert!(Vault::open(&p, PW).is_err());
}

#[test]
fn merge_google_drive_conflict_copy() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut v = Vault::create(&p, PW, opts()).unwrap();
    v.add(login("Base", "b", "b"));
    v.save().unwrap();
    // Drive tạo bản xung đột: một bản sao có thêm mục.
    let conflict = d.path().join("vault (1).pwv");
    fs::copy(&p, &conflict).unwrap();
    {
        let mut other = Vault::open(&conflict, PW).unwrap();
        other.add(login("Only in conflict copy", "c", "c"));
        other.save().unwrap();
    }
    let mut v = Vault::open(&p, PW).unwrap();
    assert_eq!(v.conflict_copies(), vec![conflict.clone()]);
    let stats = v.merge_file(&conflict).unwrap();
    assert_eq!(stats.added, 1);
    assert_eq!(v.entries().len(), 2);

    // Không gộp được file của kho khác.
    let other_vault = d.path().join("khac.pwv");
    Vault::create(&other_vault, PW, opts()).unwrap();
    assert!(matches!(
        v.merge_file(&other_vault),
        Err(Error::DifferentVault)
    ));
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
        assert!(Vault::open(&p, PW).is_err());
    }
    // header_len khổng lồ
    let mut b = b"PWV1\x01\x00".to_vec();
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&p, &b).unwrap();
    assert!(matches!(Vault::open(&p, PW), Err(Error::BadFormat)));
}

/// Bản xung đột kiểu Dropbox / OneDrive cũng được gộp và chuyển vào thư mục sao lưu.
#[test]
fn merges_dropbox_and_onedrive_conflict_copies() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut v = Vault::create(&p, PW, opts()).unwrap();
    v.add(login("Base", "b", "b"));
    v.save().unwrap();
    for (name, title) in [
        (
            "vault (Binh's conflicted copy 2026-11-20).pwv",
            "Từ Dropbox",
        ),
        ("vault-DESKTOP-AB12CD.pwv", "Từ OneDrive"),
    ] {
        let c = d.path().join(name);
        fs::copy(&p, &c).unwrap();
        let mut other = Vault::open(&c, PW).unwrap();
        other.add(login(title, "x", "x"));
        other.save().unwrap();
    }
    let mut v = Vault::open(&p, PW).unwrap();
    let results = v.merge_conflict_copies();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|(_, r)| r.is_ok()));
    v.save().unwrap();
    let titles: Vec<&str> = v.entries().iter().map(|e| e.title.as_str()).collect();
    assert!(titles.contains(&"Từ Dropbox") && titles.contains(&"Từ OneDrive"));
    assert!(
        v.conflict_copies().is_empty(),
        "đã chuyển vào thư mục sao lưu"
    );
}

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
    assert!(
        fs::read_dir(pwv_vault_core::fsutil::backup_dir(&old))
            .unwrap()
            .count()
            > 0
    );

    let new = d.path().join("Dropbox").join("Passwords").join("vault.pwv");
    let r = v.move_to(&new).unwrap();
    assert!(r.old_removed && r.backups_moved);
    assert!(!old.exists());
    assert!(!pwv_vault_core::fsutil::backup_dir(&old).exists());
    assert!(pwv_vault_core::fsutil::backup_dir(&new).is_dir());
    assert_eq!(v.path(), new.as_path());

    // Kho ở chỗ mới mở được, dữ liệu đủ, và lưu tiếp vào chỗ mới.
    v.add(login("Sau khi chuyển", "a", "a"));
    v.save().unwrap();
    let reopened = Vault::open(&new, PW).unwrap();
    assert_eq!(reopened.entries().len(), 2);
    assert_eq!(reopened.get(&id).unwrap().password, "p2");
    assert!(!old.exists(), "không được ghi lại file ở chỗ cũ");
}

#[test]
fn move_refuses_existing_target_and_same_path() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut v = Vault::create(&p, PW, opts()).unwrap();
    assert!(matches!(v.move_to(&p), Err(Error::SamePath)));
    let other = d.path().join("khac.pwv");
    fs::write(&other, b"x").unwrap();
    assert!(matches!(v.move_to(&other), Err(Error::AlreadyExists(_))));
    assert!(p.exists(), "kho cũ phải còn nguyên");
    assert_eq!(fs::read(&other).unwrap(), b"x", "không ghi đè file có sẵn");
}

/// Chế độ chỉ đọc (điện thoại): mở từ bytes, tải lại bản mới không cần mật khẩu, không ghi đĩa.
#[test]
fn read_only_open_and_replace() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pwv");
    let mut pc = Vault::create(&p, PW, opts()).unwrap();
    pc.add(login("A", "a", "a"));
    pc.save().unwrap();

    let mut phone =
        Vault::open_bytes("content://dropbox/vault.pwv", &fs::read(&p).unwrap(), PW).unwrap();
    assert!(phone.is_read_only());
    assert_eq!(phone.entries().len(), 1);
    assert!(matches!(phone.save(), Err(Error::ReadOnly)));
    assert!(matches!(
        phone.move_to(d.path().join("x.pwv")),
        Err(Error::ReadOnly)
    ));
    assert!(phone.merge_conflict_copies().is_empty());
    assert!(Vault::open_bytes("x", &fs::read(&p).unwrap(), b"sai").is_err());

    // Máy tính thêm mục và đổi master password; điện thoại tải lại được mà không cần mật khẩu mới.
    pc.add(login("B", "b", "b"));
    pc.change_password_insecure_for_tests(b"mat khau moi", KdfParams::INSECURE_TEST)
        .unwrap();
    pc.save().unwrap();
    assert!(phone.replace_from_bytes(&fs::read(&p).unwrap()).unwrap());
    assert_eq!(phone.entries().len(), 2);
    assert!(
        !phone.replace_from_bytes(&fs::read(&p).unwrap()).unwrap(),
        "không đổi ⇒ false"
    );

    // Không nhận file của kho khác.
    let other = d.path().join("other.pwv");
    Vault::create(&other, PW, opts()).unwrap();
    assert!(matches!(
        phone.replace_from_bytes(&fs::read(&other).unwrap()),
        Err(Error::DifferentVault)
    ));
}
