//! Fuzz bằng proptest: dữ liệu ngẫu nhiên / bị sửa không bao giờ làm chương trình panic,
//! và không bao giờ được chấp nhận như một kho hợp lệ.

use proptest::prelude::*;
use pwv_vault_core::format;
use pwv_vault_core::import::import_csv;
use pwv_vault_core::{CreateOptions, Entry, KdfParams, OpenOptions, Totp, Vault};

const PW: &[u8] = b"fuzz-master-password";

fn valid_file() -> Vec<u8> {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("v.pwv");
    let mut v = Vault::create(
        &p,
        PW,
        CreateOptions {
            kdf: KdfParams::INSECURE_TEST,
            allow_weak_kdf: true,
        },
    )
    .unwrap();
    let mut e = Entry::new("Bank");
    e.password = "secret".into();
    v.add(e);
    v.save().unwrap();
    std::fs::read(&p).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn parse_never_panics_on_random_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = format::parse(&bytes);
        let _ = format::peek_header(&bytes);
    }

    #[test]
    fn parse_never_panics_with_valid_magic(mut tail in proptest::collection::vec(any::<u8>(), 0..512), len in any::<u32>()) {
        let mut b = b"PWV1\x02\x00".to_vec();
        b.extend_from_slice(&(len % 1024).to_le_bytes());
        b.append(&mut tail);
        let _ = format::parse(&b);
    }

    #[test]
    fn totp_parse_never_panics(s in ".{0,200}") {
        let _ = Totp::parse(&s);
        let _ = Totp::parse(&format!("otpauth://totp/{s}"));
        if let Ok(t) = Totp::parse(&format!("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&{s}")) {
            let _ = t.code_at(u64::MAX);
        }
    }

    #[test]
    fn csv_import_never_panics(s in "(?s).{0,400}") {
        let _ = import_csv(format!("name,url,username,password\n{s}").as_bytes(), &[]);
        let _ = import_csv(s.as_bytes(), &[]);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    /// Khối niêm phong cục bộ: rác / bị sửa / cụt không bao giờ làm panic và không bao giờ mở được.
    #[test]
    fn open_local_never_panics(tail in proptest::collection::vec(any::<u8>(), 0..256), magic in any::<bool>(), purpose in ".{0,20}") {
        let v = local_vault();
        let mut b = if magic { b"PWL1".to_vec() } else { Vec::new() };
        b.extend_from_slice(&tail);
        prop_assert!(v.open_local(&purpose, &b).is_none());
        let sealed = v.seal_local(&purpose, &tail).unwrap();
        prop_assert_eq!(&**v.open_local(&purpose, &sealed).unwrap(), &tail[..]);
        if !tail.is_empty() {
            let mut bad = sealed.clone();
            let i = 4 + (tail[0] as usize) % (bad.len() - 4);
            bad[i] ^= 1;
            prop_assert!(v.open_local(&purpose, &bad).is_none());
        }
    }
}

fn local_vault() -> &'static Vault {
    static V: std::sync::OnceLock<(tempfile::TempDir, Vault)> = std::sync::OnceLock::new();
    &V.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::create(
            d.path().join("v.pwv"),
            PW,
            CreateOptions {
                kdf: KdfParams::INSECURE_TEST,
                allow_weak_kdf: true,
            },
        )
        .unwrap();
        (d, v)
    })
    .1
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 300, ..ProptestConfig::default() })]

    /// Sửa ngẫu nhiên 1–8 byte của một file hợp lệ: luôn bị từ chối, không panic.
    #[test]
    fn mutated_vault_is_rejected(edits in proptest::collection::vec((any::<usize>(), 1u8..=255), 1..8)) {
        let orig = valid_file();
        let mut bad = orig.clone();
        for (pos, xor) in &edits {
            let i = pos % bad.len();
            bad[i] ^= xor;
        }
        prop_assume!(bad != orig);
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("bad.pwv");
        std::fs::write(&p, &bad).unwrap();
        let opened = Vault::open_with(
            &p,
            PW,
            OpenOptions {
                allow_weak_kdf: true,
            },
        );
        prop_assert!(opened.is_err());
    }
}
