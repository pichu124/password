//! Tạo file kho mẫu để kiểm tra chéo với tools/pwv_recover.py.
//! cargo run -p pwv-vault-core --example make_fixture -- <đường-dẫn> <mật-khẩu>
use pwv_vault_core::{CreateOptions, Entry, KdfParams, Vault};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut v = Vault::create(
        &args[1],
        args[2].as_bytes(),
        CreateOptions {
            kdf: KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
            allow_weak_kdf: true,
        },
    )
    .unwrap();
    let mut e = Entry::new("Ngân hàng Việt");
    e.username = "nguyễn văn a".into();
    e.password = "Mật-khẩu-có-dấu-🔐".into();
    let id = v.add(e);
    v.update(&id, |e| e.password = "đổi lần 2".into()).unwrap();
    v.save().unwrap();
}
