#!/usr/bin/env python3
"""Kiểm tra chéo (chạy trong CI): công cụ cứu hộ Python — viết độc lập với mã Rust, chỉ dựa trên
docs/FORMAT.md — phải đọc được:

  1. file định dạng v2 do app hiện tại vừa tạo, SAU một lần đổi master password (đổi khoá kho);
  2. các file định dạng v1 do bản phát hành 0.1.2 tạo (nằm sẵn trong repo).

Dùng: python tools/check_recover.py <fixture.pwv tạo bởi `cargo run --example make_fixture -- fixture.pwv "pässwörd" "mật khẩu mới"`>
"""
import pathlib
import sys
import unicodedata

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from nacl.exceptions import CryptoError  # noqa: E402
from pwv_recover import decrypt_vault  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "crates" / "vault-core" / "tests" / "fixtures"


def must_fail(data: bytes, password: str) -> None:
    try:
        decrypt_vault(data, password)
    except CryptoError:
        return
    raise SystemExit(f"LỖI: mật khẩu {password!r} lẽ ra không mở được file")


def check_v2(path: str) -> None:
    data = open(path, "rb").read()
    assert data[4:6] == b"\x02\x00", "file mới phải là định dạng v2"
    new_pw = "mật khẩu mới"
    d = decrypt_vault(data, new_pw)
    bank = next(e for e in d["entries"] if e["title"] == "Ngân hàng Việt")
    assert bank["username"] == "nguyễn văn a", bank
    assert bank["password"] == "đổi lần 2", bank
    assert bank["password_history"][0]["password"] == "Mật-khẩu-có-dấu-🔐", bank
    # v2: thời điểm sửa của từng trường; mật khẩu được đổi sau khi mục được tạo.
    ft = bank["field_times"]
    assert ft["password"] >= ft["title"] > 0 and ft["deleted"] == 0, ft
    assert bank["updated_at"] == max(v for k, v in ft.items() if k != "deleted"), bank
    assert [e["title"] for e in d["trash"]] == ["Trong thùng rác"], d["trash"]
    assert d["trash"][0]["field_times"]["deleted"] > 0
    assert d["tombstones"] == []
    # Đổi master password = đổi khoá kho: khoá cũ được giữ BÊN TRONG phần đã mã hoá…
    assert len(d["old_keys"]) == 1 and len(d["old_keys"][0]["key"]) == 44, d["old_keys"]
    # …và mật khẩu cũ không còn mở được file.
    must_fail(data, "pässwörd")
    # Gõ mật khẩu bằng bàn phím kiểu tổ hợp (NFD) vẫn mở được.
    nfd = unicodedata.normalize("NFD", new_pw)
    assert nfd != new_pw
    assert decrypt_vault(data, nfd)["entries"] == d["entries"]
    print("v2 OK:", path)


def check_v1() -> None:
    g = (FIXTURES / "v1-golden-0.1.2.pwv").read_bytes()
    assert g[4:6] == b"\x01\x00"
    d = decrypt_vault(g, "golden-new-password-äö-ngựa")
    assert sorted(e["title"] for e in d["entries"]) == ["Email", "Ngân hàng Việt"], d["entries"]
    bank = next(e for e in d["entries"] if e["title"] == "Ngân hàng Việt")
    assert bank["password"] == "Mật-khẩu-2-🔐"
    assert bank["password_history"][0]["password"] == "Mật-khẩu-1-🔐"
    assert len(d["tombstones"]) == 1
    must_fail(g, "golden-old-password")

    # Kho v1 tạo bằng mật khẩu gõ kiểu tổ hợp (NFD): mở được bằng cả hai kiểu gõ.
    m = (FIXTURES / "v1-mixed.pwv").read_bytes()
    nfc = "mật khẩu kết hợp 42"
    assert unicodedata.normalize("NFC", nfc) == nfc
    for typed in (nfc, unicodedata.normalize("NFD", nfc)):
        d = decrypt_vault(m, typed)
        assert sorted(e["title"] for e in d["entries"]) == ["Email", "Ngân hàng Việt"]
    print("v1 OK")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    check_v2(sys.argv[1])
    check_v1()
    print("cross-check OK")
