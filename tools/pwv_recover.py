#!/usr/bin/env python3
"""Công cụ cứu hộ ĐỘC LẬP cho file kho .pwv (định dạng v1 và v2).

Không dùng chung dòng code nào với app Rust. Mục đích:
  1. Kiểm tra chéo rằng định dạng trong docs/FORMAT.md đúng với thực tế.
  2. Nếu một ngày app hỏng / không build được, bạn vẫn lấy lại được dữ liệu.

Cài đặt:  pip install pynacl argon2-cffi
Dùng:     python pwv_recover.py "G:\\My Drive\\Passwords\\vault.pwv" -o backup.json
          (ghi JSON đã giải mã ra file backup.json — CẨN THẬN, đó là toàn bộ mật khẩu của bạn;
          xoá file ngay sau khi dùng)

Luôn dùng -o thay vì "> backup.json": trên Windows, việc chuyển hướng bằng ">" làm hỏng các ký tự
có dấu (và có thể làm công cụ dừng giữa chừng).

Dùng được cho cả file trong thư mục sao lưu (vault.pwv.backups\\...).
Trong JSON: "entries" là các mục đang dùng, "trash" là thùng rác.

Bản sao lưu có từ TRƯỚC lần đổi master password gần nhất mang dấu "pre_change" trong header: công cụ
vẫn mở được (bằng mật khẩu hiện tại) nhưng in một CẢNH BÁO — nội dung của bản đó có thể do người biết
mật khẩu cũ ghi. Nên dùng một bản không có dấu này nếu còn.

Công cụ chỉ mở file bằng đúng master password đã khoá file đó (mật khẩu của thời điểm file được ghi);
nó không dùng các khoá cũ ("old_keys") lưu bên trong kho để mở file khác.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import struct
import sys
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as xchacha_decrypt
from nacl.exceptions import CryptoError

SUPPORTED_VERSIONS = (1, 2)


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()  # salt rỗng = 32 byte 0
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def password_candidates(password) -> list:
    """Các dạng byte của master password cần thử, theo đúng thứ tự app dùng.

    App (từ 0.2.0) chuẩn hoá mật khẩu về Unicode NFC trước khi dẫn xuất khoá. Kho tạo bởi bản
    cũ hơn dùng nguyên văn những gì bàn phím gõ ra (có thể là dạng tổ hợp NFD).
    """
    if isinstance(password, bytes):
        try:
            password = password.decode("utf-8")
        except UnicodeDecodeError:
            return [password]
    out = []
    for form in ("NFC", None, "NFD"):
        b = (unicodedata.normalize(form, password) if form else password).encode("utf-8")
        if b not in out:
            out.append(b)
    return out


def read_header(data: bytes):
    """Đọc phần đầu file (không cần mật khẩu): trả về (header dạng dict, vị trí kết thúc header)."""
    if data[:4] != b"PWV1":
        raise ValueError("không phải file pwv")
    version, header_len = struct.unpack_from("<HI", data, 4)
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"phiên bản định dạng {version} chưa hỗ trợ — hãy dùng bản mới hơn của công cụ này")
    header_end = 10 + header_len
    return json.loads(data[10:header_end]), header_end


def is_pre_change(header: dict) -> bool:
    """Dấu "pre_change" (FORMAT.md mục 3): bản sao lưu có từ trước lần đổi master password gần nhất."""
    return header.get("pre_change") is True


PRE_CHANGE_WARNING = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
CẢNH BÁO: file này là một bản sao lưu có từ TRƯỚC lần đổi master password gần nhất (dấu "pre_change").
Nội dung của nó có thể đã được ghi bởi một người biết mật khẩu CŨ (ví dụ: người đã khiến bạn phải đổi
mật khẩu) — địa chỉ trang web, tên đăng nhập hay mật khẩu trong đó có thể đã bị sửa.
Nên dùng một bản sao lưu KHÔNG có dấu này (bản ghi sau lần đổi mật khẩu) nếu còn. Nếu buộc phải dùng
bản này, hãy kiểm tra kỹ địa chỉ trang web và mật khẩu của các tài khoản quan trọng trước khi dùng.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""


def decrypt_vault(data: bytes, password) -> dict:
    """Giải mã file kho. `password` là str (hoặc bytes UTF-8)."""
    header, header_end = read_header(data)
    aad = data[:header_end]
    body_nonce = data[header_end:header_end + 24]
    body_ct = data[header_end + 24:]

    kdf = header["kdf"]
    vault_key = None
    for candidate in password_candidates(password):
        master = hash_secret_raw(
            candidate, base64.b64decode(header["salt"]),
            time_cost=kdf["t"], memory_cost=kdf["m_kib"], parallelism=kdf["p"],
            hash_len=32, type=Type.ID, version=19,
        )
        kek = hkdf_sha256(master, b"pwv/v1/key-encryption-key")
        try:
            vault_key = xchacha_decrypt(
                base64.b64decode(header["wrapped_key"]),
                b"pwv/v1/wrap:" + header["vault_id"].encode(),
                base64.b64decode(header["key_nonce"]),
                kek,
            )
            break
        except CryptoError:
            continue
    if vault_key is None:
        raise CryptoError("sai master password (hoặc header của file đã bị sửa)")
    plain = xchacha_decrypt(body_ct, aad, body_nonce, vault_key)
    (n,) = struct.unpack_from("<I", plain, 0)
    return json.loads(plain[4:4 + n])


def utf8_output() -> None:
    """Windows: khi không in ra màn hình (bị chuyển hướng, chạy trong công cụ khác), Python dùng bảng
    mã cũ (cp1252/cp1258…) và DỪNG giữa chừng khi gặp chữ có dấu. Ép UTF-8 cho mọi thứ in ra."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main() -> None:
    utf8_output()
    ap = argparse.ArgumentParser(
        description="Giải mã file kho .pwv thành JSON (công cụ cứu hộ độc lập với app).")
    ap.add_argument("vault", help="đường dẫn file kho .pwv (hoặc một file trong thư mục sao lưu)")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi JSON ra FILE (UTF-8). Không ghi đè file đã có.")
    ap.add_argument("--password-stdin", action="store_true",
                    help="đọc master password từ dòng đầu của stdin (UTF-8) — chỉ dùng cho kiểm thử tự động")
    args = ap.parse_args()

    with open(args.vault, "rb") as f:
        data = f.read()
    try:
        pre_change = is_pre_change(read_header(data)[0])
    except Exception:  # file hỏng / không phải file pwv: decrypt_vault bên dưới báo lỗi rõ ràng
        pre_change = False
    if args.password_stdin:
        pw = sys.stdin.buffer.readline().decode("utf-8").rstrip("\r\n")
    else:
        pw = getpass.getpass("Master password: ")
    try:
        vault = decrypt_vault(data, pw)
    except Exception as e:  # nacl ném CryptoError khi sai mật khẩu / file hỏng
        print(f"Không mở được: {e}", file=sys.stderr)
        sys.exit(1)
    # Khoá của các lần đổi master password trước: không cần cho việc cứu dữ liệu, không in ra.
    vault.pop("old_keys", None)
    text = json.dumps(vault, ensure_ascii=False, indent=2)
    if pre_change:
        # In trước (để thấy ngay) và nhắc lại ở cuối (để không bị trôi mất sau phần JSON / dòng "Đã ghi").
        print(PRE_CHANGE_WARNING, file=sys.stderr)
    if args.output:
        try:
            # "x": báo lỗi nếu file đã có, để không vô tình ghi đè thứ gì khác.
            with open(args.output, "x", encoding="utf-8", newline="\n") as out:
                out.write(text + "\n")
        except FileExistsError:
            print(f"File {args.output} đã tồn tại — hãy chọn tên khác hoặc xoá nó trước.", file=sys.stderr)
            sys.exit(1)
        n = len(vault.get("entries", []))
        print(f"Đã ghi {n} mục ra {args.output}. File này chứa mật khẩu ở dạng rõ — xoá ngay sau khi dùng.",
              file=sys.stderr)
    else:
        # Không có -o: in ra màn hình (đã ép UTF-8 ở đầu hàm).
        print(text)
        sys.stdout.flush()
    if pre_change:
        print("CẢNH BÁO (nhắc lại): file này có từ TRƯỚC lần đổi master password gần nhất — xem cảnh báo ở trên.",
              file=sys.stderr)


if __name__ == "__main__":
    main()
