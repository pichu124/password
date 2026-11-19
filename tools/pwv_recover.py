#!/usr/bin/env python3
"""Công cụ cứu hộ ĐỘC LẬP cho file kho .pwv (định dạng v1).

Không dùng chung dòng code nào với app Rust. Mục đích:
  1. Kiểm tra chéo rằng định dạng trong docs/FORMAT.md đúng với thực tế.
  2. Nếu một ngày app hỏng / không build được, bạn vẫn lấy lại được dữ liệu.

Cài đặt:  pip install pynacl argon2-cffi
Dùng:     python pwv_recover.py "G:\\My Drive\\Passwords\\vault.pwv"
          (in ra JSON đã giải mã — CẨN THẬN, đây là toàn bộ mật khẩu của bạn!)
"""
import base64
import getpass
import hashlib
import hmac
import json
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as xchacha_decrypt


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()  # salt rỗng = 32 byte 0
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def decrypt_vault(data: bytes, password: bytes) -> dict:
    if data[:4] != b"PWV1":
        raise ValueError("không phải file pwv")
    version, header_len = struct.unpack_from("<HI", data, 4)
    if version != 1:
        raise ValueError(f"phiên bản {version} chưa hỗ trợ")
    header_end = 10 + header_len
    header = json.loads(data[10:header_end])
    aad = data[:header_end]
    body_nonce = data[header_end:header_end + 24]
    body_ct = data[header_end + 24:]

    kdf = header["kdf"]
    master = hash_secret_raw(
        password, base64.b64decode(header["salt"]),
        time_cost=kdf["t"], memory_cost=kdf["m_kib"], parallelism=kdf["p"],
        hash_len=32, type=Type.ID, version=19,
    )
    kek = hkdf_sha256(master, b"pwv/v1/key-encryption-key")
    vault_key = xchacha_decrypt(
        base64.b64decode(header["wrapped_key"]),
        b"pwv/v1/wrap:" + header["vault_id"].encode(),
        base64.b64decode(header["key_nonce"]),
        kek,
    )
    plain = xchacha_decrypt(body_ct, aad, body_nonce, vault_key)
    (n,) = struct.unpack_from("<I", plain, 0)
    return json.loads(plain[4:4 + n])


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    pw = getpass.getpass("Master password: ").encode()
    try:
        vault = decrypt_vault(data, pw)
    except Exception as e:  # nacl ném CryptoError khi sai mật khẩu
        print(f"Không mở được: {e}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(vault, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
