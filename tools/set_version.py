#!/usr/bin/env python3
"""Đặt số phiên bản cho cả workspace Rust, app Tauri và frontend.

Dùng: python tools/set_version.py 0.1.2
Sau đó: commit + push, rồi vào Actions → Release → Run workflow.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+", sys.argv[1]):
        print(__doc__)
        sys.exit(2)
    v = sys.argv[1]

    for toml in [ROOT / "Cargo.toml", ROOT / "app/src-tauri/Cargo.toml"]:
        s = toml.read_text(encoding="utf-8")
        s2 = re.sub(r'(?m)^version = "\d+\.\d+\.\d+"', f'version = "{v}"', s, count=1)
        toml.write_text(s2, encoding="utf-8")

    for js in [ROOT / "app/src-tauri/tauri.conf.json", ROOT / "app/package.json"]:
        data = json.loads(js.read_text(encoding="utf-8"))
        data["version"] = v
        js.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Cập nhật lockfile cho khớp. CI build với --locked nên lockfile lệch là build đỏ: báo lỗi ngay ở đây.
    steps = [
        (["cargo", "update", "--workspace", "--offline"], ROOT),
        (["cargo", "update", "-p", "pwv-app", "--offline"], ROOT / "app/src-tauri"),
        (["npm", "install", "--package-lock-only", "--no-audit", "--no-fund"], ROOT / "app"),
    ]
    for cmd, cwd in steps:
        r = subprocess.run(cmd, cwd=cwd, check=False, shell=sys.platform == "win32")
        if r.returncode != 0:
            print(f"LỖI: lệnh {' '.join(cmd)} (trong {cwd}) thất bại — file khoá chưa được cập nhật.")
            sys.exit(1)
    print(f"Đã đặt phiên bản {v}.")


if __name__ == "__main__":
    main()
