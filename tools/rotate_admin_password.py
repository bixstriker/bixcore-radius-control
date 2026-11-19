#!/usr/bin/env python3
"""Change the single BiXCore admin password locally on NAS, without echoing it.

Run from the application checkout with suitable rights. The old account is
invalidated immediately because session cookies bind to the password hash.
"""
from __future__ import annotations
import getpass
import os
from pathlib import Path
import json
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.auth import make_password_record

ROOT = Path("/srv/bixcore-radius-control")
TARGET = ROOT / "private" / "admin_account" / "credentials.json"


def main():
    if not TARGET.is_file():
        raise RuntimeError("Missing private/admin_account/credentials.json: initialize the service first")
    password = getpass.getpass("Новый пароль администратора (16+ символов): ")
    verify = getpass.getpass("Повторите пароль: ")
    if password != verify:
        raise ValueError("Пароли не совпадают")
    record = make_password_record(password)
    old = TARGET.stat()
    fd, temp = tempfile.mkstemp(prefix=".admin-auth-", dir=str(TARGET.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(record, f, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chown(temp, old.st_uid, old.st_gid)
        os.chmod(temp, 0o400)
        os.replace(temp, TARGET)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print("Пароль администратора обновлён. Все ранее выданные cookie стали недействительными.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Не удалось обновить пароль: " + str(e), file=sys.stderr)
        raise SystemExit(1)
