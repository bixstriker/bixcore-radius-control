"""Single-administrator local login for BiXCore RADIUS Control.

Only password verification data and a signing key are mounted into the container.
The account password is not transmitted to or stored by source control.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
import tempfile
from pathlib import Path
import secrets
import threading
import time

COOKIE_NAME = "__Host-bixcore_session"
SESSION_SECONDS = 7 * 24 * 60 * 60
AUTH_FILE_DEFAULT = "/run/secrets/bix_admin_credentials"
SIGNING_KEY_DEFAULT = "/run/secrets/bix_admin_signing_key"
ATTEMPTS = {}
ATTEMPTS_LOCK = threading.Lock()
ATTEMPT_WINDOW_SECONDS = 180
MAX_FAILURES = 8


def enabled() -> bool:
    return os.getenv("BIX_ADMIN_AUTH_ENABLED") == "1"


def _paths() -> tuple[Path, Path]:
    return (Path(os.getenv("BIX_ADMIN_CREDENTIALS_PATH", AUTH_FILE_DEFAULT)),
            Path(os.getenv("BIX_ADMIN_SIGNING_KEY_PATH", SIGNING_KEY_DEFAULT)))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def make_password_record(password: str, username: str = "admin") -> dict:
    """Used once during provisioning; never log the password or hash."""
    if len(password) < 16:
        raise ValueError("Password must contain at least 16 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return {"username": username, "algorithm": "scrypt-16384-8-1",
            "salt": _b64(salt), "password_hash": _b64(digest)}


def _load_config() -> tuple[dict, bytes]:
    credential_path, signing_path = _paths()
    obj = json.loads(credential_path.read_text(encoding="utf8"))
    secret = signing_path.read_bytes()
    if (not isinstance(obj, dict) or obj.get("algorithm") != "scrypt-16384-8-1"
            or obj.get("username") != "admin" or not isinstance(secret, bytes) or len(secret) < 32):
        raise ValueError("Administrator login not configured")
    if len(_decode(obj["salt"])) != 16 or len(_decode(obj["password_hash"])) != 32:
        raise ValueError("Invalid password verifier")
    return obj, secret


def configured() -> bool:
    try:
        _load_config()
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def password_matches(username: str, password: str) -> bool:
    try:
        obj, _ = _load_config()
        if len(password) > 256 or len(username) > 64:
            return False
        candidate = hashlib.scrypt(password.encode("utf8"), salt=_decode(obj["salt"]),
                                   n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(username, obj["username"]) and hmac.compare_digest(candidate, _decode(obj["password_hash"]))
    except (OSError, ValueError, KeyError, TypeError, MemoryError):
        return False


def create_cookie() -> str:
    obj, key = _load_config()
    now = int(time.time())
    payload = {"sub": obj["username"], "iat": now, "exp": now + SESSION_SECONDS,
               "nonce": secrets.token_hex(12),
               "cred": hashlib.sha256(obj["password_hash"].encode("ascii")).hexdigest()[:20]}
    encoded = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf8"))
    signature = _b64(hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest())
    return encoded + "." + signature


def valid_cookie(token: str | None) -> bool:
    if not token or len(token) > 2048:
        return False
    try:
        encoded, sig = token.split(".")
        obj, key = _load_config()
        expected = hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _decode(sig)):
            return False
        payload = json.loads(_decode(encoded))
        now = int(time.time())
        return (payload.get("sub") == obj["username"] and
                isinstance(payload.get("iat"), int) and isinstance(payload.get("exp"), int) and
                now >= payload["iat"] - 60 and now < payload["exp"] and
                payload["exp"] - payload["iat"] <= SESSION_SECONDS and
                payload.get("cred") == hashlib.sha256(obj["password_hash"].encode("ascii")).hexdigest()[:20])
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, AttributeError, binascii.Error):
        return False


def failed_limit(remote: str) -> bool:
    now = time.monotonic()
    with ATTEMPTS_LOCK:
        attempts = [t for t in ATTEMPTS.get(remote, []) if now - t < ATTEMPT_WINDOW_SECONDS]
        ATTEMPTS[remote] = attempts
        return len(attempts) >= MAX_FAILURES


def record_failed(remote: str):
    with ATTEMPTS_LOCK:
        ATTEMPTS.setdefault(remote, []).append(time.monotonic())


def clear_failures(remote: str):
    with ATTEMPTS_LOCK:
        ATTEMPTS.pop(remote, None)


CHANGE_LOCK = threading.Lock()


def change_password(current_password: str, new_password: str, confirm_password: str) -> None:
    """Replace only the password verifier, atomically; cookies invalidate immediately.

    In production BIX_ADMIN_CREDENTIALS_PATH points inside a tightly scoped,
    writable bind-mounted directory. The signing key stays read-only elsewhere.
    """
    if new_password != confirm_password:
        raise ValueError("CONFIRM_MISMATCH")
    if not 16 <= len(new_password) <= 256:
        raise ValueError("PASSWORD_LENGTH")
    if hmac.compare_digest(current_password, new_password):
        raise ValueError("PASSWORD_UNCHANGED")
    with CHANGE_LOCK:
        credential, _ = _paths()
        if (credential.is_symlink() or credential.parent.is_symlink()
                or not credential.is_file()
                or not stat.S_ISREG(credential.stat().st_mode)):
            raise OSError("Credential store unavailable")
        if not password_matches("admin", current_password):
            raise ValueError("CURRENT_INCORRECT")
        data = make_password_record(new_password)
        fd, temporary = tempfile.mkstemp(prefix=".admin-rotate-", dir=str(credential.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf8") as output:
                json.dump(data, output, separators=(",", ":"))
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o400)
            os.replace(temporary, credential)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        # Read on every request, so neither login nor cookie checks need a restart.
        # The directory fsync persists the atomic rename.
        if os.name == "posix":
            directory_fd = os.open(str(credential.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
