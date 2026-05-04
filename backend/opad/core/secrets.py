from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Any

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:  # pragma: no cover
    Fernet = None
    InvalidToken = Exception


def _key_material() -> bytes:
    raw = os.getenv("OPAD_SECRET_KEY") or os.getenv("SECRET_KEY") or "opad-dev-secret-change-me"
    digest = hashlib.sha256(raw.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(value: str) -> str:
    if Fernet is None:
        # The fallback is intentionally marked; production deployments should install cryptography.
        return "plain:" + base64.urlsafe_b64encode(value.encode()).decode()
    return "fernet:" + Fernet(_key_material()).encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    if value.startswith("env:"):
        return os.getenv(value[4:], "")
    if value.startswith("plain:"):
        return base64.urlsafe_b64decode(value[6:].encode()).decode()
    if value.startswith("fernet:") and Fernet is not None:
        return Fernet(_key_material()).decrypt(value[7:].encode()).decode()
    return value


def redact(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if value.startswith("env:"):
        return value
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "..." + value[-keep:]
