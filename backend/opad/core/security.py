from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Iterable

DEFAULT_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"*"},
    "defense": {
        "read:*",
        "service:read",
        "service:restart",
        "patch:read",
        "patch:plan",
        "patch:apply",
        "patch:rollback",
        "traffic:read",
        "traffic:write",
        "rule:read",
        "rule:plan",
        "rule:apply",
    },
    "attack": {
        "read:*",
        "target:read",
        "exploit:read",
        "exploit:write",
        "exploit:run",
        "flag:read",
        "flag:write",
        "submitter:read",
        "submitter:submit",
    },
    "traffic": {
        "read:*",
        "traffic:read",
        "traffic:write",
        "rule:read",
        "rule:plan",
        "patch:read",
    },
    "viewer": {"read:*", "service:read", "traffic:read", "flag:read", "exploit:read", "patch:read"},
}

@dataclass(frozen=True)
class Actor:
    username: str
    role: str
    auth_type: str = "anonymous"
    permissions: frozenset[str] = frozenset()

    def can(self, permission: str) -> bool:
        perms = set(self.permissions) or DEFAULT_ROLE_PERMISSIONS.get(self.role, set())
        if "*" in perms or permission in perms:
            return True
        namespace = permission.split(":", 1)[0]
        return f"{namespace}:*" in perms or "read:*" in perms and permission.endswith(":read")

ANONYMOUS = Actor("anonymous", "viewer", "anonymous", frozenset(DEFAULT_ROLE_PERMISSIONS["viewer"]))


def secret_key() -> bytes:
    key = os.getenv("OPAD_SECRET_KEY") or os.getenv("SECRET_KEY") or "opad-dev-secret-change-me"
    return key.encode("utf-8")


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    rounds = 240_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), rounds).hex()
    return f"pbkdf2_sha256${rounds}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        alg, rounds_s, salt, digest = stored.split("$", 3)
        if alg != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(rounds_s)).hex()
        return hmac.compare_digest(calc, digest)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_api_token(prefix: str = "opad") -> str:
    return prefix + "_" + secrets.token_urlsafe(32)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode())


def sign_session(payload: dict[str, Any], ttl_seconds: int = 12 * 3600) -> str:
    body = dict(payload)
    body.setdefault("iat", int(time.time()))
    body["exp"] = int(time.time()) + ttl_seconds
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    part = _b64(raw)
    sig = hmac.new(secret_key(), part.encode(), hashlib.sha256).digest()
    return part + "." + _b64(sig)


def verify_session(token: str) -> dict[str, Any] | None:
    try:
        part, sig_s = token.split(".", 1)
        expected = _b64(hmac.new(secret_key(), part.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig_s):
            return None
        payload = json.loads(_unb64(part))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def role_permissions(role: str, custom: Iterable[str] | None = None) -> frozenset[str]:
    perms = set(DEFAULT_ROLE_PERMISSIONS.get(role, set()))
    if custom:
        perms.update(custom)
    return frozenset(perms)


def redact_secret(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "..." + value[-keep:]


def ensure_allowed(actor: Actor, permission: str) -> None:
    if not actor.can(permission):
        raise PermissionError(f"{actor.role} cannot {permission}")
