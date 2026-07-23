import base64
import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, Request

from blockwart.config import Settings

ADMIN_COOKIE_NAME = "blockwart_admin_session"
ADMIN_SESSION_VERSION = "v1"


def admin_is_configured(request: Request) -> bool:
    return _settings(request).admin_token is not None


def admin_token_matches(settings: Settings, candidate: str) -> bool:
    if settings.admin_token is None:
        return False
    expected = settings.admin_token.get_secret_value()
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def create_admin_session(settings: Settings, *, now: int | None = None) -> str:
    if settings.admin_token is None:
        raise ValueError("admin token is not configured")
    issued_at = int(time.time()) if now is None else now
    expires_at = issued_at + settings.admin_session_ttl_seconds
    nonce = secrets.token_urlsafe(18)
    payload = f"{ADMIN_SESSION_VERSION}.{expires_at}.{nonce}"
    signature = _signature(settings, payload)
    return f"{payload}.{signature}"


def verify_admin_session(
    settings: Settings,
    session_value: str | None,
    *,
    now: int | None = None,
) -> bool:
    if settings.admin_token is None or not session_value or len(session_value) > 512:
        return False
    parts = session_value.split(".")
    if len(parts) != 4:
        return False
    version, expires_text, nonce, supplied_signature = parts
    if version != ADMIN_SESSION_VERSION or not expires_text.isascii() or not expires_text.isdigit():
        return False
    if len(nonce) < 16:
        return False
    current_time = int(time.time()) if now is None else now
    if int(expires_text) <= current_time:
        return False
    payload = f"{version}.{expires_text}.{nonce}"
    expected_signature = _signature(settings, payload)
    return hmac.compare_digest(supplied_signature, expected_signature)


def can_write(request: Request) -> bool:
    settings = _settings(request)
    return verify_admin_session(settings, request.cookies.get(ADMIN_COOKIE_NAME))


def require_admin_write(request: Request) -> None:
    if not can_write(request):
        raise HTTPException(status_code=403, detail="Admin write access required")


def settings_for_request(request: Request) -> Settings:
    return _settings(request)


def _settings(request: Request) -> Settings:
    settings = getattr(request.app.state, "settings", None)
    if not isinstance(settings, Settings):
        raise RuntimeError("Blockwart settings are not initialized")
    return settings


def _signature(settings: Settings, payload: str) -> str:
    if settings.admin_token is None:
        raise ValueError("admin token is not configured")
    digest = hmac.new(
        settings.admin_token.get_secret_value().encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
