"""Security module for CloudGuardian.

Provides:
- Authentication & token verification for API endpoints.
- Telegram user verification and callback payload validation.
- Sensitive data masking and redaction for audit logs.
"""
from functools import wraps
import os
import re
import secrets
from typing import Any, Callable, Dict, Optional, Set, Tuple
from flask import Request, jsonify, request

# Global or environment-configured API key
_CONFIGURED_API_KEY: Optional[str] = os.getenv("CG_API_KEY")
# If not explicitly set in environment, generate a secure random session key for local runtime
_ACTIVE_API_KEY: str = _CONFIGURED_API_KEY or secrets.token_hex(24)

# Header and cookie constants
AUTH_HEADER = "X-API-Key"
BEARER_PREFIX = "Bearer "
SESSION_COOKIE_NAME = "cg_session"

# Redaction patterns
RE_ACCOUNT_ID = re.compile(r"\b\d{12}\b")
RE_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
RE_SECRET_KEY = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")
RE_TELEGRAM_TOKEN = re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{30,}\b")


def get_active_api_key() -> str:
    """Return the active API key used for API authentication."""
    return _ACTIVE_API_KEY


def set_active_api_key(new_key: str) -> None:
    """Set the active API key (primarily for test harnesses)."""
    global _ACTIVE_API_KEY
    _ACTIVE_API_KEY = new_key


def extract_token_from_request(req: Request) -> Optional[str]:
    """Extract auth token from X-API-Key header, Authorization header, or session cookie."""
    # 1. Direct header
    api_key = req.headers.get(AUTH_HEADER)
    if api_key:
        return api_key.strip()

    # 2. Bearer Authorization header
    auth_header = req.headers.get("Authorization")
    if auth_header and auth_header.startswith(BEARER_PREFIX):
        return auth_header[len(BEARER_PREFIX):].strip()

    # 3. Session cookie (browser dashboard authentication)
    cookie_token = req.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        return cookie_token.strip()

    return None


def is_authenticated(req: Request) -> bool:
    """Verify whether the incoming request contains a valid token."""
    token = extract_token_from_request(req)
    if not token:
        return False
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(token, _ACTIVE_API_KEY)


def require_auth(f: Callable[..., Any]) -> Callable[..., Any]:
    """Flask route decorator requiring valid authentication token for protected endpoints."""
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if not is_authenticated(request):
            return jsonify({
                "ok": False,
                "error": "Unauthorized: Valid API key or session required.",
                "hint": f"Provide '{AUTH_HEADER}' header or authenticate via dashboard."
            }), 401
        return f(*args, **kwargs)
    return decorated_function


# ---- Telegram Authorization & Validation ----

def get_authorized_telegram_users() -> Set[str]:
    """Return set of authorized Telegram user/chat IDs."""
    users = set()
    chat_id = os.getenv("TG_CHAT_ID")
    if chat_id:
        users.add(str(chat_id).strip())

    allowed = os.getenv("TG_ALLOWED_USERS", "")
    for u in allowed.split(","):
        u = u.strip()
        if u:
            users.add(u)
    return users


def is_telegram_user_authorized(user_id: Any) -> bool:
    """Check if a given Telegram user ID is authorized to approve/reject remediations."""
    if not user_id:
        return False
    allowed = get_authorized_telegram_users()
    if not allowed:
        # If no users configured, fail safe (reject)
        return False
    return str(user_id).strip() in allowed


def validate_telegram_callback_data(data: str, valid_keys: Set[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate Telegram inline keyboard callback payload.
    
    Expected format: '<action>:<key>' where action in {'ok', 'no'} and key in valid_keys.
    Returns: (is_valid, action, key)
    """
    if not data or ":" not in data:
        return False, None, None

    parts = data.split(":", 1)
    if len(parts) != 2:
        return False, None, None

    action, key = parts[0].strip(), parts[1].strip()
    if action not in {"ok", "no"}:
        return False, None, None

    if key not in valid_keys:
        return False, None, None

    return True, action, key


# ---- Sensitive Data Masking & Redaction ----

def redact_sensitive_data(text: str, mask_enabled: bool = True) -> str:
    """Redact AWS account numbers, access keys, telegram bot tokens and credentials from logs."""
    if not mask_enabled or not text:
        return text

    # Redact 12-digit AWS account IDs
    text = RE_ACCOUNT_ID.sub("************", text)
    # Redact AWS Access Key IDs (AKIA / ASIA)
    text = RE_ACCESS_KEY.sub("AKIA****************", text)
    # Redact Telegram bot tokens
    text = RE_TELEGRAM_TOKEN.sub("<telegram-token>", text)
    return text
