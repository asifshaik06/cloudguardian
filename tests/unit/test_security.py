"""Unit tests for CloudGuardian security module:
- Authentication & tokens
- Telegram user verification and callback payload validation
- Sensitive data redaction
"""
import pytest
from flask import Flask, request

from backend.security import (
    AUTH_HEADER,
    SESSION_COOKIE_NAME,
    extract_token_from_request,
    get_active_api_key,
    is_authenticated,
    is_telegram_user_authorized,
    redact_sensitive_data,
    set_active_api_key,
    validate_telegram_callback_data,
)


@pytest.fixture
def app():
    app = Flask(__name__)
    return app


def test_auth_extraction_from_api_key_header(app):
    with app.test_request_context(headers={AUTH_HEADER: "test-secret-key-123"}):
        token = extract_token_from_request(request)
        assert token == "test-secret-key-123"


def test_auth_extraction_from_bearer_token(app):
    with app.test_request_context(headers={"Authorization": "Bearer bearer-token-xyz"}):
        token = extract_token_from_request(request)
        assert token == "bearer-token-xyz"


def test_auth_extraction_from_session_cookie(app):
    with app.test_request_context(headers={"Cookie": f"{SESSION_COOKIE_NAME}=cookie-token-abc"}):
        token = extract_token_from_request(request)
        assert token == "cookie-token-abc"


def test_auth_extraction_empty_when_no_token(app):
    with app.test_request_context():
        token = extract_token_from_request(request)
        assert token is None


def test_is_authenticated_with_valid_key(app):
    active_key = get_active_api_key()
    with app.test_request_context(headers={AUTH_HEADER: active_key}):
        assert is_authenticated(request) is True


def test_is_authenticated_with_invalid_key(app):
    with app.test_request_context(headers={AUTH_HEADER: "wrong-invalid-key"}):
        assert is_authenticated(request) is False


def test_is_authenticated_missing_token(app):
    with app.test_request_context():
        assert is_authenticated(request) is False


# ---- Telegram Authorization Tests ----

def test_telegram_authorized_primary_chat(monkeypatch):
    monkeypatch.setenv("TG_CHAT_ID", "987654321")
    monkeypatch.delenv("TG_ALLOWED_USERS", raising=False)
    assert is_telegram_user_authorized("987654321") is True
    assert is_telegram_user_authorized(987654321) is True
    assert is_telegram_user_authorized("111222333") is False


def test_telegram_authorized_multiple_users(monkeypatch):
    monkeypatch.setenv("TG_CHAT_ID", "100")
    monkeypatch.setenv("TG_ALLOWED_USERS", "200, 300, 400")
    assert is_telegram_user_authorized("100") is True
    assert is_telegram_user_authorized("200") is True
    assert is_telegram_user_authorized("300") is True
    assert is_telegram_user_authorized("500") is False


def test_telegram_unauthorized_when_no_users_configured(monkeypatch):
    monkeypatch.delenv("TG_CHAT_ID", raising=False)
    monkeypatch.delenv("TG_ALLOWED_USERS", raising=False)
    assert is_telegram_user_authorized("123") is False


# ---- Telegram Callback Validation Tests ----

def test_validate_telegram_callback_valid():
    valid_keys = {"s3", "ct", "sg", "key"}
    ok, action, key = validate_telegram_callback_data("ok:s3", valid_keys)
    assert ok is True
    assert action == "ok"
    assert key == "s3"

    ok, action, key = validate_telegram_callback_data("no:key", valid_keys)
    assert ok is True
    assert action == "no"
    assert key == "key"


def test_validate_telegram_callback_invalid_action():
    valid_keys = {"s3", "ct"}
    ok, action, key = validate_telegram_callback_data("maybe:s3", valid_keys)
    assert ok is False
    assert action is None
    assert key is None


def test_validate_telegram_callback_invalid_key():
    valid_keys = {"s3", "ct"}
    ok, action, key = validate_telegram_callback_data("ok:unknown_res", valid_keys)
    assert ok is False


def test_validate_telegram_callback_malformed():
    valid_keys = {"s3"}
    assert validate_telegram_callback_data("", valid_keys)[0] is False
    assert validate_telegram_callback_data("justtext", valid_keys)[0] is False
    assert validate_telegram_callback_data("a:b:c", valid_keys)[0] is False


# ---- Redaction Tests ----

def test_redact_masks_account_id():
    text = "Error in AWS account 123456789012 during scan."
    redacted = redact_sensitive_data(text)
    assert "123456789012" not in redacted
    assert "************" in redacted


def test_redact_masks_access_key():
    text = "Key AKIAIOSFODNN7EXAMPLE used from RU"
    redacted = redact_sensitive_data(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "AKIA****************" in redacted


def test_redact_masks_telegram_token():
    text = "Bot token 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ012345678 configured"
    redacted = redact_sensitive_data(text)
    assert "123456789:ABCdef" not in redacted
    assert "<telegram-token>" in redacted


def test_redact_disabled():
    text = "Account 123456789012 and key AKIAIOSFODNN7EXAMPLE"
    assert redact_sensitive_data(text, mask_enabled=False) == text
