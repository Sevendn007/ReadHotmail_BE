# auth_utils.py
import os
import time
import hmac
import hashlib
import base64
import json

# Nên set AUTH_SECRET trong Vercel → Project Settings → Environment Variables
AUTH_SECRET = os.environ.get("AUTH_SECRET", "CHANGE_ME_PLEASE")  # nhớ đổi!

TOKEN_TTL_SECONDS = 3600  # token sống trong 1 giờ


class AuthError(Exception):
    pass


def _b64url_encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_token(username: str) -> str:
    """
    Tạo token dạng: base64url(payload).base64url(signature)
    payload = {"sub": username, "exp": unix_timestamp}
    """
    now = int(time.time())
    payload = {
        "sub": username,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)

    secret = AUTH_SECRET.encode("utf-8")
    sig = hmac.new(secret, payload_b64, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)

    return (payload_b64 + b"." + sig_b64).decode("utf-8")


def verify_token(token: str) -> str:
    """
    Verify token. Trả về username nếu hợp lệ, ngược lại raise AuthError.
    """
    if not token:
        raise AuthError("missing token")

    try:
        payload_b64_str, sig_b64_str = token.split(".", 1)
    except ValueError:
        raise AuthError("invalid token format")

    payload_b64 = payload_b64_str.encode("utf-8")
    sig_b64 = sig_b64_str.encode("utf-8")

    secret = AUTH_SECRET.encode("utf-8")

    # recompute signature
    expected_sig = hmac.new(secret, payload_b64, hashlib.sha256).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)

    if not hmac.compare_digest(expected_sig_b64, sig_b64):
        raise AuthError("invalid signature")

    # decode payload
    try:
        payload_bytes = _b64url_decode(payload_b64_str)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise AuthError("invalid payload")

    exp = payload.get("exp")
    sub = payload.get("sub")
    if not isinstance(exp, int) or not isinstance(sub, str):
        raise AuthError("invalid payload fields")

    now = int(time.time())
    if now > exp:
        raise AuthError("token expired")

    return sub  # username
