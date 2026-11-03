"""Local demo authentication for the /api/v1 backend.

A single opaque demo token is read from the SENTINELX_DEMO_TOKEN environment
variable (or a built-in fallback). This is for local demo use only - it is
NOT production authentication. The token is never logged or returned in
responses.

The backend defaults to local-only operation (127.0.0.1 bind).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

DEMO_TOKEN_ENV = "SENTINELX_DEMO_TOKEN"
_FALLBACK_TOKEN = "sentinelx-demo-local-only"


def _load_demo_token() -> str:
    token = os.environ.get(DEMO_TOKEN_ENV)
    if token:
        return token
    return _FALLBACK_TOKEN


DEMO_TOKEN = _load_demo_token()

# Secret used to sign SSE session cookies. Derived from DEMO_TOKEN so that
# only this server can issue valid SSE session cookies.
_SSE_SECRET = hashlib.sha256(DEMO_TOKEN.encode("utf-8")).digest()
_SSE_TTL_SECONDS = 3600


def _sign_sse_session(session_id: str) -> str:
    """Issue an unpredictable, server-validated SSE session cookie value.

    Format: base64url(session_id:expiry:hmac_hex). The HMAC is computed over
    "session_id:expiry" using _SSE_SECRET. Verification recomputes the HMAC
    and checks expiry, so a forged cookie value is rejected.
    """
    expiry = int(time.time()) + _SSE_TTL_SECONDS
    payload = f"{session_id}:{expiry}"
    mac = hmac.new(_SSE_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    signed = f"{payload}:{mac}"
    return base64.urlsafe_b64encode(signed.encode("utf-8")).decode("ascii")


def _verify_sse_session(token: str | None) -> bool:
    """Verify a server-issued SSE session cookie value.

    Returns True only if the token was issued by this server, is unexpired,
    and the HMAC is valid. Rejects forged or tampered values.
    """
    if not token:
        return False
    try:
        decoded = base64.urlsafe_b64decode(token.encode("ascii")).decode("ascii")
        parts = decoded.split(":")
        if len(parts) != 3:
            return False
        session_id, expiry_str, mac_hex = parts
        expiry = int(expiry_str)
        if time.time() > expiry:
            return False
        payload = f"{session_id}:{expiry}"
        expected = hmac.new(_SSE_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return secrets.compare_digest(mac_hex, expected)
    except Exception:
        return False


_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    """Validate the bearer token. Returns 'demo' on success.

    Raises HTTP 401 when the token is missing or wrong. Errors are generic
    to avoid leaking whether the token exists.
    """
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not secrets.compare_digest(creds.credentials, DEMO_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "demo"


def require_demo_auth(user: Annotated[str, Depends(get_current_user)]) -> str:
    """Explicit auth dependency for endpoints that need it."""
    return user
