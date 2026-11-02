"""Local demo authentication for the /api/v1 backend.

A single opaque demo token is read from the SENTINELX_DEMO_TOKEN environment
variable (or a built-in fallback). This is for local demo use only - it is
NOT production authentication. The token is never logged or returned in
responses.

The backend defaults to local-only operation (127.0.0.1 bind).
"""

from __future__ import annotations

import os
import secrets
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
