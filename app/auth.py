"""
JWT authentication logic.

Concepts:
- Access token:  short-lived (30 min), used to authenticate requests
- Refresh token: long-lived (7 days), used only to get a new access token
- Both are signed JWTs — the server verifies the signature without hitting the DB
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt

SECRET_KEY       = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
ALGORITHM        = "HS256"
ACCESS_TOKEN_TTL  = timedelta(minutes=30)
REFRESH_TOKEN_TTL = timedelta(days=7)


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _create_token(data: dict, expires_delta: timedelta) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + expires_delta
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(user_id: int, email: str) -> str:
    return _create_token(
        {"sub": str(user_id), "email": email, "type": "access"},
        ACCESS_TOKEN_TTL,
    )


def create_refresh_token(user_id: int) -> str:
    return _create_token(
        {"sub": str(user_id), "type": "refresh"},
        REFRESH_TOKEN_TTL,
    )


def decode_token(token: str) -> Optional[dict]:
    """
    Decodes and validates a JWT.
    Returns the payload dict or None if invalid/expired.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
