from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .database import get_db
from .auth import decode_token
from . import crud, models

bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """
    FastAPI dependency that:
    1. Extracts the Bearer token from the Authorization header
    2. Decodes and validates the JWT
    3. Verifies it's an access token (not refresh)
    4. Returns the User from the DB

    Raises 401 if any step fails.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        raise credentials_exception

    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exception

    user = crud.get_user_by_id(db, int(user_id))
    if not user or not user.is_active:
        raise credentials_exception

    return user
