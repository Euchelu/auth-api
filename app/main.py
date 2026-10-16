from fastapi import FastAPI, HTTPException, Depends, Request, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from .database import engine, get_db
from . import models, schemas, crud
from .auth import verify_password, create_access_token, create_refresh_token, decode_token
from .dependencies import get_current_user

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth API",
    description="JWT authentication API — register, login, refresh tokens and protected routes",
    version="1.0.0",
    contact={
        "name": "Euchelu",
        "url": "https://github.com/Euchelu",
    },
)

# Login is the one endpoint worth throttling — it's the only place a brute-force
# password guess is cheap for an attacker and expensive for us.
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/", tags=["health"])
def health_check():
    return {"status": "ok", "message": "Auth API is running"}


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.post("/auth/register", response_model=schemas.UserResponse,
          status_code=status.HTTP_201_CREATED, tags=["auth"])
def register(data: schemas.UserRegister, db: Session = Depends(get_db)):
    """Creates a new user account. Rejects duplicate email or username."""
    if crud.get_user_by_email(db, data.email):
        raise HTTPException(status_code=409, detail="Email already registered")
    if crud.get_user_by_username(db, data.username):
        raise HTTPException(status_code=409, detail="Username already taken")
    return crud.create_user(db, data)


@app.post("/auth/login", response_model=schemas.TokenResponse, tags=["auth"])
@limiter.limit("5/minute")
def login(request: Request, data: schemas.UserLogin, db: Session = Depends(get_db)):
    """Authenticates a user and returns access + refresh tokens. Limited to 5 attempts/minute per IP."""
    user = crud.get_user_by_email(db, data.email)
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    access_token  = create_access_token(user.id, user.email)
    refresh_token = create_refresh_token(user.id)
    crud.save_refresh_token(db, user, refresh_token)

    return schemas.TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@app.post("/auth/refresh", response_model=schemas.AccessTokenResponse, tags=["auth"])
def refresh_token(data: schemas.RefreshRequest, db: Session = Depends(get_db)):
    """
    Issues a new access token using a valid refresh token.
    The refresh token must match the one stored in the DB (single session).
    """
    credentials_exception = HTTPException(status_code=401, detail="Invalid refresh token")

    payload = decode_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise credentials_exception

    user = crud.get_user_by_id(db, int(payload["sub"]))
    if not user or user.refresh_token != data.refresh_token:
        raise credentials_exception

    access_token = create_access_token(user.id, user.email)
    return schemas.AccessTokenResponse(access_token=access_token)


@app.post("/auth/logout", response_model=schemas.MessageResponse, tags=["auth"])
def logout(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revokes the refresh token — the user must log in again to get a new one."""
    crud.revoke_refresh_token(db, current_user)
    return {"message": "Logged out successfully"}


# ── Protected routes ──────────────────────────────────────────────────────────

@app.get("/users/me", response_model=schemas.UserResponse, tags=["users"])
def get_me(current_user: models.User = Depends(get_current_user)):
    """Returns the authenticated user's profile. Requires valid access token."""
    return current_user
