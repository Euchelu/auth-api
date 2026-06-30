from sqlalchemy.orm import Session
from . import models, schemas
from .auth import hash_password


def get_user_by_email(db: Session, email: str) -> models.User | None:
    return db.query(models.User).filter(models.User.email == email).first()


def get_user_by_id(db: Session, user_id: int) -> models.User | None:
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_username(db: Session, username: str) -> models.User | None:
    return db.query(models.User).filter(models.User.username == username).first()


def create_user(db: Session, data: schemas.UserRegister) -> models.User:
    user = models.User(
        email=data.email,
        username=data.username,
        hashed_password=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def save_refresh_token(db: Session, user: models.User, token: str) -> None:
    """Stores the latest refresh token for the user (single active session)."""
    user.refresh_token = token
    db.commit()


def revoke_refresh_token(db: Session, user: models.User) -> None:
    """Invalidates the current refresh token (logout)."""
    user.refresh_token = None
    db.commit()
