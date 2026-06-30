from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from .database import Base


class User(Base):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    email           = Column(String(255), unique=True, index=True, nullable=False)
    username        = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active       = Column(Boolean, default=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())

    # Almacena el refresh token actual — solo uno activo por usuario
    refresh_token   = Column(String(512), nullable=True)
