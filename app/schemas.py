from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional


class UserRegister(BaseModel):
    email:    EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    email:    EmailStr
    password: str


class UserResponse(BaseModel):
    id:         int
    email:      str
    username:   str
    is_active:  bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"


class MessageResponse(BaseModel):
    message: str
