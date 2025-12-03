from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    """Payload to register a new user (email, username, password)."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    """Payload to login (email + password). Required by /sessions endpoint."""
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserUpdate(BaseModel):
    """Payload to update user profile (username and/or full_name)."""
    username: Optional[str] = Field(None, min_length=3, max_length=100)
    full_name: Optional[str] = None


class UserOut(BaseModel):
    """User object returned from API responses."""
    id: str
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    """JWT access token response."""
    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Decoded JWT payload representation used internally."""
    sub: Optional[str] = None
    exp: Optional[int] = None


# Explicit export list to make imports predictable.
__all__ = [
    "UserCreate",
    "UserLogin",
    "UserUpdate",
    "UserOut",
    "Token",
    "TokenPayload",
]
