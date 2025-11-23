from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app import crud
from app.auth import decode_access_token
from app.schemas import TokenPayload

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/sessions")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token_data: TokenPayload = decode_access_token(token)
    except Exception as e:
        raise credentials_exception
    if not token_data.sub:
        raise credentials_exception
    user = crud.get_user(db, token_data.sub)
    if not user or not user.is_active:
        raise credentials_exception
    return user
