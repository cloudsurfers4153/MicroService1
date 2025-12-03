from typing import Optional
from sqlalchemy.orm import Session
from app import models, schemas
from passlib.context import CryptContext
import logging
import secrets

logger = logging.getLogger(__name__)

# Primary crypt context uses bcrypt; fallback uses pbkdf2_sha256 (no 72-byte limit)
primary_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
fallback_ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored hash.
    Try the primary context first; on any exception or mismatch, fall back to pbkdf2_sha256.
    """
    try:
        if primary_ctx.verify(plain_password, hashed_password):
            return True
    except Exception as e:
        logger.warning("Primary password verification failed: %s. Falling back to pbkdf2.", e)

    try:
        if fallback_ctx.verify(plain_password, hashed_password):
            return True
    except Exception as e:
        logger.exception("Fallback password verification also failed: %s", e)

    return False


def get_password_hash(password: str) -> str:
    """
    Hash a password. Try bcrypt first; if it fails, fall back to pbkdf2_sha256.
    """
    try:
        return primary_ctx.hash(password)
    except Exception as e:
        logger.warning("Primary password hash (bcrypt) failed: %s. Using pbkdf2_sha256 fallback.", e)
        return fallback_ctx.hash(password)


def get_user_by_email(db: Session, email: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.email == email).first()


def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.username == username).first()


def get_user(db: Session, user_id: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.id == user_id).first()


def create_user(db: Session, user_in: schemas.UserCreate) -> models.User:
    """
    Create a new user with a user-supplied password (password is hashed).
    """
    hashed = get_password_hash(user_in.password)
    db_user = models.User(
        email=user_in.email,
        username=user_in.username,
        password_hash=hashed,
        full_name=user_in.full_name
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_user_oauth(db: Session, email: str, full_name: Optional[str] = None) -> models.User:
    """
    Create a user for OAuth login:
      - Generate a random password (never shown to the user) and hash it to satisfy non-null password constraints.
      - Build a username derived from the email's local part; append a numeric suffix on collisions.
    Returns the created models.User.
    """
    random_password = secrets.token_urlsafe(24)
    hashed = get_password_hash(random_password)

    base = email.split("@")[0].replace(".", "_")
    username = base
    suffix_attempt = 0

    # Ensure username uniqueness
    while get_user_by_username(db, username) is not None:
        suffix_attempt += 1
        username = f"{base[:20]}{suffix_attempt}"

    db_user = models.User(
        email=email,
        username=username,
        password_hash=hashed,
        full_name=full_name
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db: Session, email: str, password: str) -> Optional[models.User]:
    """
    Authenticate by email + password. Return user if credentials match and user is active.
    """
    user = get_user_by_email(db, email)
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def deactivate_user(db: Session, user_id: str) -> Optional[models.User]:
    """
    Soft-deactivate a user by setting is_active = False.
    """
    user = get_user(db, user_id)
    if not user:
        return None
    user.is_active = False
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_user_profile(db: Session, user: models.User, full_name: str = None, username: str = None) -> models.User:
    """
    Update the user's profile fields (username and/or full_name).
    """
    if full_name is not None:
        user.full_name = full_name
    if username is not None:
        user.username = username
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
