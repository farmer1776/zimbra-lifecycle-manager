"""Authentication: JWT tokens, password hashing, dependency injection."""

import jwt
import bcrypt
import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.config import settings

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 12


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(user_id: int, username: str, role: str, token_version: int = 0) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "ver": token_version,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token, settings.JWT_SECRET, algorithms=[ALGORITHM],
            options={"verify_sub": False},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


def _extract_token(request: Request) -> Optional[str]:
    """Extract JWT from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
):
    from app.models import User

    token = _extract_token(request)
    if not token:
        raise HTTPException(401, "Not authenticated")

    payload = decode_token(token)
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or inactive")
    if payload.get("ver", 0) != user.token_version:
        raise HTTPException(401, "Token revoked — please log in again")
    return user


async def require_admin(
    request: Request,
    db: Session = Depends(get_db),
):
    from app.models import User

    token = _extract_token(request)
    if not token:
        raise HTTPException(401, "Not authenticated")

    payload = decode_token(token)
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or inactive")
    if payload.get("ver", 0) != user.token_version:
        raise HTTPException(401, "Token revoked — please log in again")
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user


def seed_users(db: Session):
    """Create default users if they don't exist."""
    from app.models import User

    defaults = [
        ("admin", settings.SEED_ADMIN_PASSWORD, "Administrator", "admin"),
    ]
    for username, password, display, role in defaults:
        existing = db.query(User).filter(User.username == username).first()
        if not existing:
            db.add(User(
                username=username,
                password_hash=hash_password(password),
                display_name=display,
                role=role,
            ))
            logger.info("Seeded user: %s (%s)", username, role)
    db.commit()
