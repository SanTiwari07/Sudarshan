"""
Sudarshan JWT Auth Engine
==========================
Provides:
  POST /api/v1/auth/register - create new analyst account
  POST /api/v1/auth/login - returns JWT access_token

Roles:
  analyst - can upload APKs and view their own cases
  soc_lead - can view all cases + threat intel
  admin - full access + user management

Dependencies:
  pip install python-jose[cryptography] passlib[bcrypt]

JWT secret is read from JWT_SECRET_KEY env var (required in production).
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, APIRouter, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.db.database import (
    create_user, get_user_by_username, get_user_by_id, username_exists,
    update_user_role,
)
from app.rate_limit import limiter
from app.registration_policy import public_registration_allowed

logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────

# No default. A hardcoded fallback ships a publicly-known signing key in a public
# repo, letting anyone forge a token for any user/role. Refuse to start instead.
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY is not set. Refusing to start with an insecure default. "
        "Generate one with:  python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "12"))

# Self-registration always lands here. Elevation is an admin action.
DEFAULT_ROLE = "analyst"
ASSIGNABLE_ROLES = {"analyst", "soc_lead", "admin"}

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
_bearer = HTTPBearer(auto_error=False)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ─── Helpers ──────────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


def create_access_token(user_id: int, username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─── FastAPI Dependencies ─────────────────────────────────────────────────────

async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Extract & validate JWT from Authorization header."""
    if not creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = _decode_token(creds.credentials)
    user_id = int(payload.get("sub", 0))
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_role(*roles: str):
    """Dependency factory that enforces minimum role membership."""
    async def _check(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {list(roles)}. Your role: {user.get('role')}",
            )
        return user
    return _check


# Convenience aliases
require_analyst  = require_role("analyst", "soc_lead", "admin")
require_soc_lead = require_role("soc_lead", "admin")
require_admin    = require_role("admin")


# ─── Request / Response Models ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    password: str
    # NOTE: deliberately no `role` field. Self-registration always yields an
    # analyst. Elevating a user is an admin operation (see /auth/users/{id}/role),
    # never something the registering caller can ask for.


class LoginRequest(BaseModel):
    username: str
    password: str


class RoleChangeRequest(BaseModel):
    role: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    expires_in_hours: int = ACCESS_TOKEN_EXPIRE_HOURS


class UserInfo(BaseModel):
    id: int
    username: str
    role: str
    created_at: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/register", response_model=UserInfo, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")
async def register(request: Request, req: RegisterRequest):
    """
    Register a new account. Always created with the 'analyst' role - privilege is granted by an admin afterwards, never self-assigned.
    """
    if not public_registration_allowed():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled.",
        )

    if await username_exists(req.username):
        raise HTTPException(status_code=409, detail="Username already taken")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    hashed = hash_password(req.password)
    user_id = await create_user(req.username, hashed, DEFAULT_ROLE)
    logger.info(f"[Auth] Registered user: {req.username} role={DEFAULT_ROLE}")
    return UserInfo(
        id=user_id,
        username=req.username,
        role=DEFAULT_ROLE,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@router.patch("/users/{user_id}/role", response_model=UserInfo)
async def set_user_role(
    user_id: int,
    req: RoleChangeRequest,
    admin: dict = Depends(require_admin),
):
    """
    Grant or revoke a role. Admin only - this is the ONLY way to create a
    soc_lead or admin, replacing the self-assignment hole in /register.
    """
    if req.role not in ASSIGNABLE_ROLES:
        raise HTTPException(
            status_code=400, detail=f"Role must be one of: {sorted(ASSIGNABLE_ROLES)}"
        )

    target = await get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    await update_user_role(user_id, req.role)
    logger.info(
        f"[Auth] Role change: user_id={user_id} {target['role']} -> {req.role} "
        f"by admin={admin['username']}"
    )
    return UserInfo(
        id=user_id,
        username=target["username"],
        role=req.role,
        created_at=target.get("created_at", ""),
    )


@router.post("/login", response_model=TokenResponse)
@limiter.limit("30/minute")
async def login(request: Request, req: LoginRequest):
    """
    Authenticate and receive a JWT access token.
    """
    user = await get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["hashed_pw"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user["id"], user["username"], user["role"])
    logger.info(f"[Auth] Login: {req.username} role={user['role']}")
    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=user["role"],
    )


@router.get("/me", response_model=UserInfo)
async def me(user: dict = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return UserInfo(
        id=user["id"],
        username=user["username"],
        role=user["role"],
        created_at=user.get("created_at", ""),
    )
