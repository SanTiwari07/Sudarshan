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
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, HTTPException, APIRouter, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.db.database import (
    create_user, get_user_by_username, get_user_by_id, username_exists,
    update_user_role, set_user_active, touch_last_login,
)
from app.db.security import (
    count_recent_failures, create_session, is_session_active,
    list_active_sessions, record_login_attempt, revoke_all_sessions_for_user,
    revoke_session, touch_session,
)
from app.rate_limit import limiter
from app.registration_policy import public_registration_allowed
from app.services import audit_service
from app.services.audit_service import Action

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

# Verified against when the username does not exist, so that a missing account
# and a wrong password cost roughly the same wall-clock time. Without it, the
# "no such user" path returns immediately and response latency alone tells an
# attacker which usernames are real.
_DUMMY_HASH = _pwd_ctx.hash("sudarshan-timing-equaliser")

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ─── Helpers ──────────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


def create_access_token(
    user_id: int,
    username: str,
    role: str,
    *,
    jti: Optional[str] = None,
) -> str:
    """
    Mint a signed token. Pure - it does NOT create the session row.

    Use `issue_session_token()` for anything a real client will present;
    a token minted here without a matching session is rejected by
    `get_current_user`, which is the point of the session table.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": expire,
        # Identifies the session row. The token itself is never stored; this
        # claim is the only link between a bearer token and its revocation
        # state, so a database leak cannot yield a usable credential.
        "jti": jti or secrets.token_urlsafe(24),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def issue_session_token(
    user: dict,
    request: Optional[Request] = None,
) -> str:
    """Mint a token and register its session, so it can later be revoked."""
    jti = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    expire = now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)

    await create_session(
        jti=jti,
        user_id=user["id"],
        issued_at=now,
        expires_at=expire,
        ip=audit_service.client_ip(request),
        user_agent=audit_service.user_agent(request),
    )
    return create_access_token(user["id"], user["username"], user["role"], jti=jti)


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
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """
    Validate the bearer token and return the user.

    Six checks, in cost order - signature and expiry are free, the rest hit the
    database:

      1. signature is ours          (_decode_token)
      2. token has not expired      (_decode_token, via `exp`)
      3. the token carries a jti    - a token without one predates sessions
      4. the session exists and is neither revoked nor expired
      5. the user still exists
      6. the account is active

    Steps 3-4 are what make logout real. Before them, deleting the token from
    localStorage left it valid for the rest of its 12-hour window.

    The returned dict is the user row plus `_jti`, so a route can revoke the
    session it was called with (logout) without re-parsing the header.
    """
    if not creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = _decode_token(creds.credentials)

    jti = payload.get("jti")
    if not jti:
        # Issued before server-side sessions existed. It cannot be revoked, so
        # it cannot be trusted; the holder simply logs in again.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token predates session tracking. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not await is_session_active(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked or has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = int(payload.get("sub", 0))
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # `is_active` arrives via migration 0002 with a default of 1, so a row that
    # predates the column reads as active - which is what it was.
    if not user.get("is_active", 1):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been disabled.",
        )

    await touch_session(jti)

    user = dict(user)
    user["_jti"] = jti

    # Published for middleware that runs after the route and needs to know who
    # the caller was - the export ledger, specifically. Without this, recording
    # an export would mean decoding the token a second time.
    try:
        request.state.user = user
    except Exception:  # noqa: BLE001
        pass

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


class ActiveChangeRequest(BaseModel):
    is_active: bool


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
    await audit_service.record(
        Action.USER_CREATED,
        actor_username=req.username,
        target_type="user",
        target_id=str(user_id),
        detail={"role": DEFAULT_ROLE, "via": "self_registration"},
        request=request,
    )
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
    request: Request,
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

    # A privilege grant is the single most security-relevant action in the
    # application and previously left no trace at all.
    await audit_service.record(
        Action.ROLE_CHANGED,
        actor=admin,
        target_type="user",
        target_id=str(user_id),
        detail={
            "target_username": target["username"],
            "from_role": target["role"],
            "to_role": req.role,
        },
        request=request,
    )

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


# ─── Durable login protection ────────────────────────────────────────────────
#
# The slowapi limiter above stays as the cheap first layer: it rejects a flood
# before any database work happens. It is per-process and in-memory though, so
# it resets on restart and is not shared across replicas. These thresholds add
# the durable layer.
#
# Both locks are TEMPORARY and self-healing. A permanent account lock triggered
# by failed passwords hands any anonymous caller a denial-of-service against a
# named analyst, which is a worse outcome than the guessing it prevents. The
# account threshold is deliberately well above a fat-fingered password and the
# window is short; the per-IP threshold is what actually blunts spraying, since
# an attacker enumerating many usernames trips it long before any one account
# locks.
LOCKOUT_WINDOW_MINUTES = int(os.getenv("AUTH_LOCKOUT_WINDOW_MINUTES", "15"))
ACCOUNT_LOCK_THRESHOLD = int(os.getenv("AUTH_ACCOUNT_LOCK_THRESHOLD", "10"))
IP_LOCK_THRESHOLD = int(os.getenv("AUTH_IP_LOCK_THRESHOLD", "25"))


async def _lockout_reason(username: str, ip: Optional[str]) -> Optional[str]:
    """Return a lockout category if this attempt should be refused untried."""
    if await count_recent_failures(
        username=username, window_minutes=LOCKOUT_WINDOW_MINUTES
    ) >= ACCOUNT_LOCK_THRESHOLD:
        return "account_locked"
    if ip and await count_recent_failures(
        ip=ip, window_minutes=LOCKOUT_WINDOW_MINUTES
    ) >= IP_LOCK_THRESHOLD:
        return "ip_locked"
    return None


@router.post("/login", response_model=TokenResponse)
@limiter.limit("30/minute")
async def login(request: Request, req: LoginRequest):
    """
    Authenticate and receive a JWT access token bound to a revocable session.
    """
    ip = audit_service.client_ip(request)

    async def _reject(reason: str, detail: str, code: int = status.HTTP_401_UNAUTHORIZED):
        await record_login_attempt(req.username, success=False, ip=ip, failure_reason=reason)
        await audit_service.record(
            Action.LOGIN_FAILURE,
            actor_username=req.username,
            target_type="user",
            target_id=req.username,
            detail={"reason": reason},
            ip=ip,
        )
        raise HTTPException(
            status_code=code,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

    locked = await _lockout_reason(req.username, ip)
    if locked:
        await audit_service.record(
            Action.ACCOUNT_LOCKED,
            actor_username=req.username,
            target_type="user",
            target_id=req.username,
            detail={"reason": locked, "window_minutes": LOCKOUT_WINDOW_MINUTES},
            ip=ip,
        )
        await _reject(
            locked,
            f"Too many failed sign-in attempts. Try again in "
            f"{LOCKOUT_WINDOW_MINUTES} minutes.",
            code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    user = await get_user_by_username(req.username)

    # One message and one code for every credential failure. Distinguishing
    # "no such user" from "wrong password" turns the endpoint into a username
    # oracle. verify_password still runs on a dummy hash when the user is
    # absent so the two paths take comparable time.
    if not user:
        verify_password(req.password, _DUMMY_HASH)
        await _reject("unknown_user", "Incorrect username or password")

    if not verify_password(req.password, user["hashed_pw"]):
        await _reject("bad_password", "Incorrect username or password")

    if not user.get("is_active", 1):
        await _reject(
            "account_disabled",
            "This account has been disabled.",
            code=status.HTTP_403_FORBIDDEN,
        )

    token = await issue_session_token(user, request)
    await touch_last_login(user["id"])
    await record_login_attempt(req.username, success=True, ip=ip)
    await audit_service.record(
        Action.LOGIN_SUCCESS,
        actor=user,
        target_type="user",
        target_id=str(user["id"]),
        detail={"role": user["role"]},
        ip=ip,
    )

    logger.info(f"[Auth] Login: {req.username} role={user['role']}")
    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=user["role"],
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(request: Request, user: dict = Depends(get_current_user)):
    """
    Revoke the session this request authenticated with.

    Previously logout existed only in the browser: AuthContext deleted the
    token from localStorage and the token stayed valid server-side for the rest
    of its window. This makes it real.
    """
    revoked = await revoke_session(user["_jti"], revoked_by=user["id"], reason="logout")
    await audit_service.record(
        Action.LOGOUT,
        actor=user,
        target_type="session",
        target_id=user["_jti"][:12],
        request=request,
    )
    return {"revoked": revoked, "detail": "Signed out."}


@router.post("/logout-all", status_code=status.HTTP_200_OK)
async def logout_all(request: Request, user: dict = Depends(get_current_user)):
    """Revoke every session for the caller, including this one."""
    count = await revoke_all_sessions_for_user(
        user["id"], revoked_by=user["id"], reason="logout_all"
    )
    await audit_service.record(
        Action.SESSION_REVOKED,
        actor=user,
        target_type="user",
        target_id=str(user["id"]),
        detail={"scope": "self_all", "sessions_revoked": count},
        request=request,
    )
    return {"revoked": count, "detail": f"Signed out of {count} session(s)."}


@router.get("/sessions")
async def my_sessions(user: dict = Depends(get_current_user)):
    """List the caller's active sessions, so they can spot one they don't recognise."""
    sessions = await list_active_sessions(user["id"])
    for s in sessions:
        s["current"] = s["jti"] == user["_jti"]
        # The jti is a live credential reference. Enough to identify a row in
        # the UI, not enough to act on someone else's.
        s["jti"] = s["jti"][:12]
    return {"sessions": sessions, "count": len(sessions)}


@router.post("/users/{user_id}/revoke-sessions")
async def admin_revoke_sessions(
    user_id: int,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """Admin: force-sign-out a user everywhere. Used when an account is compromised."""
    target = await get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    count = await revoke_all_sessions_for_user(
        user_id, revoked_by=admin["id"], reason="admin_revoked"
    )
    await audit_service.record(
        Action.SESSION_REVOKED,
        actor=admin,
        target_type="user",
        target_id=str(user_id),
        detail={"scope": "admin_all", "sessions_revoked": count,
                "target_username": target["username"]},
        request=request,
    )
    return {"revoked": count, "username": target["username"]}


@router.patch("/users/{user_id}/active", response_model=UserInfo)
async def set_user_active_state(
    user_id: int,
    req: ActiveChangeRequest,
    request: Request,
    admin: dict = Depends(require_admin),
):
    """
    Enable or disable an account.

    Disabling also revokes every live session - otherwise the account stays
    usable until its tokens expire, which is exactly the window an admin is
    trying to close.
    """
    target = await get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if user_id == admin["id"] and not req.is_active:
        raise HTTPException(
            status_code=400,
            detail="You cannot disable your own account.",
        )

    await set_user_active(user_id, req.is_active)

    revoked = 0
    if not req.is_active:
        revoked = await revoke_all_sessions_for_user(
            user_id, revoked_by=admin["id"], reason="account_disabled"
        )

    await audit_service.record(
        Action.USER_DISABLED if not req.is_active else Action.USER_ENABLED,
        actor=admin,
        target_type="user",
        target_id=str(user_id),
        detail={"target_username": target["username"], "sessions_revoked": revoked},
        request=request,
    )
    return UserInfo(
        id=user_id,
        username=target["username"],
        role=target["role"],
        created_at=target.get("created_at", ""),
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
