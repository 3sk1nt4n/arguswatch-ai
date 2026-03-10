"""
ArgusWatch AI v16.4.7 - Authentication & Authorization
JWT-based auth with role-based access control (RBAC).

Roles:
  admin   - full access, manage users, settings, AI keys
  analyst - read/write findings, customers, run collections
  viewer  - read-only access to dashboards and reports

Usage in endpoints:
  @app.get("/api/settings/ai", dependencies=[Depends(require_role("admin"))])
  async def get_ai_settings(...): ...
"""
import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ── Config ──────────────────────────────────────────────
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

# Bootstrap admin credentials from env (first-run only)
BOOTSTRAP_ADMIN_USER = os.getenv("ADMIN_USER", "admin")
BOOTSTRAP_ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "arguswatch-admin-changeme")
BOOTSTRAP_API_KEY = os.getenv("API_KEY", "")  # Optional: static API key for automation

# Auth is DISABLED by default. Set AUTH_DISABLED=false to enforce JWT auth.
AUTH_DISABLED = os.getenv("AUTH_DISABLED", "true").lower() not in ("false", "0", "no")

# ── Password hashing ───────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


# ── Models ──────────────────────────────────────────────
class TokenData(BaseModel):
    username: str
    role: str = "viewer"
    exp: Optional[datetime] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    role: str
    username: str


class UserInfo(BaseModel):
    username: str
    role: str
    is_api_key: bool = False


# ── Database-backed user store (persistent across restarts) ──

async def _ensure_bootstrap_db():
    """Create bootstrap admin user in DB if no users exist."""
    from arguswatch.database import async_session
    from arguswatch.models import User
    from sqlalchemy import select, func
    try:
        async with async_session() as db:
            count = await db.scalar(select(func.count(User.id)))
            if count == 0:
                db.add(User(
                    username=BOOTSTRAP_ADMIN_USER,
                    hashed_password=pwd_context.hash(BOOTSTRAP_ADMIN_PASS),
                    role="admin",
                ))
                await db.commit()
    except Exception:
        pass  # Table may not exist yet during first migration


# Flag to ensure bootstrap runs once per process
_bootstrap_done = False

async def _ensure_bootstrap():
    global _bootstrap_done
    if not _bootstrap_done:
        await _ensure_bootstrap_db()
        _bootstrap_done = True


# ── Token creation ──────────────────────────────────────
def create_access_token(username: str, role: str) -> tuple[str, int]:
    """Create JWT token. Returns (token, expires_in_seconds)."""
    expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    expire_dt = datetime.utcnow() + expires
    payload = {
        "sub": username,
        "role": role,
        "exp": expire_dt,
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, int(expires.total_seconds())


# ── Token verification ──────────────────────────────────
def verify_token(token: str) -> UserInfo:
    """Decode and verify a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role", "viewer")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return UserInfo(username=username, role=role)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {e}")


# ── Dependency: get current user ────────────────────────
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> UserInfo:
    """
    Extract and verify the current user from:
    1. Bearer token in Authorization header
    2. Static API key in X-API-Key header
    3. AUTH_DISABLED mode (returns admin)
    """
    # Dev/test bypass
    if AUTH_DISABLED:
        return UserInfo(username="dev-admin", role="admin")

    # Check Bearer token
    if credentials and credentials.credentials:
        return verify_token(credentials.credentials)

    # Check X-API-Key header
    api_key = request.headers.get("X-API-Key", "")
    if api_key and BOOTSTRAP_API_KEY and api_key == BOOTSTRAP_API_KEY:
        return UserInfo(username="api-key-user", role="analyst", is_api_key=True)

    # Query param token removed -  JWTs in URLs appear in logs, browser history, and Referer headers.
    # Use Authorization: Bearer header or X-API-Key header instead.

    raise HTTPException(
        status_code=401,
        detail="Not authenticated. Provide Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── Dependency: require specific role ───────────────────
def require_role(*allowed_roles: str):
    """
    FastAPI dependency that enforces role-based access.

    Usage:
        @app.get("/api/admin-only", dependencies=[Depends(require_role("admin"))])
        @app.get("/api/write", dependencies=[Depends(require_role("admin", "analyst"))])
    """
    async def _check(user: UserInfo = Depends(get_current_user)):
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user.role}' not authorized. Required: {allowed_roles}",
            )
        return user
    return _check


# ── User management (database-backed) ────────────────────
async def authenticate_user(username: str, password: str) -> Optional[UserInfo]:
    """Verify username/password against DB. Returns UserInfo or None."""
    await _ensure_bootstrap()
    from arguswatch.database import async_session
    from arguswatch.models import User
    from sqlalchemy import select
    try:
        async with async_session() as db:
            r = await db.execute(select(User).where(User.username == username, User.active == True))
            user = r.scalar_one_or_none()
            if not user:
                return None
            if not pwd_context.verify(password, user.hashed_password):
                return None
            user.last_login = datetime.utcnow()
            await db.commit()
            return UserInfo(username=user.username, role=user.role)
    except Exception:
        return None


async def create_user(username: str, password: str, role: str = "analyst") -> bool:
    """Create a new user in DB. Returns False if username exists."""
    await _ensure_bootstrap()
    from arguswatch.database import async_session
    from arguswatch.models import User
    from sqlalchemy import select
    try:
        async with async_session() as db:
            existing = await db.execute(select(User).where(User.username == username))
            if existing.scalar_one_or_none():
                return False
            db.add(User(
                username=username,
                hashed_password=pwd_context.hash(password),
                role=role,
            ))
            await db.commit()
            return True
    except Exception:
        return False


async def list_users() -> list[dict]:
    """List all users from DB (without passwords)."""
    await _ensure_bootstrap()
    from arguswatch.database import async_session
    from arguswatch.models import User
    from sqlalchemy import select
    try:
        async with async_session() as db:
            r = await db.execute(select(User).where(User.active == True))
            return [{"username": u.username, "role": u.role} for u in r.scalars().all()]
    except Exception:
        return [{"username": BOOTSTRAP_ADMIN_USER, "role": "admin"}]


async def delete_user(username: str) -> bool:
    """Soft-delete a user. Cannot delete last admin."""
    await _ensure_bootstrap()
    from arguswatch.database import async_session
    from arguswatch.models import User
    from sqlalchemy import select, func
    try:
        async with async_session() as db:
            r = await db.execute(select(User).where(User.username == username))
            user = r.scalar_one_or_none()
            if not user:
                return False
            # Protect last admin
            if user.role == "admin":
                admin_count = await db.scalar(select(func.count(User.id)).where(User.role == "admin", User.active == True))
                if admin_count <= 1:
                    return False
            user.active = False
            await db.commit()
            return True
    except Exception:
        return False


# ── Dashboard auth (serves login page if not authenticated) ──
def get_dashboard_token_from_cookie(request: Request) -> Optional[str]:
    """Extract JWT from cookie for dashboard SSR auth."""
    return request.cookies.get("arguswatch_token")
