"""
ArgusWatch AI v16.4.1 - Authentication & Authorization
JWT-based auth with role-based access control (RBAC).

Roles:
  admin    - full access, manage users, settings, AI keys
  analyst  - read/write findings, customers, run collections
  viewer   - read-only access to dashboards and reports

Usage in endpoints:
  @app.get("/api/settings/ai", dependencies=[Depends(require_role("admin"))])
  async def get_ai_settings(...): ...
"""
import os
import secrets
from datetime import datetime, timedelta
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


# ── In-memory user store (replace with DB table for production) ──
# Structure: {username: {"hashed_password": "...", "role": "admin|analyst|viewer"}}
_users: dict = {}


def _ensure_bootstrap():
    """Create bootstrap admin user if no users exist."""
    if not _users:
        _users[BOOTSTRAP_ADMIN_USER] = {
            "hashed_password": pwd_context.hash(BOOTSTRAP_ADMIN_PASS),
            "role": "admin",
        }


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

    # Check query param (for dashboard iframe/websocket compat)
    token_param = request.query_params.get("token", "")
    if token_param:
        return verify_token(token_param)

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


# ── User management ────────────────────────────────────
def authenticate_user(username: str, password: str) -> Optional[UserInfo]:
    """Verify username/password. Returns UserInfo or None."""
    _ensure_bootstrap()
    user = _users.get(username)
    if not user:
        return None
    if not pwd_context.verify(password, user["hashed_password"]):
        return None
    return UserInfo(username=username, role=user["role"])


def create_user(username: str, password: str, role: str = "analyst") -> bool:
    """Create a new user. Returns False if username exists."""
    _ensure_bootstrap()
    if username in _users:
        return False
    _users[username] = {
        "hashed_password": pwd_context.hash(password),
        "role": role,
    }
    return True


def list_users() -> list[dict]:
    """List all users (without passwords)."""
    _ensure_bootstrap()
    return [{"username": u, "role": d["role"]} for u, d in _users.items()]


def delete_user(username: str) -> bool:
    """Delete a user. Cannot delete last admin."""
    _ensure_bootstrap()
    if username not in _users:
        return False
    admins = [u for u, d in _users.items() if d["role"] == "admin"]
    if _users[username]["role"] == "admin" and len(admins) <= 1:
        return False  # protect last admin
    del _users[username]
    return True


# ── Dashboard auth (serves login page if not authenticated) ──
def get_dashboard_token_from_cookie(request: Request) -> Optional[str]:
    """Extract JWT from cookie for dashboard SSR auth."""
    return request.cookies.get("arguswatch_token")
