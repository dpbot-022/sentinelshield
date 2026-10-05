import bcrypt
from typing import Optional, Dict, Any

# Secure password hashing utility using bcrypt directly
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# In-memory enterprise user database with pre-hashed credentials
USERS_DB: Dict[str, Dict[str, Any]] = {
    "admin": {
        "username": "admin",
        "email": "admin@sentinelshield.internal",
        "hashed_password": hash_password("SentinelAdmin2026!"),
        "role": "admin",
        "tier": "admin",
        "is_active": True,
    },
    "developer": {
        "username": "developer",
        "email": "dev@sentinelshield.internal",
        "hashed_password": hash_password("DevSecret2026!"),
        "role": "developer",
        "tier": "tier-2",
        "is_active": True,
    },
    "enterprise_app": {
        "username": "enterprise_app",
        "email": "app-gateway@enterprise.corp",
        "hashed_password": hash_password("ClientApp2026!"),
        "role": "service",
        "tier": "tier-1",
        "is_active": True,
    },
    "guest": {
        "username": "guest",
        "email": "guest@sentinelshield.internal",
        "hashed_password": hash_password("GuestDemo2026!"),
        "role": "guest",
        "tier": "guest",
        "is_active": True,
    },
}


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user
