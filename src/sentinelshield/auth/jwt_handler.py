from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sentinelshield.config import settings

security_bearer = HTTPBearer(auto_error=False)

TIER_HIERARCHY: Dict[str, int] = {
    "guest": 0,
    "tier-1": 1,
    "tier-2": 2,
    "admin": 3,
}


def create_access_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": int(expire.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "iss": "sentinelshield-gateway",
    })
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer="sentinelshield-gateway",
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please re-authenticate.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(err)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Dict[str, Any]:
    # Check X-API-Key header first
    api_key = request.headers.get("X-API-Key")
    if api_key:
        try:
            from sentinelshield.db import get_user_by_api_key
            user = get_user_by_api_key(api_key)
            if user:
                return {
                    "sub": user["username"],
                    "username": user["username"],
                    "role": user["role"],
                    "tier": user["tier"],
                    "auth_method": "api_key",
                }
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-API-Key provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Header. Bearer JWT token or X-API-Key required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_access_token(token)
    payload["auth_method"] = "jwt"
    return payload


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Dict[str, Any]:
    # Check X-API-Key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        try:
            from sentinelshield.db import get_user_by_api_key
            user = get_user_by_api_key(api_key)
            if user:
                return {
                    "sub": user["username"],
                    "username": user["username"],
                    "role": user["role"],
                    "tier": user["tier"],
                    "auth_method": "api_key",
                }
        except Exception:
            pass

    if credentials:
        try:
            payload = decode_access_token(credentials.credentials)
            payload["auth_method"] = "jwt"
            return payload
        except HTTPException:
            pass

    # Default unauthenticated guest context
    return {
        "sub": "anonymous-guest",
        "username": "guest",
        "role": "guest",
        "tier": "guest",
        "is_guest": True,
        "auth_method": "none",
    }


def require_tier(minimum_tier: str):
    min_level = TIER_HIERARCHY.get(minimum_tier, 0)

    async def tier_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_tier = current_user.get("tier", "guest")
        user_level = TIER_HIERARCHY.get(user_tier, 0)

        if user_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "InsufficientTierPrivilege",
                    "required_tier": minimum_tier,
                    "current_tier": user_tier,
                    "message": f"Operation requires tier '{minimum_tier}' or higher. Upgrade your API subscription.",
                },
            )
        return current_user

    return tier_checker
