from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from fastapi import Depends, HTTPException, status
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
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Dict[str, Any]:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Header. Bearer token required for enterprise inference.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_access_token(token)
    return payload


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Dict[str, Any]:
    if not credentials:
        # Default unauthenticated guest context
        return {
            "sub": "anonymous-guest",
            "username": "guest",
            "role": "guest",
            "tier": "guest",
            "is_guest": True,
        }
    try:
        return decode_access_token(credentials.credentials)
    except HTTPException:
        # Fallback to guest if invalid token passed to optional endpoint
        return {
            "sub": "anonymous-guest",
            "username": "guest",
            "role": "guest",
            "tier": "guest",
            "is_guest": True,
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
