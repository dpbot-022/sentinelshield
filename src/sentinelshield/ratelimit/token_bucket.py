import time
import asyncio
from typing import Dict, Tuple, Optional, Any
from fastapi import Request, HTTPException, status
from sentinelshield.config import settings


class TokenBucket:
    def __init__(self, capacity: int, fill_rate: float):
        """
        capacity: Maximum tokens in bucket (burst limit)
        fill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = float(capacity)
        self.last_update = time.time()
        self.lock = asyncio.Lock()

    async def consume(self, amount: int = 1) -> Tuple[bool, int, int]:
        """
        Consumes tokens.
        Returns:
            (allowed: bool, remaining_tokens: int, retry_after_seconds: int)
        """
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now

            # Refill tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)

            if self.tokens >= amount:
                self.tokens -= amount
                return True, int(self.tokens), 0
            else:
                # Calculate time until enough tokens are available
                needed = amount - self.tokens
                retry_after = int(needed / self.fill_rate) + 1
                return False, int(self.tokens), retry_after


class RateLimiter:
    """Enterprise In-Memory Token Bucket Manager per Tier & Client Identity"""

    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def _get_tier_specs(self, tier: str) -> Tuple[int, float, int]:
        cfg = settings.RATE_LIMIT_TIERS.get(tier, settings.RATE_LIMIT_TIERS["guest"])
        rate = cfg["rate"]
        burst = cfg.get("burst", rate)
        window = cfg.get("window_seconds", 60)
        fill_rate = rate / float(window)
        return burst, fill_rate, rate

    async def get_bucket(self, key: str, tier: str) -> TokenBucket:
        async with self._lock:
            if key not in self._buckets:
                burst, fill_rate, _ = self._get_tier_specs(tier)
                self._buckets[key] = TokenBucket(capacity=burst, fill_rate=fill_rate)
            return self._buckets[key]

    async def check_rate_limit(self, request: Request, user_tier: str = "guest", user_id: str = "anon"):
        client_ip = request.client.host if request.client else "127.0.0.1"
        limiter_key = f"{user_tier}:{user_id}:{client_ip}"

        burst, fill_rate, limit = self._get_tier_specs(user_tier)
        bucket = await self.get_bucket(limiter_key, user_tier)
        allowed, remaining, retry_after = await bucket.consume(1)

        # Store rate limit headers on request state for response middleware
        request.state.ratelimit_limit = str(limit)
        request.state.ratelimit_remaining = str(remaining)
        request.state.ratelimit_reset = str(retry_after)

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "RateLimitExceeded",
                    "tier": user_tier,
                    "limit_per_minute": limit,
                    "retry_after_seconds": retry_after,
                    "message": f"Token bucket capacity exhausted for tier '{user_tier}'. Please slow down or upgrade your subscription.",
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(retry_after),
                },
            )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "active_buckets": len(self._buckets),
            "configured_tiers": settings.RATE_LIMIT_TIERS,
        }


rate_limiter = RateLimiter()
