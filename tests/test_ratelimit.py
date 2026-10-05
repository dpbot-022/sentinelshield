import pytest
import asyncio
from sentinelshield.ratelimit.token_bucket import TokenBucket, RateLimiter
from fastapi import Request


@pytest.mark.asyncio
async def test_token_bucket_burst_and_drain():
    # Capacity: 3 tokens, fill_rate: 1 token/sec
    bucket = TokenBucket(capacity=3, fill_rate=1.0)

    # 1st consume: success
    ok, rem, _ = await bucket.consume(1)
    assert ok is True
    assert rem == 2

    # 2nd consume: success
    ok, rem, _ = await bucket.consume(1)
    assert ok is True
    assert rem == 1

    # 3rd consume: success
    ok, rem, _ = await bucket.consume(1)
    assert ok is True
    assert rem == 0

    # 4th consume: bucket empty -> rejected!
    ok, rem, retry_after = await bucket.consume(1)
    assert ok is False
    assert retry_after >= 1


@pytest.mark.asyncio
async def test_token_bucket_refill():
    bucket = TokenBucket(capacity=2, fill_rate=10.0)  # 10 tokens/sec
    await bucket.consume(2)
    # Tokens depleted
    ok, _, _ = await bucket.consume(1)
    assert ok is False

    # Wait for refill
    await asyncio.sleep(0.15)
    ok, rem, _ = await bucket.consume(1)
    assert ok is True
