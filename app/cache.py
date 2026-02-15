"""Redis caching layer for fast account lookups."""
from __future__ import annotations

import json
import logging
import redis
from app.config import settings

logger = logging.getLogger(__name__)

_redis = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    decode_responses=True,
)

CACHE_TTL = 300  # 5 minutes
DOMAIN_STATS_KEY = "zimbra:domain_stats"
ACCOUNT_PREFIX = "zimbra:acct:"
SYNC_STATUS_KEY = "zimbra:sync_status"


def ping() -> bool:
    try:
        return _redis.ping()
    except Exception:
        return False


def cache_account(email: str, data: dict, ttl: int = CACHE_TTL):
    try:
        _redis.setex(f"{ACCOUNT_PREFIX}{email}", ttl, json.dumps(data, default=str))
    except Exception as e:
        logger.warning("Redis cache_account error: %s", e)


def get_cached_account(email: str) -> dict | None:
    try:
        raw = _redis.get(f"{ACCOUNT_PREFIX}{email}")
        return json.loads(raw) if raw else None
    except Exception:
        return None


def cache_domain_stats(stats: dict, ttl: int = CACHE_TTL):
    try:
        _redis.setex(DOMAIN_STATS_KEY, ttl, json.dumps(stats, default=str))
    except Exception as e:
        logger.warning("Redis cache_domain_stats error: %s", e)


def get_domain_stats() -> dict | None:
    try:
        raw = _redis.get(DOMAIN_STATS_KEY)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def set_sync_status(status: dict):
    try:
        _redis.set(SYNC_STATUS_KEY, json.dumps(status, default=str))
    except Exception as e:
        logger.warning("Redis set_sync_status error: %s", e)


def get_sync_status() -> dict | None:
    try:
        raw = _redis.get(SYNC_STATUS_KEY)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def invalidate_all():
    try:
        keys = _redis.keys("zimbra:*")
        if keys:
            _redis.delete(*keys)
    except Exception as e:
        logger.warning("Redis invalidate_all error: %s", e)


RATE_LIMIT_PREFIX = "ratelimit:"


def check_rate_limit(key: str, max_attempts: int = 5, window: int = 300) -> bool:
    """Return True if the key has exceeded max_attempts within window seconds."""
    try:
        rkey = f"{RATE_LIMIT_PREFIX}{key}"
        count = _redis.incr(rkey)
        if count == 1:
            _redis.expire(rkey, window)
        return count > max_attempts
    except Exception:
        return False


def clear_rate_limit(key: str):
    try:
        _redis.delete(f"{RATE_LIMIT_PREFIX}{key}")
    except Exception:
        pass
