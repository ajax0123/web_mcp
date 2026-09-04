"""
Layer 1: Intelligent Rate Limiting & Sliding-Window Throttling
===============================================================
Adaptive multi-tier rate limiting with sliding windows, dynamic penalty box,
and distributed token bucket synchronization.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from cyberguard_api.security.auth_defense.core.interfaces import (
    AuthRoute,
    MitigationAction,
    RateLimitState,
    RateLimiter,
)


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting tier."""
    # Sliding window
    window_seconds: int = 60
    max_requests: int = 100
    max_failed: int = 5

    # Penalty box (greylisting)
    penalty_threshold_failed: int = 10  # Failed attempts before penalty
    penalty_threshold_rate: float = 0.5  # Failure rate threshold

    # Penalty levels
    # Level 0: Normal
    # Level 1: Tarpit (artificial delay)
    # Level 2: Challenge required
    # Level 3: Block
    tarpit_delay_ms: int = 2000  # 2 second delay
    challenge_required_after: int = 3  # Penalty level for challenge
    block_after: int = 5  # Penalty level for block

    # Penalty decay
    penalty_decay_minutes: int = 15  # Reduce penalty level after this time
    max_penalty_duration_hours: int = 24

    # Distributed sync
    sync_enabled: bool = False
    redis_url: Optional[str] = None


class SlidingWindowRateLimiter(RateLimiter):
    """
    Sliding window rate limiter with adaptive penalty box.
    Supports per-IP, per-user, per-device, and per-fingerprint limits.
    """

    def __init__(
        self,
        config: Optional[RateLimitConfig] = None,
        route_configs: Optional[dict[AuthRoute, RateLimitConfig]] = None,
    ) -> None:
        self.config = config or RateLimitConfig()
        self.route_configs = route_configs or {
            AuthRoute.LOGIN: RateLimitConfig(
                window_seconds=60,
                max_requests=20,
                max_failed=5,
                penalty_threshold_failed=5,
                penalty_threshold_rate=0.3,
            ),
            AuthRoute.SIGNUP: RateLimitConfig(
                window_seconds=3600,  # 1 hour
                max_requests=5,
                max_failed=3,
                penalty_threshold_failed=3,
                penalty_threshold_rate=0.5,
            ),
            AuthRoute.PASSWORD_RESET: RateLimitConfig(
                window_seconds=3600,
                max_requests=3,
                max_failed=2,
                penalty_threshold_failed=2,
                penalty_threshold_rate=0.5,
            ),
            AuthRoute.TOKEN_REFRESH: RateLimitConfig(
                window_seconds=60,
                max_requests=30,
                max_failed=10,
                penalty_threshold_failed=10,
                penalty_threshold_rate=0.4,
            ),
        }

        # In-memory state (in production, use Redis)
        self._states: dict[str, RateLimitState] = {}
        self._lock = asyncio.Lock()

        # Penalty tracking
        self._penalty_history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def _make_key(self, identifier: str, identifier_type: str, route: AuthRoute) -> str:
        """Create composite key for state storage."""
        return f"{identifier_type}:{identifier}:{route.value}"

    def _get_config(self, route: AuthRoute) -> RateLimitConfig:
        """Get config for route."""
        return self.route_configs.get(route, self.config)

    async def check_limit(
        self,
        identifier: str,
        identifier_type: str,
        route: AuthRoute,
        cost: int = 1,
    ) -> tuple[bool, RateLimitState]:
        """Check if request is within rate limits."""
        key = self._make_key(identifier, identifier_type, route)
        config = self._get_config(route)

        async with self._lock:
            state = self._states.get(key)

            if not state:
                # Create new state
                state = RateLimitState(
                    identifier=identifier,
                    identifier_type=identifier_type,
                    window_start=datetime.now(timezone.utc),
                )
                self._states[key] = state

            now = datetime.now(timezone.utc)

            # Check if window has expired
            window_elapsed = (now - state.window_start).total_seconds()
            if window_elapsed > config.window_seconds:
                # Reset window
                state.window_start = now
                state.request_count = 0
                state.failed_count = 0
                state.success_count = 0

            # Check penalty
            if state.penalty_until and now < state.penalty_until:
                # In penalty box
                if state.penalty_level >= config.block_after:
                    return False, state
                elif state.penalty_level >= config.challenge_required_after:
                    # Challenge required - allow but flag
                    pass
                elif state.penalty_level >= 1:
                    # Tarpit - allow but will delay
                    pass

            # Check rate limits
            if state.request_count + cost > config.max_requests:
                return False, state

            # Check failed rate in window
            if state.request_count > 0:
                failed_rate = state.failed_count / state.request_count
                if failed_rate > config.penalty_threshold_rate and state.failed_count >= config.penalty_threshold_failed:
                    # Escalate penalty
                    await self._escalate_penalty(state, config, now)

            return True, state

    async def _escalate_penalty(
        self,
        state: RateLimitState,
        config: RateLimitConfig,
        now: datetime,
    ) -> None:
        """Escalate penalty level."""
        old_level = state.penalty_level

        if state.penalty_level == 0:
            state.penalty_level = 1  # Tarpit
        elif state.penalty_level < config.block_after:
            state.penalty_level += 1

        # Set penalty expiration
        penalty_duration = min(
            config.penalty_decay_minutes * (2 ** state.penalty_level),  # Exponential backoff
            config.max_penalty_duration_hours * 60,
        )
        state.penalty_until = now + timedelta(minutes=penalty_duration)

        # Record penalty event
        self._penalty_history[f"{state.identifier_type}:{state.identifier}"].append({
            "timestamp": now.isoformat(),
            "old_level": old_level,
            "new_level": state.penalty_level,
            "penalty_until": state.penalty_until.isoformat(),
            "reason": f"Failed rate: {state.failed_count}/{state.request_count}",
        })

    async def record_attempt(
        self,
        identifier: str,
        identifier_type: str,
        route: AuthRoute,
        success: bool,
    ) -> RateLimitState:
        """Record authentication attempt and update state."""
        key = self._make_key(identifier, identifier_type, route)
        config = self._get_config(route)

        async with self._lock:
            state = self._states.get(key)

            if not state:
                state = RateLimitState(
                    identifier=identifier,
                    identifier_type=identifier_type,
                    window_start=datetime.now(timezone.utc),
                )
                self._states[key] = state

            now = datetime.now(timezone.utc)
            state.request_count += 1
            state.last_request = now

            if success:
                state.success_count += 1
                # Reduce penalty on success
                if state.penalty_level > 0:
                    state.penalty_level = max(0, state.penalty_level - 1)
                    if state.penalty_level == 0:
                        state.penalty_until = None
            else:
                state.failed_count += 1

                # Check if we should escalate penalty
                if state.request_count > 0:
                    failed_rate = state.failed_count / state.request_count
                    if failed_rate > config.penalty_threshold_rate and state.failed_count >= config.penalty_threshold_failed:
                        await self._escalate_penalty(state, config, now)

            return state

    async def get_state(
        self,
        identifier: str,
        identifier_type: str,
        route: AuthRoute,
    ) -> Optional[RateLimitState]:
        """Get current rate limit state."""
        key = self._make_key(identifier, identifier_type, route)
        async with self._lock:
            return self._states.get(key)

    async def reset(self, identifier: str, identifier_type: str, route: AuthRoute) -> None:
        """Reset rate limit state."""
        key = self._make_key(identifier, identifier_type, route)
        async with self._lock:
            if key in self._states:
                del self._states[key]

    async def apply_tarpit(self, state: RateLimitState) -> None:
        """Apply tarpit delay based on penalty level."""
        if state.penalty_level >= 1:
            config = self._get_config(AuthRoute.LOGIN)  # Default config
            delay = config.tarpit_delay_ms * state.penalty_level
            await asyncio.sleep(delay / 1000.0)

    def get_penalty_history(self, identifier: str, identifier_type: str) -> list[dict[str, Any]]:
        """Get penalty history for identifier."""
        key = f"{identifier_type}:{identifier}"
        return self._penalty_history.get(key, [])


class DistributedTokenBucket:
    """
    Distributed token bucket for multi-node synchronization.
    Uses Redis for shared state across cluster nodes.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379") -> None:
        self.redis_url = redis_url
        self._local_cache: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_refill)
        self._redis = None
        self._connect_task: Optional[asyncio.Task] = None

    async def _ensure_connected(self) -> None:
        """Ensure Redis connection."""
        if self._redis is None and self._connect_task is None:
            self._connect_task = asyncio.create_task(self._connect())

        if self._connect_task:
            await self._connect_task

    async def _connect(self) -> None:
        """Connect to Redis."""
        try:
            import redis.asyncio as redis
            self._redis = redis.from_url(self.redis_url, decode_responses=True)
            await self._redis.ping()
        except Exception:
            self._redis = None

    async def consume(
        self,
        key: str,
        capacity: int,
        refill_rate: float,  # tokens per second
        tokens: int = 1,
    ) -> tuple[bool, float]:
        """
        Consume tokens from distributed bucket.
        Returns (allowed, remaining_tokens).
        """
        await self._ensure_connected()

        now = time.time()
        redis_key = f"ratelimit:{key}"

        if self._redis:
            # Use Redis Lua script for atomic operation
            lua_script = """
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local tokens = tonumber(ARGV[3])
            local now = tonumber(ARGV[4])

            local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
            local current_tokens = tonumber(bucket[1])
            local last_refill = tonumber(bucket[2])

            if current_tokens == nil then
                current_tokens = capacity
                last_refill = now
            end

            local elapsed = now - last_refill
            local new_tokens = math.min(capacity, current_tokens + elapsed * refill_rate)

            if new_tokens >= tokens then
                new_tokens = new_tokens - tokens
                redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
                redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) + 60)
                return {1, new_tokens}
            else
                redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
                redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) + 60)
                return {0, new_tokens}
            end
            """
            try:
                result = await self._redis.eval(lua_script, 1, redis_key, capacity, refill_rate, tokens, now)
                return bool(result[0]), float(result[1])
            except Exception:
                pass  # Fall back to local

        # Local fallback
        return self._local_consume(key, capacity, refill_rate, tokens, now)

    def _local_consume(
        self,
        key: str,
        capacity: int,
        refill_rate: float,
        tokens: int,
        now: float,
    ) -> tuple[bool, float]:
        """Local token bucket consumption."""
        if key not in self._local_cache:
            self._local_cache[key] = (float(capacity), now)

        current_tokens, last_refill = self._local_cache[key]
        elapsed = now - last_refill
        new_tokens = min(capacity, current_tokens + elapsed * refill_rate)

        if new_tokens >= tokens:
            self._local_cache[key] = (new_tokens - tokens, now)
            return True, new_tokens - tokens
        else:
            self._local_cache[key] = (new_tokens, now)
            return False, new_tokens


class MultiTierRateLimiter:
    """
    Multi-tier rate limiter combining:
    - Per-IP limits
    - Per-user limits
    - Per-device/fingerprint limits
    - Global limits
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self.ip_limiter = SlidingWindowRateLimiter()
        self.user_limiter = SlidingWindowRateLimiter()
        self.device_limiter = SlidingWindowRateLimiter()
        self.fingerprint_limiter = SlidingWindowRateLimiter()

        # Distributed sync if Redis available
        self.distributed = DistributedTokenBucket(redis_url) if redis_url else None

        # Route-specific configs for each tier
        self._configure_tiers()

    def _configure_tiers(self) -> None:
        """Configure rate limits for each tier."""
        # IP tier - strictest
        self.ip_limiter.route_configs = {
            AuthRoute.LOGIN: RateLimitConfig(window_seconds=60, max_requests=20, max_failed=5),
            AuthRoute.SIGNUP: RateLimitConfig(window_seconds=3600, max_requests=3, max_failed=2),
            AuthRoute.PASSWORD_RESET: RateLimitConfig(window_seconds=3600, max_requests=2, max_failed=1),
            AuthRoute.TOKEN_REFRESH: RateLimitConfig(window_seconds=60, max_requests=50, max_failed=15),
        }

        # User tier - moderate
        self.user_limiter.route_configs = {
            AuthRoute.LOGIN: RateLimitConfig(window_seconds=300, max_requests=30, max_failed=10),
            AuthRoute.SIGNUP: RateLimitConfig(window_seconds=86400, max_requests=5, max_failed=3),
            AuthRoute.PASSWORD_RESET: RateLimitConfig(window_seconds=3600, max_requests=3, max_failed=2),
            AuthRoute.TOKEN_REFRESH: RateLimitConfig(window_seconds=300, max_requests=100, max_failed=20),
        }

        # Device tier - moderate
        self.device_limiter.route_configs = {
            AuthRoute.LOGIN: RateLimitConfig(window_seconds=300, max_requests=25, max_failed=8),
            AuthRoute.SIGNUP: RateLimitConfig(window_seconds=86400, max_requests=3, max_failed=2),
            AuthRoute.PASSWORD_RESET: RateLimitConfig(window_seconds=3600, max_requests=2, max_failed=1),
            AuthRoute.TOKEN_REFRESH: RateLimitConfig(window_seconds=300, max_requests=80, max_failed=15),
        }

        # Fingerprint tier - strict for automation detection
        self.fingerprint_limiter.route_configs = {
            AuthRoute.LOGIN: RateLimitConfig(window_seconds=60, max_requests=10, max_failed=3),
            AuthRoute.SIGNUP: RateLimitConfig(window_seconds=3600, max_requests=2, max_failed=1),
            AuthRoute.PASSWORD_RESET: RateLimitConfig(window_seconds=3600, max_requests=1, max_failed=1),
            AuthRoute.TOKEN_REFRESH: RateLimitConfig(window_seconds=60, max_requests=20, max_failed=5),
        }

    async def check_all_tiers(
        self,
        ip: str,
        user_id: Optional[str],
        device_id: Optional[str],
        fingerprint_id: Optional[str],
        route: AuthRoute,
    ) -> tuple[bool, dict[str, RateLimitState], list[MitigationAction]]:
        """
        Check all rate limit tiers.
        Returns (allowed, states_by_tier, mitigation_actions).
        """
        mitigation_actions = []
        states = {}

        # Check IP tier
        allowed, state = await self.ip_limiter.check_limit(ip, "ip", route)
        states["ip"] = state
        if not allowed:
            mitigation_actions.append(MitigationAction.BLOCK_IP)
            return False, states, mitigation_actions
        if state.penalty_level >= 1:
            mitigation_actions.append(MitigationAction.TARPIT)
        if state.penalty_level >= 2:
            mitigation_actions.append(MitigationAction.CHALLENGE)

        # Check user tier
        if user_id:
            allowed, state = await self.user_limiter.check_limit(user_id, "user", route)
            states["user"] = state
            if not allowed:
                mitigation_actions.append(MitigationAction.BLOCK_USER)
                return False, states, mitigation_actions
            if state.penalty_level >= 2:
                mitigation_actions.append(MitigationAction.CHALLENGE)

        # Check device tier
        if device_id:
            allowed, state = await self.device_limiter.check_limit(device_id, "device", route)
            states["device"] = state
            if not allowed:
                mitigation_actions.append(MitigationAction.BLOCK_USER)
                return False, states, mitigation_actions

        # Check fingerprint tier
        if fingerprint_id:
            allowed, state = await self.fingerprint_limiter.check_limit(fingerprint_id, "fingerprint", route)
            states["fingerprint"] = state
            if not allowed:
                mitigation_actions.append(MitigationAction.BLOCK_IP)  # Block fingerprint
                return False, states, mitigation_actions
            if state.penalty_level >= 1:
                mitigation_actions.append(MitigationAction.TARPIT)

        return True, states, mitigation_actions

    async def record_attempt_all_tiers(
        self,
        ip: str,
        user_id: Optional[str],
        device_id: Optional[str],
        fingerprint_id: Optional[str],
        route: AuthRoute,
        success: bool,
    ) -> dict[str, RateLimitState]:
        """Record attempt in all applicable tiers."""
        states = {}

        await self.ip_limiter.record_attempt(ip, "ip", route, success)
        states["ip"] = await self.ip_limiter.get_state(ip, "ip", route)

        if user_id:
            await self.user_limiter.record_attempt(user_id, "user", route, success)
            states["user"] = await self.user_limiter.get_state(user_id, "user", route)

        if device_id:
            await self.device_limiter.record_attempt(device_id, "device", route, success)
            states["device"] = await self.device_limiter.get_state(device_id, "device", route)

        if fingerprint_id:
            await self.fingerprint_limiter.record_attempt(fingerprint_id, "fingerprint", route, success)
            states["fingerprint"] = await self.fingerprint_limiter.get_state(fingerprint_id, "fingerprint", route)

        return states


# Global multi-tier rate limiter
multi_tier_limiter = MultiTierRateLimiter()