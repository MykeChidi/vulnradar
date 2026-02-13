# vulnradar/utils/rate_limit.py - Production-grade adaptive rate limiter

import asyncio
import time
from typing import Any, Dict, Optional

from .logger import setup_logger

logger = setup_logger("rate_limiter", log_to_file=False)

# Constants
DEFAULT_INITIAL_RATE = 5.0
DEFAULT_MIN_RATE = 1.0
DEFAULT_MAX_RATE = 20.0
DEFAULT_MAX_TOKENS = 20.0
SUCCESS_THRESHOLD = 10
INCREASE_MULTIPLIER = 1.2
RATE_LIMIT_DECREASE = 0.5
FAILURE_DECREASE = 0.8


class AdaptiveRateLimiter:
    """
    Improved adaptive rate limiter.
    """

    def __init__(
        self,
        initial_rate: float = DEFAULT_INITIAL_RATE,
        min_rate: float = DEFAULT_MIN_RATE,
        max_rate: float = DEFAULT_MAX_RATE,
        max_tokens: float = DEFAULT_MAX_TOKENS,
        per_endpoint: bool = False,
    ):
        """
        Initialize adaptive rate limiter.

        Args:
            initial_rate: Starting requests per second
            min_rate: Minimum allowed rate
            max_rate: Maximum allowed rate
            max_tokens: Maximum token capacity
            per_endpoint: If True, maintain separate limits per endpoint
        """
        if not (min_rate <= initial_rate <= max_rate):
            raise ValueError(
                f"Invalid rate configuration: min_rate={min_rate}, "
                f"initial_rate={initial_rate}, max_rate={max_rate}"
            )

        self.initial_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.max_tokens = max_tokens
        self.per_endpoint = per_endpoint

        # Use monotonic time
        self.current_rate = initial_rate
        self.tokens = float(max_tokens)
        self.last_update = time.monotonic()

        # Adaptive behavior tracking
        self.consecutive_successes = 0
        self.consecutive_failures = 0

        # Use asyncio.Condition for better concurrency
        self._lock = asyncio.Lock()
        self._condition = asyncio.Condition(self._lock)

        # Per-endpoint tracking
        if per_endpoint:
            self._endpoint_limiters: Dict[str, "AdaptiveRateLimiter"] = {}
            self._endpoint_lock = asyncio.Lock()

        # Statistics with overflow protection
        self._total_requests = 0
        self._total_wait_time = 0.0
        self._max_requests = 2**63 - 1  # Prevent overflow

    async def acquire(self, tokens: int = 1, endpoint: Optional[str] = None):
        """
        Acquire tokens before making a request with proper concurrency.

        Args:
            tokens: Number of tokens to acquire (default 1)
            endpoint: Optional endpoint identifier for per-endpoint limiting
        """
        # Validate token count
        if tokens <= 0:
            raise ValueError(f"Invalid token count: {tokens}")
        if tokens > self.max_tokens:
            raise ValueError(
                f"Requested tokens ({tokens}) exceeds maximum ({self.max_tokens})"
            )

        # Per-endpoint limiting
        if self.per_endpoint and endpoint:
            async with self._endpoint_lock:
                if endpoint not in self._endpoint_limiters:
                    self._endpoint_limiters[endpoint] = AdaptiveRateLimiter(
                        initial_rate=self.initial_rate,
                        min_rate=self.min_rate,
                        max_rate=self.max_rate,
                        max_tokens=self.max_tokens,
                        per_endpoint=False,  # Don't nest
                    )

            limiter = self._endpoint_limiters[endpoint]
            await limiter.acquire(tokens)
            return

        start_wait = time.monotonic()

        async with self._condition:
            while self.tokens < tokens:
                # Refill tokens based on time passed
                await self._refill_tokens()

                if self.tokens < tokens:
                    # Calculate wait time
                    wait_time = (tokens - self.tokens) / self.current_rate

                    # Use wait_for with timeout to prevent indefinite blocking
                    try:
                        await asyncio.wait_for(
                            self._condition.wait(), timeout=wait_time
                        )
                    except asyncio.TimeoutError:
                        # Timeout is expected, refill tokens
                        await self._refill_tokens()

            # Consume tokens
            self.tokens -= tokens

            # Update statistics with overflow protection
            if self._total_requests < self._max_requests:
                self._total_requests += 1
                self._total_wait_time += time.monotonic() - start_wait

    async def _refill_tokens(self):
        """
        Refill tokens based on elapsed time.

        Must be called with condition lock held.
        """
        # Use monotonic time
        now = time.monotonic()
        elapsed = now - self.last_update

        # Prevent negative elapsed time (shouldn't happen with monotonic)
        if elapsed < 0:
            logger.warning(
                f"Negative time elapsed: {elapsed}. "
                "This should not happen with monotonic time."
            )
            elapsed = 0

        # Refill tokens
        new_tokens = self.tokens + (elapsed * self.current_rate)
        self.tokens = min(new_tokens, self.max_tokens)
        self.last_update = now

    async def report_success(self):
        """Report a successful request to adjust rate."""
        async with self._lock:
            self.consecutive_successes += 1
            self.consecutive_failures = 0

            # Gradually increase rate after multiple successes
            if self.consecutive_successes >= SUCCESS_THRESHOLD:
                self.consecutive_successes = 0
                new_rate = min(self.max_rate, self.current_rate * INCREASE_MULTIPLIER)

                if new_rate != self.current_rate:
                    self.current_rate = new_rate
                    logger.debug(f"Rate limit increased to {new_rate:.2f} req/s")

        # Notify waiting tasks
        async with self._condition:
            self._condition.notify_all()

    async def report_failure(self, is_rate_limit: bool = False):
        """
        Report a failed request to adjust rate.

        Args:
            is_rate_limit: Whether the failure was due to rate limiting
        """
        async with self._lock:
            self.consecutive_failures += 1
            self.consecutive_successes = 0

            # Decrease rate on failures
            multiplier = RATE_LIMIT_DECREASE if is_rate_limit else FAILURE_DECREASE
            new_rate = max(self.min_rate, self.current_rate * multiplier)

            if new_rate != self.current_rate:
                self.current_rate = new_rate
                failure_type = "rate limit" if is_rate_limit else "failure"
                logger.warning(
                    f"Rate limit decreased to {new_rate:.2f} req/s "
                    f"due to {failure_type}"
                )

        # Notify waiting tasks
        async with self._condition:
            self._condition.notify_all()

    async def reset(self):
        """Reset rate limiter to initial state."""
        async with self._lock:
            self.current_rate = self.initial_rate
            self.tokens = float(self.max_tokens)
            self.last_update = time.monotonic()
            self.consecutive_successes = 0
            self.consecutive_failures = 0
            logger.info("Rate limiter reset to initial state")

        # Clear per-endpoint limiters
        if self.per_endpoint:
            async with self._endpoint_lock:
                self._endpoint_limiters.clear()

        async with self._condition:
            self._condition.notify_all()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get rate limiter statistics.

        Returns:
            Dictionary of statistics
        """
        avg_wait_time = (
            self._total_wait_time / self._total_requests
            if self._total_requests > 0
            else 0.0
        )

        stats = {
            "current_rate": self.current_rate,
            "min_rate": self.min_rate,
            "max_rate": self.max_rate,
            "available_tokens": self.tokens,
            "max_tokens": self.max_tokens,
            "total_requests": self._total_requests,
            "avg_wait_time_ms": avg_wait_time * 1000,
            "consecutive_successes": self.consecutive_successes,
            "consecutive_failures": self.consecutive_failures,
        }

        if self.per_endpoint:
            stats["endpoints"] = len(self._endpoint_limiters)

        return stats


class RateLimiter:
    """
    Global rate limiter for shared resource management.

    Used when you need to limit total rate across all endpoints,
    in addition to per-endpoint limiting.
    """

    def __init__(
        self,
        global_rate: float = DEFAULT_MAX_RATE,
        endpoint_rate: float = DEFAULT_INITIAL_RATE,
    ):
        """
        Initialize global rate limiter.

        Args:
            global_rate: Maximum total rate across all endpoints
            endpoint_rate: Default rate per endpoint
        """
        self.global_limiter = AdaptiveRateLimiter(
            initial_rate=global_rate,
            min_rate=global_rate * 0.1,
            max_rate=global_rate,
        )
        self.endpoint_limiter = AdaptiveRateLimiter(
            initial_rate=endpoint_rate,
            min_rate=endpoint_rate * 0.2,
            max_rate=endpoint_rate * 2,
            per_endpoint=True,
        )

    async def acquire(self, tokens: int = 1, endpoint: Optional[str] = None):
        """
        Acquire tokens from both global and endpoint limiters.

        Args:
            tokens: Number of tokens to acquire
            endpoint: Optional endpoint identifier
        """
        # Acquire from global limiter first
        await self.global_limiter.acquire(tokens)

        # Then acquire from endpoint limiter
        if endpoint:
            await self.endpoint_limiter.acquire(tokens, endpoint)

    async def report_success(self, endpoint: Optional[str] = None):
        """Report success to both limiters."""
        await self.global_limiter.report_success()
        if endpoint and self.endpoint_limiter.per_endpoint:
            # Report to specific endpoint
            async with self.endpoint_limiter._endpoint_lock:
                if endpoint in self.endpoint_limiter._endpoint_limiters:
                    await self.endpoint_limiter._endpoint_limiters[
                        endpoint
                    ].report_success()

    async def report_failure(
        self, is_rate_limit: bool = False, endpoint: Optional[str] = None
    ):
        """Report failure to both limiters."""
        await self.global_limiter.report_failure(is_rate_limit)
        if endpoint and self.endpoint_limiter.per_endpoint:
            async with self.endpoint_limiter._endpoint_lock:
                if endpoint in self.endpoint_limiter._endpoint_limiters:
                    await self.endpoint_limiter._endpoint_limiters[
                        endpoint
                    ].report_failure(is_rate_limit)
