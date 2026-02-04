# vulnradar/utils/rate_limit.py - Rate limiter for HTTP and concurrent operations

import asyncio
import time
from .logger import setup_logger

logger = setup_logger("rate_limiter", log_to_file=False)


class RateLimiter:
    """
    Adaptive rate limiter that adjusts based on server responses.
    Backs off when encountering rate limits or errors.
    """
    
    def __init__(self, initial_rate: float = 5, min_rate: float = 1, max_rate: float = 20):
        """
        Initialize adaptive rate limiter.
        
        Args:
            initial_rate: Starting requests per second
            min_rate: Minimum allowed rate
            max_rate: Maximum allowed rate
        """
        self.current_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.tokens: float = 10.0
        self.last_update = time.time()
        self.consecutive_successes = 0
        self.consecutive_failures = 0
        self.lock = asyncio.Lock()
        
    async def acquire(self, tokens: int = 1):
        """
        Acquire tokens before making a request.
        Blocks until tokens are available.
        
        Args:
            tokens: Number of tokens to acquire (default 1)
        """
        async with self.lock:
            while self.tokens < tokens:
                # Refill tokens based on time passed
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(self.tokens + elapsed * self.current_rate, self.max_rate)
                self.last_update = now
                
                if self.tokens < tokens:
                    # Calculate wait time
                    wait_time = (tokens - self.tokens) / self.current_rate
                    await asyncio.sleep(wait_time)
            
            # Consume tokens
            self.tokens -= tokens
            self.last_update = time.time()
        
    async def report_success(self):
        """Report a successful request."""
        async with self.lock:
            self.consecutive_successes += 1
            self.consecutive_failures = 0
            
            # Gradually increase rate after multiple successes
            if self.consecutive_successes >= 10:
                self.consecutive_successes = 0
                new_rate = min(self.max_rate, self.current_rate * 1.2)
                if new_rate != self.current_rate:
                    self.current_rate = new_rate
                    logger.debug(f"Rate limit increased to {new_rate:.2f} req/s")
                    
    async def report_failure(self, is_rate_limit: bool = False):
        """
        Report a failed request.
        
        Args:
            is_rate_limit: Whether the failure was due to rate limiting
        """
        async with self.lock:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            
            # Decrease rate on failures
            multiplier = 0.5 if is_rate_limit else 0.8
            new_rate = max(self.min_rate, self.current_rate * multiplier)
            
            if new_rate != self.current_rate:
                self.current_rate = new_rate
                logger.warning(f"Rate limit decreased to {new_rate:.2f} req/s")