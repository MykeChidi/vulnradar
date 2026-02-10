# vulnradar/utils/cache.py - Caching for redundant requests

import functools
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from cryptography.fernet import Fernet

from .error_handler import get_global_error_handler, handle_errors
from .logger import setup_logger
from .validator import Validator

error_handler = get_global_error_handler()


class CacheEntry:
    """Single cache entry."""

    def __init__(self, data: Any, ttl: int):
        """
        Initialize cache entry.

        Args:
            data: Cached data
            ttl: Time to live in seconds
        """
        self.data = data
        self.timestamp = time.time()
        self.ttl = ttl

    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if self.ttl == 0:
            return False  # Never expires
        return (time.time() - self.timestamp) > self.ttl


class ScanCache:
    """Cache for scan results."""

    def __init__(
        self,
        cache_dir: Path,
        default_ttl: int = 3600,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize cache.

        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default time to live in seconds
        """
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.default_ttl = default_ttl
        self.memory_cache: Dict[str, CacheEntry] = {}
        self.logger = setup_logger("ScanCache")
        self._lock = threading.Lock()

        # Initialize encryption
        if encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            # Generate key - cache won't persist across restarts
            key = Fernet.generate_key()
            self.cipher = Fernet(key)
            self.logger.warning("Using ephemeral encryption key")

        # Cache statistics
        self.hits = 0
        self.misses = 0

    def generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments."""
        key_data = str(args) + str(sorted(kwargs.items()))
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _serialize(self, data: Any) -> bytes:
        """Safely serialize data."""
        try:
            # Convert to JSON
            json_str = json.dumps(data, default=str, ensure_ascii=False)

            # Encrypt
            encrypted = self.cipher.encrypt(json_str.encode("utf-8"))

            # Add HMAC for integrity
            mac = hmac.new(self.cipher._signing_key, encrypted, hashlib.sha256).digest()

            return mac + encrypted
        except Exception as e:
            self.logger.error(f"Serialization error: {str(e)}")
            raise

    def _deserialize(self, data: bytes) -> Any:
        """Safely deserialize data."""
        try:
            # Split HMAC and encrypted data
            if len(data) < 32:
                raise ValueError("Invalid cache data")

            mac = data[:32]
            encrypted = data[32:]

            # Verify HMAC
            expected_mac = hmac.new(
                self.cipher._signing_key, encrypted, hashlib.sha256
            ).digest()

            if not hmac.compare_digest(mac, expected_mac):
                raise ValueError("Cache integrity check failed")

            # Decrypt
            decrypted = self.cipher.decrypt(encrypted)

            # Deserialize JSON
            return json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            self.logger.error(f"Deserialization error: {str(e)}")
            raise

    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        # Validate key
        try:
            Validator.validate_cache_key(key)
        except ValueError as e:
            self.logger.warning(f"Invalid cache key: {str(e)}")
            return None

        # Check memory cache first
        with self._lock:
            if key in self.memory_cache:
                entry = self.memory_cache[key]
                if not entry.is_expired():
                    self.hits += 1
                    self.logger.debug(f"Memory cache hit: {key}")
                    return entry.data
                else:
                    del self.memory_cache[key]

        # Check disk cache
        cache_file = self.cache_dir / f"{key}.cache"
        if cache_file.exists():
            try:
                # Verify file permissions
                stat = cache_file.stat()
                if stat.st_mode & 0o077:
                    self.logger.warning(
                        f"Insecure cache file permissions: {cache_file}"
                    )
                    cache_file.unlink()
                    return None

                with open(cache_file, "rb") as f:
                    data = f.read()

                # Deserialize securely
                cache_data = self._deserialize(data)

                # Reconstruct entry
                entry = CacheEntry(data=cache_data["data"], ttl=cache_data["ttl"])
                entry.timestamp = cache_data["timestamp"]

                if not entry.is_expired():
                    with self._lock:
                        self.memory_cache[key] = entry
                    self.hits += 1
                    return entry.data
                else:
                    cache_file.unlink()

            except Exception as e:
                self.logger.warning(f"Failed to load cache {key}: {str(e)}")
                if cache_file.exists():
                    cache_file.unlink()

        self.misses += 1
        return None

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to cache result",
        return_on_error=None,
    )
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Set cached value.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live (uses default if None)
        """
        # Validate key
        try:
            Validator.validate_cache_key(key)
        except ValueError as e:
            self.logger.warning(f"Invalid cache key: {str(e)}")
            return
        ttl = ttl if ttl is not None else self.default_ttl
        entry = CacheEntry(value, ttl)

        # Store in memory cache
        with self._lock:
            self.memory_cache[key] = entry

        # Prepare for disk
        cache_data = {"data": value, "timestamp": entry.timestamp, "ttl": ttl}

        try:
            serialized = self._serialize(cache_data)
        except Exception as e:
            self.logger.warning(f"Cannot serialize cache {key}: {str(e)}")
            return

        # Atomic file write
        cache_file = self.cache_dir / f"{key}.cache"
        temp_file = cache_file.with_suffix(".tmp")

        try:
            # Write with secure permissions
            with open(
                temp_file, "wb", opener=lambda path, flags: os.open(path, flags, 0o600)
            ) as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename
            temp_file.replace(cache_file)
        except Exception as e:
            self.logger.warning(f"Failed to save cache {key}: {str(e)}")
            if temp_file.exists():
                temp_file.unlink()

    def invalidate(self, key: str):
        """Invalidate a cache entry."""
        with self._lock:
            if key in self.memory_cache:
                del self.memory_cache[key]

        cache_file = self.cache_dir / f"{key}.cache"
        if cache_file.exists():
            cache_file.unlink()

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to clear cache",
        return_on_error=None,
    )
    def clear_all(self):
        """Clear all cache entries."""
        with self._lock:
            self.memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                cache_file.unlink()
            except Exception as e:
                self.logger.warning(f"Failed to delete {cache_file}: {e}")

        self.logger.info("Cache cleared")

    def get_stats(self) -> Dict:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.2f}%",
            "memory_entries": len(self.memory_cache),
            "disk_entries": len(list(self.cache_dir.glob("*.cache"))),
        }


def cached(ttl: int = 3600, key_func: Optional[Callable] = None):
    """
    Decorator for caching async function results.

    Args:
        ttl: Time to live in seconds
        key_func: Optional function to generate cache key
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Check if caching is disabled
            if getattr(self, "_cache", None) is None:
                # No cache, just execute function
                return await func(self, *args, **kwargs)

            # Get cache instance from self
            if not hasattr(self, "_cache"):
                # Initialize cache if not present
                cache_dir = Path("cache") / self.__class__.__name__
                self._cache = ScanCache(cache_dir, default_ttl=ttl)

            # Generate cache key
            if key_func:
                cache_key = key_func(self, *args, **kwargs)
            else:
                cache_key = self._cache.generate_key(func.__name__, *args, **kwargs)

            # Check cache
            cached_result = self._cache.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Execute function
            result = await func(self, *args, **kwargs)

            # Cache result
            self._cache.set(cache_key, result, ttl)

            return result

        return wrapper

    return decorator
