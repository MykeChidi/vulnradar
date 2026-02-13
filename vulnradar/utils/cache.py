# vulnradar/utils/cache.py - Secure caching system for redundant requests

import functools
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .error_handler import get_global_error_handler, handle_errors
from .logger import setup_logger
from .validator import Validator

error_handler = get_global_error_handler()

# Constants for security and configuration
CACHE_ENTRY_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
CACHE_MAX_MEMORY_ENTRIES = 1000  # LRU eviction threshold
PBKDF2_ITERATIONS = 100_000  # OWASP recommendation
MAX_DESERIALIZATION_DEPTH = 10
HMAC_KEY_SIZE = 32
ENCRYPTION_KEY_SIZE = 32


class CacheEntry:
    """Single cache entry with metadata."""

    def __init__(self, data: Any, ttl: Optional[int]):
        """
        Initialize cache entry.

        Args:
            data: Cached data
            ttl: Time to live in seconds (None for no expiry, 0 for immediate expiry)
        """
        self.data = data
        self.timestamp = time.monotonic()  # Use monotonic time
        self.ttl = ttl
        self.access_count = 0
        self.last_accessed = self.timestamp

    def is_expired(self) -> bool:
        """
        Check if entry is expired.
        """
        if self.ttl is None:
            return False  # Never expires
        if self.ttl == 0:
            return True  # Immediate expiry

        # Use monotonic time
        return (time.monotonic() - self.timestamp) > self.ttl

    def touch(self) -> None:
        """Update access metadata for LRU tracking."""
        self.access_count += 1
        self.last_accessed = time.monotonic()


class ScanCache:
    """
    Secure cache with security features.
    """

    def __init__(
        self,
        cache_dir: Path,
        default_ttl: Optional[int] = 3600,
        master_key: Optional[bytes] = None,
        max_memory_entries: int = CACHE_MAX_MEMORY_ENTRIES,
    ):
        """
        Initialize secure cache.

        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default time to live in seconds (None for no expiry)
            master_key: Master key for encryption (will derive encryption/HMAC keys)
            max_memory_entries: Maximum entries in memory cache before LRU eviction
        """
        self.cache_dir = cache_dir
        self.default_ttl = default_ttl
        self.max_memory_entries = max_memory_entries

        # LRU cache using OrderedDict
        self.memory_cache: OrderedDict[str, CacheEntry] = OrderedDict()

        self.logger = setup_logger("scancache")

        # Use RWLock for better concurrency (readers don't block each other)
        # Fallback to regular Lock if RWLock not available
        try:
            from readerwriterlock import rwlock  # type: ignore

            self._lock = rwlock.RWLockFair()
        except ImportError:
            self._lock = threading.RLock() # type: ignore
            self._is_rwlock = False
        else:
            self._is_rwlock = True

        # Create cache directory with secure permissions
        self._create_secure_directory(self.cache_dir)

        # FIX: Initialize encryption with proper key derivation
        if master_key:
            self._initialize_encryption(master_key)
        else:
            # Generate ephemeral master key
            master_key = secrets.token_bytes(32)
            self._initialize_encryption(master_key)
            self.logger.warning(
                "Using ephemeral encryption key. "
                "Cache will not persist across restarts. "
                "Provide master_key for persistent cache."
            )

        # Atomic counters for statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._stats_lock = threading.Lock()

    def _create_secure_directory(self, directory: Path) -> None:
        """
        Create directory hierarchy with secure permissions.

        Args:
            directory: Directory to create
        """
        # Create each parent directory with secure permissions
        for parent in reversed(list(directory.parents)):
            if not parent.exists():
                try:
                    parent.mkdir(mode=0o700, exist_ok=True)
                    # Verify permissions
                    stat = parent.stat()
                    if stat.st_mode & 0o077:
                        self.logger.warning(
                            f"Failed to set secure permissions on {parent}. "
                            f"Attempting to fix..."
                        )
                        parent.chmod(0o700)
                except Exception as e:
                    self.logger.error(f"Failed to create directory {parent}: {e}")
                    raise

        # Create the final directory
        if not directory.exists():
            directory.mkdir(mode=0o700, exist_ok=True)

        # Verify final directory permissions
        stat = directory.stat()
        if stat.st_mode & 0o077:
            self.logger.warning(f"Insecure permissions on {directory}. Fixing...")
            directory.chmod(0o700)

    def _initialize_encryption(self, master_key: bytes) -> None:
        """
        FIX: Initialize encryption with proper key derivation.

        Uses PBKDF2 to derive:
        1. Encryption key for Fernet
        2. Separate HMAC key for authentication

        Args:
            master_key: Master key for derivation
        """
        # Generate salt (stored with cache for deterministic key derivation)
        salt_file = self.cache_dir / ".salt"
        if salt_file.exists():
            # Load existing salt
            with open(salt_file, "rb") as f:
                salt = f.read()
                if len(salt) != 32:
                    raise ValueError("Invalid salt file")
        else:
            # Generate new salt
            salt = secrets.token_bytes(32)
            # Write with secure permissions
            fd = os.open(salt_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, salt)
            finally:
                os.close(fd)

        # Derive encryption key using PBKDF2
        kdf_encryption = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=ENCRYPTION_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        encryption_key = kdf_encryption.derive(master_key)

        # Derive separate HMAC key
        kdf_hmac = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=HMAC_KEY_SIZE,
            salt=salt + b"HMAC",  # Different salt for HMAC key
            iterations=PBKDF2_ITERATIONS,
        )
        self.hmac_key = kdf_hmac.derive(master_key)

        # Initialize Fernet cipher
        try:
            # Fernet expects URL-safe base64-encoded key
            import base64

            fernet_key = base64.urlsafe_b64encode(encryption_key)
            self.cipher = Fernet(fernet_key)

            # Test the cipher
            test_data = b"test"
            encrypted = self.cipher.encrypt(test_data)
            decrypted = self.cipher.decrypt(encrypted)
            if decrypted != test_data:
                raise ValueError("Cipher test failed")

        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {e}")
            raise ValueError(f"Invalid encryption key: {e}") from e

    def _serialize(self, data: Any) -> bytes:
        """
        Safely serialize data with size limits and HMAC.

        Args:
            data: Data to serialize

        Returns:
            Encrypted and authenticated data

        Raises:
            ValueError: If data exceeds size limit or serialization fails
        """
        try:
            # Validate data depth to prevent deeply nested structures
            self._validate_data_depth(data)

            # Convert to JSON with size limit
            json_str = json.dumps(
                data,
                default=str,
                ensure_ascii=True,  # ASCII-only for safety
                separators=(",", ":"),  # Compact
            )

            # Check size limit
            if len(json_str) > CACHE_ENTRY_MAX_SIZE:
                raise ValueError(
                    f"Cache entry too large: {len(json_str)} bytes "
                    f"(max {CACHE_ENTRY_MAX_SIZE})"
                )

            json_bytes = json_str.encode("utf-8")

            # Encrypt
            encrypted = self.cipher.encrypt(json_bytes)

            # Add HMAC with separate key
            mac = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()

            # Return MAC + encrypted data
            return mac + encrypted

        except (TypeError, ValueError, OverflowError) as e:
            self.logger.error(f"Serialization error: {str(e)}")
            raise ValueError(f"Failed to serialize data: {e}") from e

    def _deserialize(self, data: bytes) -> Any:
        """
        Safely deserialize data with validation.

        Args:
            data: Encrypted and authenticated data

        Returns:
            Deserialized data

        Raises:
            ValueError: If data is corrupted or invalid
        """
        try:
            # Validate minimum size
            if len(data) < 32:
                raise ValueError("Invalid cache data: too short")

            # Split HMAC and encrypted data
            mac = data[:32]
            encrypted = data[32:]

            # Verify HMAC with constant-time comparison
            expected_mac = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()

            if not hmac.compare_digest(mac, expected_mac):
                raise ValueError("Cache integrity check failed: HMAC mismatch")

            # Decrypt
            try:
                decrypted = self.cipher.decrypt(encrypted)
            except InvalidToken as e:
                raise ValueError("Failed to decrypt cache data") from e

            # Deserialize JSON
            result = json.loads(decrypted.decode("utf-8"))

            # Validate deserialized data
            self._validate_data_depth(result)

            return result

        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            self.logger.error(f"Deserialization error: {str(e)}")
            raise ValueError(f"Failed to deserialize data: {e}") from e

    def _validate_data_depth(
        self, data: Any, depth: int = 0, max_depth: int = MAX_DESERIALIZATION_DEPTH
    ) -> None:
        """
        Validate data depth to prevent DoS via deeply nested structures.

        Args:
            data: Data to validate
            depth: Current depth
            max_depth: Maximum allowed depth

        Raises:
            ValueError: If depth exceeds maximum
        """
        if depth > max_depth:
            raise ValueError(f"Data nesting too deep: {depth} levels (max {max_depth})")

        if isinstance(data, dict):
            for value in data.values():
                self._validate_data_depth(value, depth + 1, max_depth)
        elif isinstance(data, (list, tuple)):
            for item in data:
                self._validate_data_depth(item, depth + 1, max_depth)

    def generate_key(self, *args, **kwargs) -> str:
        """
        Generate cache key from arguments.

        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            SHA256 hash of arguments
        """
        # Sort kwargs for deterministic hashing
        key_data = repr(args) + repr(sorted(kwargs.items()))
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value with thread-safe LRU tracking.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired/invalid
        """
        # Validate key
        try:
            Validator.validate_cache_key(key)
        except ValueError as e:
            self.logger.warning(f"Invalid cache key: {str(e)}")
            with self._stats_lock:
                self._misses += 1
            return None

        # Use reader lock for concurrent reads
        if self._is_rwlock:
            lock = self._lock.gen_rlock()
        else:
            lock = self._lock # type: ignore

        # Check memory cache
        with lock:
            if key in self.memory_cache:
                entry = self.memory_cache[key]
                if not entry.is_expired():
                    # LRU - move to end
                    self.memory_cache.move_to_end(key)
                    entry.touch()
                    with self._stats_lock:
                        self._hits += 1
                    self.logger.debug(f"Memory cache hit: {key}")
                    return entry.data
                else:
                    # Remove expired entry
                    del self.memory_cache[key]

        # Check disk cache (outside lock to avoid blocking readers)
        cache_file = self.cache_dir / f"{key}.cache"
        if cache_file.exists():
            try:
                # Verify file permissions and owner BEFORE reading
                stat = cache_file.stat()

                # Check permissions
                if stat.st_mode & 0o077:
                    self.logger.warning(
                        f"Insecure cache file permissions: {cache_file}"
                    )
                    cache_file.unlink()
                    with self._stats_lock:
                        self._misses += 1
                    return None

                # Read file
                with open(cache_file, "rb") as f:
                    data = f.read()

                # Validate file size
                if len(data) > CACHE_ENTRY_MAX_SIZE + 1024:  # +1024 for overhead
                    self.logger.warning(f"Cache file too large: {cache_file}")
                    cache_file.unlink()
                    with self._stats_lock:
                        self._misses += 1
                    return None

                # Deserialize
                cache_data = self._deserialize(data)

                # Reconstruct entry
                entry = CacheEntry(data=cache_data["data"], ttl=cache_data["ttl"])
                entry.timestamp = cache_data["timestamp"]

                if not entry.is_expired():
                    # Add to memory cache
                    if self._is_rwlock:
                        lock = self._lock.gen_wlock() # type: ignore
                    else:
                        lock = self._lock # type: ignore

                    with lock:
                        self._add_to_memory_cache(key, entry)

                    with self._stats_lock:
                        self._hits += 1
                    return entry.data
                else:
                    # Remove expired file
                    cache_file.unlink()

            except (ValueError, OSError, IOError) as e:
                self.logger.warning(f"Failed to load cache {key}: {str(e)}")
                if cache_file.exists():
                    cache_file.unlink()
                else:
                    pass  # File already deleted

        with self._stats_lock:
            self._misses += 1
        return None

    def _add_to_memory_cache(self, key: str, entry: CacheEntry) -> None:
        """
        Add entry to memory cache with LRU eviction.

        Must be called with write lock held.

        Args:
            key: Cache key
            entry: Cache entry
        """
        # Add to cache
        self.memory_cache[key] = entry
        self.memory_cache.move_to_end(key)

        # LRU eviction if cache is full
        while len(self.memory_cache) > self.max_memory_entries:
            # Remove oldest entry
            oldest_key = next(iter(self.memory_cache))
            del self.memory_cache[oldest_key]
            with self._stats_lock:
                self._evictions += 1
            self.logger.debug(f"Evicted cache entry: {oldest_key}")

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to cache result",
        return_on_error=None,
    )
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set cached value with atomic file operations.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live (None for no expiry, 0 for immediate expiry)

        Returns:
            True if successful, False otherwise
        """
        # Validate key
        try:
            Validator.validate_cache_key(key)
        except ValueError as e:
            self.logger.warning(f"Invalid cache key: {str(e)}")
            return False

        ttl = ttl if ttl is not None else self.default_ttl
        entry = CacheEntry(value, ttl)

        # Don't cache if TTL is 0 (immediate expiry)
        if ttl == 0:
            return True  # Success but no caching

        # Add to memory cache
        if self._is_rwlock:
            lock = self._lock.gen_wlock()
        else:
            lock = self._lock # type: ignore

        with lock:
            self._add_to_memory_cache(key, entry)

        # Prepare for disk
        cache_data = {"data": value, "timestamp": entry.timestamp, "ttl": ttl}

        try:
            serialized = self._serialize(cache_data)
        except ValueError as e:
            self.logger.warning(f"Cannot serialize cache {key}: {str(e)}")
            return False

        # Atomic file write with proper error handling
        cache_file = self.cache_dir / f"{key}.cache"
        temp_file = cache_file.with_suffix(f".tmp.{os.getpid()}")  # PID for uniqueness

        try:
            # Write with secure permissions atomically
            fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, serialized)
                os.fsync(fd)  # Force write to disk
            finally:
                os.close(fd)

            # Atomic rename
            temp_file.replace(cache_file)
            return True

        except Exception as e:
            self.logger.warning(f"Failed to save cache {key}: {str(e)}")
            # Cleanup in finally block
            if temp_file.exists():
                temp_file.unlink()
            else:
                pass # Temp file already deleted
            return False

    def invalidate(self, key: str) -> bool:
        """
        Invalidate a cache entry.

        Args:
            key: Cache key

        Returns:
            True if entry was invalidated
        """
        found = False

        # Remove from memory
        if self._is_rwlock:
            lock = self._lock.gen_wlock()
        else:
            lock = self._lock # type: ignore

        with lock:
            if key in self.memory_cache:
                del self.memory_cache[key]
                found = True

        # Remove from disk
        cache_file = self.cache_dir / f"{key}.cache"
        if cache_file.exists():
            try:
                cache_file.unlink()
                found = True
            except Exception as e:
                self.logger.warning(f"Failed to delete cache file {cache_file}: {e}")

        return found

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to clear cache",
        return_on_error=None,
    )
    def clear_all(self) -> None:
        """Clear all cache entries."""
        # Clear memory
        if self._is_rwlock:
            lock = self._lock.gen_wlock()
        else:
            lock = self._lock # type: ignore

        with lock:
            self.memory_cache.clear()

        # Clear disk
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                cache_file.unlink()
            except Exception as e:
                self.logger.warning(f"Failed to delete {cache_file}: {e}")

        self.logger.info("Cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics thread-safely.

        Returns:
            Dictionary of cache statistics
        """
        with self._stats_lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0

            return {
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_rate": f"{hit_rate:.2f}%",
                "memory_entries": len(self.memory_cache),
                "disk_entries": len(list(self.cache_dir.glob("*.cache"))),
                "total_requests": total_requests,
            }


def cached(ttl: Optional[int] = 3600, key_func: Optional[Callable] = None):
    """
    Improved decorator for caching async function results.

    Args:
        ttl: Time to live in seconds (None for no expiry, 0 to disable caching)
        key_func: Optional function to generate cache key
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Check if caching is disabled
            if not hasattr(self, "_cache") or self._cache is None:
                # No cache, just execute function
                return await func(self, *args, **kwargs)

            # Don't cache if TTL is 0
            if ttl == 0:
                return await func(self, *args, **kwargs)

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
