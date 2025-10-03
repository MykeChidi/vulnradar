# vulnscan/utils/cache.py - Caching for redundant requests

import hashlib
import pickle
import time
from pathlib import Path
from typing import Any, Optional, Callable, Dict
import functools
from utils.logger import setup_logger


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
    
    def __init__(self, cache_dir: Path, default_ttl: int = 3600):
        """
        Initialize cache.
        
        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default time to live in seconds
        """
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self.memory_cache: Dict[str, CacheEntry] = {}
        self.logger = setup_logger("ScanCache")
        
        # Cache statistics
        self.hits = 0
        self.misses = 0
    
    def generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments."""
        key_data = str(args) + str(sorted(kwargs.items()))
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        # Check memory cache first
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
                with open(cache_file, 'rb') as f:
                    entry = pickle.load(f)
                
                if not entry.is_expired():
                    # Load into memory cache
                    self.memory_cache[key] = entry
                    self.hits += 1
                    self.logger.debug(f"Disk cache hit: {key}")
                    return entry.data
                else:
                    cache_file.unlink()
            except Exception as e:
                self.logger.warning(f"Failed to load cache {key}: {str(e)}")
        
        self.misses += 1
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Set cached value.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live (uses default if None)
        """
        ttl = ttl if ttl is not None else self.default_ttl
        entry = CacheEntry(value, ttl)
        
        # Store in memory cache
        self.memory_cache[key] = entry
        
        # Store in disk cache
        cache_file = self.cache_dir / f"{key}.cache"
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(entry, f)
        except Exception as e:
            self.logger.warning(f"Failed to save cache {key}: {str(e)}")
    
    def invalidate(self, key: str):
        """Invalidate a cache entry."""
        if key in self.memory_cache:
            del self.memory_cache[key]
        
        cache_file = self.cache_dir / f"{key}.cache"
        if cache_file.exists():
            cache_file.unlink()
    
    def clear_all(self):
        """Clear all cache entries."""
        self.memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.cache"):
            cache_file.unlink()
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
            "disk_entries": len(list(self.cache_dir.glob("*.cache")))
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
            if getattr(self, '_cache', None) is None:
                # No cache, just execute function
                return await func(self, *args, **kwargs)

            # Get cache instance from self
            if not hasattr(self, '_cache'):
                # Initialize cache if not present
                cache_dir = Path("cache") / self.__class__.__name__
                self._cache = ScanCache(cache_dir, default_ttl=ttl)
            
            # Generate cache key
            if key_func:
                cache_key = key_func(self, *args, **kwargs)
            else:
                cache_key = self._cache.generate_key(
                    func.__name__, 
                    *args, 
                    **kwargs
                )
            
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