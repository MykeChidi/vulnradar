# vulnradar/utils/validator.py

import re
import ipaddress
import socket
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


class Validator:
    """Validates all user inputs to prevent injection attacks."""
    
    # Whitelist patterns for various input types
    SAFE_URL_PATTERN = re.compile(r'^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$')
    SAFE_HEADER_VALUE = re.compile(r'^[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;= ]+$')
    SAFE_COOKIE_PATTERN = re.compile(r'^[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+$')
    SAFE_CACHE_KEY = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    # Blocked networks for SSRF prevention
    BLOCKED_NETWORKS = [
        ipaddress.ip_network('127.0.0.0/8'),      # Loopback
        ipaddress.ip_network('10.0.0.0/8'),       # Private
        ipaddress.ip_network('172.16.0.0/12'),    # Private
        ipaddress.ip_network('192.168.0.0/16'),   # Private
        ipaddress.ip_network('169.254.0.0/16'),   # Link-local (AWS metadata)
        ipaddress.ip_network('::1/128'),          # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),         # IPv6 private
        ipaddress.ip_network('fe80::/10'),        # IPv6 link-local
    ]
    
    @staticmethod
    def validate_url(url: str) -> str:
        """Validate and sanitize URL input."""
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")
            
        if len(url) > 255:
            raise ValueError("URL exceeds maximum length of characters")
        
        # Check against whitelist pattern
        if not Validator.SAFE_URL_PATTERN.match(url):
            raise ValueError(f"URL contains invalid characters")
        
        # Parse and validate components
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")
        
        if parsed.scheme not in ['http', 'https']:
            raise ValueError("Only HTTP/HTTPS schemes allowed")
        
        if not parsed.netloc:
            raise ValueError("URL must contain a hostname")
        
        # Prevent SSRF to internal networks
        if Validator._is_blocked_host(parsed.hostname):
            raise ValueError("Cannot scan internal/private IP addresses or blocked hosts")
        
        return url
    
    @staticmethod
    def _is_blocked_host(hostname: str) -> bool:
        """Check if hostname resolves to blocked IP or is a blocked domain."""
        if not hostname:
            return True
        
        # Check blocked domains
        blocked_domains = [
            'localhost', 'metadata.google.internal',
            'metadata', 'metadata.azure.com'
             '127.0.0.1', '0.0.0.0', '169.254.169.254',
        ]
        
        if hostname.lower() in blocked_domains:
            return True
        
        # Try to resolve and check IP
        try:
            # Get all resolved IPs
            addr_info = socket.getaddrinfo(hostname, None)
            
            for family, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                
                try:
                    ip = ipaddress.ip_address(ip_str)
                    
                    # Check if IP is in any blocked network
                    for network in Validator.BLOCKED_NETWORKS:
                        if ip in network:
                            return True
                    
                    # Additional checks
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                        return True
                        
                except ValueError:
                    continue
                    
        except (socket.gaierror, socket.error):
            # DNS resolution failed
            pass
        
        return False
    
    @staticmethod
    def validate_header_value(value: str, name: str) -> str:
        """Validate HTTP header value to prevent injection."""
        if not isinstance(value, str):
            raise ValueError(f"{name} header must be a string")
            
        if len(value) > 4096:
            raise ValueError(f"{name} header exceeds maximum length")
        
        if not Validator.SAFE_HEADER_VALUE.match(value):
            raise ValueError("Header contains invalid characters")
        
        # Check for injection attempts
        dangerous_chars = ['\r', '\n', '\0']
        if any(char in value for char in dangerous_chars):
            raise ValueError(f"{name} header contains forbidden control characters")
        
        # Additional validation for cookies
        if name.lower() == 'cookie':
            if not Validator.SAFE_COOKIE_PATTERN.match(value):
                raise ValueError("Cookie contains invalid characters")
        
        return value
    
    @staticmethod
    def sanitize_file_path(path: str, base_dir: Optional[str] = None) -> Path:
        """Sanitize file path for safe dir creation."""
        if not path or not isinstance(path, str):
            raise ValueError("Path must be a non-empty string")
        
        # Resolve to absolute path
        try:
            resolved_path = Path(path).resolve()
        except Exception as e:
            raise ValueError(f"Invalid path: {e}")
        
        # If base directory specified, ensure path is within it
        if base_dir:
            try:
                base = Path(base_dir).resolve()
                # Check if resolved path starts with base directory
                resolved_path.relative_to(base)
            except (ValueError, RuntimeError):
                raise ValueError(f"Path {path} is outside allowed directory")
        
        # Check for dangerous patterns
        path_str = str(resolved_path)
        dangerous_patterns = ['..', '~']
        if any(pattern in str(path_str) for pattern in dangerous_patterns):
            raise ValueError("Path contains invalid patterns")
        
        return resolved_path
    
    @staticmethod
    def validate_cache_key(key: str) -> str:
        """Validate cache key format."""
        if not key or not isinstance(key, str):
            raise ValueError("Cache key must be a non-empty string")
        
        if len(key) > 200:
            raise ValueError("Cache key too long")
        
        if not Validator.SAFE_CACHE_KEY.match(key):
            raise ValueError("Cache key contains invalid characters")
        
        return key
    
    @staticmethod
    def sanitize_filename(filename: str, max_length: int = 200) -> str:
        """Sanitize filename for safe file creation."""
        import unicodedata
        
        if not filename:
            return 'unnamed'
        
        # Normalize unicode
        filename = unicodedata.normalize('NFKD', filename)
        filename = filename.encode('ascii', 'ignore').decode('ascii')
        
        # Remove dangerous characters
        dangerous_chars = ['/', '\\', '..', '\0', '\r', '\n', ':', '*', '?', '"', '<', '>', '|', ';', '&', '$']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing dots and spaces
        filename = filename.strip('. ')
        
        # Truncate to max length
        if len(filename) > max_length:
            name, ext = Path(filename).stem, Path(filename).suffix
            filename = name[:max_length-len(ext)] + ext
        
        # Ensure filename is not empty after sanitization
        if not filename or filename == '.':
            filename = 'unnamed'
        
        return filename
