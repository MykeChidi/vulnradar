# vulnradar/utils/validator.py - Input validation & sanitization

import re
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from .error_handler import ValidationError, get_global_error_handler, handle_errors

error_handler = get_global_error_handler()


class Validator:
    """Validates all user inputs to prevent injection attacks."""

    # Whitelist patterns for various input types
    SAFE_URL_PATTERN = re.compile(r"^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$")
    SAFE_HEADER_VALUE = re.compile(r"^[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;= ]+$")
    SAFE_COOKIE_PATTERN = re.compile(r"^[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+$")
    SAFE_CACHE_KEY = re.compile(r"^[a-zA-Z0-9_-]+$")
    PORT_RANGE_PATTERN = re.compile(r"^[\d,\-]+$")
    DEFAULT_MAX_PORTS = 65535

    @staticmethod
    @handle_errors(
        error_handler=error_handler,
        user_message="URL validation failed",
        return_on_error="",
    )
    def validate_url(url: str) -> str:
        """Validate and sanitize URL input."""
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")

        if len(url) > 255:
            raise ValueError("URL exceeds maximum length of characters")

        # Check against whitelist pattern
        if not Validator.SAFE_URL_PATTERN.match(url):
            raise ValueError("URL contains invalid characters")

        # Parse and validate components
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")

        if parsed.scheme not in ["http", "https"]:
            raise ValueError("Only HTTP/HTTPS schemes allowed")

        if not parsed.netloc:
            raise ValueError("URL must contain a hostname")

        return url

    @staticmethod
    @handle_errors(
        error_handler=error_handler,
        user_message="Header validation failed",
        return_on_error="",
    )
    def validate_header_value(value: str, name: str) -> str:
        """Validate HTTP header value to prevent injection."""
        if not isinstance(value, str):
            raise ValueError(f"{name} header must be a string")

        if len(value) > 4096:
            raise ValueError(f"{name} header exceeds maximum length")

        if not Validator.SAFE_HEADER_VALUE.match(value):
            raise ValueError("Header contains invalid characters")

        # Check for injection attempts
        dangerous_chars = ["\r", "\n", "\0"]
        if any(char in value for char in dangerous_chars):
            raise ValueError(f"{name} header contains forbidden control characters")

        # Additional validation for cookies
        if name.lower() == "cookie":
            if not Validator.SAFE_COOKIE_PATTERN.match(value):
                raise ValueError("Cookie contains invalid characters")

        return value

    @staticmethod
    def validate_port_range(
        port_range: str, max_ports: int = DEFAULT_MAX_PORTS
    ) -> List[int]:
        """
        Validate and parse port range.

        Args:
            port_range: Port range string (e.g., "80,443,1000-2000")
            max_ports: Maximum number of ports allowed

        Returns:
            List of validated port numbers

        Raises:
            ValidationError: If port range is invalid
        """
        if not Validator.PORT_RANGE_PATTERN.match(port_range):
            raise ValidationError(
                f"Invalid port range format: {port_range}",
                context={"port_range": port_range},
            )

        ports: List = []
        for part in port_range.split(","):
            part = part.strip()

            if "-" in part:
                start_str, end_str = part.split("-", 1)
                start, end = int(start_str), int(end_str)

                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValidationError(f"Port out of range: {part}")

                if start > end:
                    raise ValidationError(f"Invalid range (start > end): {part}")

                if end - start > max_ports:
                    raise ValidationError(f"Range too large: {part}")

                ports.extend(range(start, end + 1))
            else:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValidationError(f"Port out of range: {port}")
                ports.append(port)

        ports = sorted(set(ports))

        if len(ports) > max_ports:
            raise ValidationError(f"Too many ports: {len(ports)} (max {max_ports})")

        return ports

    @staticmethod
    @handle_errors(
        error_handler=error_handler,
        user_message="File path sanitization failed",
        return_on_error=None,
    )
    def sanitize_file_path(path: str, base_dir: Optional[str] = None) -> Path:
        """Sanitize file path for safe dir creation."""
        if not path or not isinstance(path, str):
            raise ValueError("Path must be a non-empty string")

        # Disallow obvious dangerous input early
        if ".." in path or "~" in path:
            raise ValueError("Path contains invalid patterns")

        # Determine project root (parent of the vulnradar package)
        try:
            project_root = Path(__file__).resolve().parents[2]
        except Exception:
            # Fallback to current working directory if resolution fails
            project_root = Path.cwd()

        # Resolve relative paths against the project root by default
        try:
            p = Path(path)
            if not p.is_absolute():
                resolved_path = (project_root / p).resolve()
            else:
                resolved_path = p.resolve()
        except Exception as e:
            raise ValueError(f"Invalid path: {e}")

        # If base_dir specified, ensure path is within it
        if base_dir:
            try:
                base = Path(base_dir).resolve()
                resolved_path.relative_to(base)
            except (ValueError, RuntimeError):
                raise ValueError(f"Path {path} is outside allowed directory")

        return resolved_path

    @staticmethod
    @handle_errors(
        error_handler=error_handler,
        user_message="Cache key validation failed",
        return_on_error="",
    )
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
    @handle_errors(
        error_handler=error_handler,
        user_message="Filename sanitization failed",
        return_on_error="output",
    )
    def sanitize_filename(filename: str, max_length: int = 200) -> str:
        """Sanitize filename for safe file creation."""
        import unicodedata

        if not filename:
            return "unnamed"

        # Normalize unicode
        filename = unicodedata.normalize("NFKD", filename)
        filename = filename.encode("ascii", "ignore").decode("ascii")

        # Remove dangerous characters
        dangerous_chars = [
            "/",
            "\\",
            "..",
            "\0",
            "\r",
            "\n",
            ":",
            "*",
            "?",
            '"',
            "<",
            ">",
            "|",
            ";",
            "&",
            "$",
        ]
        for char in dangerous_chars:
            filename = filename.replace(char, "_")

        # Remove leading/trailing dots and spaces
        filename = filename.strip(". ")

        # Truncate to max length
        if len(filename) > max_length:
            name, ext = Path(filename).stem, Path(filename).suffix
            filename = name[: max_length - len(ext)] + ext

        # Ensure filename is not empty after sanitization
        if not filename or filename == ".":
            filename = "unnamed"

        return filename
