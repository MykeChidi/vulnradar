# vulnradar/reconn/_target.py - ReconTarget with comprehensive validation

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from ..utils.error_handler import ValidationError, get_global_error_handler
from ..utils.logger import setup_logger

# Initialize logger and error handler
logger = setup_logger("recon", log_to_file=False)
error_handler = get_global_error_handler()

# Constants
MAX_URL_LENGTH = 1024
MAX_HOSTNAME_LENGTH = 255
MAX_LABEL_LENGTH = 63
ALLOWED_SCHEMES = frozenset(["http", "https"])


@dataclass(frozen=True)  # Make immutable to prevent post-validation mutation
class ReconTarget:
    """
    Immutable data class to store validated target information.
    """

    url: str
    hostname: str
    ip: Optional[str] = None
    port: int = 80
    is_https: bool = False

    _validated: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self):
        """Validate all target attributes with comprehensive security checks."""
        # Validate URL length (DoS protection)
        if len(self.url) > MAX_URL_LENGTH:
            error_msg = f"URL too long: {len(self.url)} chars (max {MAX_URL_LENGTH})"
            logger.error(error_msg)
            error_handler.handle_error(
                ValidationError(error_msg),
                context={"url_length": len(self.url), "validation_type": "url_length"},
            )
            raise ValueError(error_msg)

        # Parse and validate URL
        try:
            parsed = urlparse(self.url)
        except Exception as e:
            error_msg = f"Failed to parse URL: {str(e)}"
            logger.error(error_msg)
            error_handler.handle_error(
                ValidationError(error_msg, original_error=e),
                context={
                    "url": self._sanitize_url_for_log(self.url),
                    "validation_type": "invalid url",
                },
            )
            raise ValueError(error_msg)

        # Validate URL structure
        if not parsed.scheme or not parsed.netloc:
            error_msg = "Invalid URL format: missing scheme or netloc"
            logger.error(error_msg)
            error_handler.handle_error(
                ValidationError(error_msg),
                context={
                    "url": self._sanitize_url_for_log(self.url),
                    "validation_type": "url_format",
                },
            )
            raise ValueError(error_msg)

        # Strict scheme validation
        if parsed.scheme not in ALLOWED_SCHEMES:
            error_msg = (
                f"Invalid URL scheme: {parsed.scheme}. "
                f"Only {', '.join(ALLOWED_SCHEMES)} are allowed"
            )
            logger.error(error_msg)
            error_handler.handle_error(
                ValidationError(error_msg),
                context={"scheme": parsed.scheme, "validation_type": "scheme"},
            )
            raise ValueError(error_msg)

        # Validate port range and warn about privileged ports
        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            error_msg = f"Invalid port: {self.port}. Must be integer between 1-65535"
            logger.error(error_msg)
            error_handler.handle_error(
                ValidationError(error_msg),
                context={"port": self.port, "validation_type": "port_range"},
            )
            raise ValueError(error_msg)

        # Comprehensive hostname validation
        self._validate_hostname(self.hostname)

        logger.debug(
            f"Target validated successfully: {self._sanitize_url_for_log(self.url)}"
        )

        # Mark as validated (using object.__setattr__ to bypass frozen dataclass)
        object.__setattr__(self, "_validated", True)

    def _validate_hostname(self, hostname: str) -> None:
        """
        FIX: Comprehensive hostname validation.

        Args:
            hostname: Hostname to validate

        Raises:
            ValueError: If hostname is invalid
        """
        if not hostname:
            error_msg = "Hostname cannot be empty"
            logger.error(error_msg)
            error_handler.handle_error(
                ValidationError(error_msg),
                context={"validation_type": "hostname_empty"},
            )
            raise ValueError(error_msg)

        # Strip port if included in hostname
        hostname_clean = hostname.split(":")[0]

        # Length validation (RFC 1035)
        if len(hostname_clean) > MAX_HOSTNAME_LENGTH:
            error_msg = (
                f"Hostname too long: {len(hostname_clean)} chars "
                f"(max {MAX_HOSTNAME_LENGTH})"
            )
            logger.error(error_msg)
            error_handler.handle_error(
                ValidationError(error_msg),
                context={
                    "hostname_length": len(hostname_clean),
                    "validation_type": "hostname_length",
                },
            )
            raise ValueError(error_msg)

        # Validate each label (DNS name parts between dots)
        labels = hostname_clean.split(".")
        for label in labels:
            if not label:
                error_msg = f"Invalid hostname: empty label in '{hostname_clean}'"
                logger.error(error_msg)
                raise ValueError(error_msg)

            if len(label) > MAX_LABEL_LENGTH:
                error_msg = (
                    f"Invalid hostname: label '{label}' exceeds "
                    f"{MAX_LABEL_LENGTH} characters"
                )
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Validate label format (RFC 1035)
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", label):
                error_msg = (
                    f"Invalid hostname: label '{label}' contains invalid characters. "
                    "Labels must start/end with alphanumeric and contain only "
                    "alphanumeric and hyphens."
                )
                logger.error(error_msg)
                raise ValueError(error_msg)

        # Detect if hostname contains mixed scripts (e.g., Cyrillic and Latin)
        if self._contains_mixed_scripts(hostname_clean):
            logger.warning(f"Hostname '{hostname_clean}' contains mixed scripts. ")

            raise ValueError("Hostname contains mixed scripts")

    def _contains_mixed_scripts(self, hostname: str) -> bool:
        """
        Detect mixed scripts in hostname (IDN homograph attack).

        Args:
            hostname: Hostname to check

        Returns:
            True if hostname contains characters from multiple scripts
        """
        # Simple check: if hostname contains both ASCII and non-ASCII
        has_ascii = any(ord(c) < 128 for c in hostname)
        has_non_ascii = any(ord(c) >= 128 for c in hostname)

        return has_ascii and has_non_ascii

    @staticmethod
    def _sanitize_url_for_log(url: str) -> str:
        """
        Sanitize URL for logging (remove credentials).

        Args:
            url: URL to sanitize

        Returns:
            Sanitized URL safe for logging
        """
        try:
            parsed = urlparse(url)
            # Remove username/password
            if parsed.username or parsed.password:
                netloc = parsed.hostname
                if parsed.port:
                    netloc = f"{netloc}:{parsed.port}"
                sanitized = parsed._replace(netloc=netloc)  # type: ignore
                return sanitized.geturl()
        except Exception:
            # If sanitization fails, return generic message
            return "[URL parsing failed]"

        return url

    def to_dict(self) -> dict:
        """
        Convert target to dictionary for serialization.

        Returns:
            Dictionary representation of target
        """
        return {
            "url": self.url,
            "hostname": self.hostname,
            "ip": self.ip,
            "port": self.port,
            "is_https": self.is_https,
        }

    def __str__(self) -> str:
        """String representation."""
        return (
            f"ReconTarget(url={self._sanitize_url_for_log(self.url)}, port={self.port})"
        )
