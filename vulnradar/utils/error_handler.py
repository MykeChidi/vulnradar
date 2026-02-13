# vulnradar/utils/error_handler.py - Secure Error Handling Module

import functools
import re
import sys
import traceback
from collections import defaultdict
from enum import Enum
from pathlib import Path
from threading import Lock
from time import time
from typing import Any, Callable, Dict, Optional

from colorama import Fore, Style

from .logger import setup_logger

# Initialize logger
logger = setup_logger("Error_logs")

# Constants for configuration
ERROR_DEDUP_WINDOW_SECONDS = 60
ERROR_CLEANUP_WINDOW_SECONDS = 300
MAX_SAFE_MESSAGE_LENGTH = 200


class ErrorSeverity(Enum):
    """Error severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification"""

    NETWORK = "network"
    AUTHENTICATION = "authentication"
    VALIDATION = "validation"
    PERMISSION = "permission"
    RESOURCE = "resource"
    CONFIGURATION = "configuration"
    TIMEOUT = "timeout"
    PARSE = "parse"
    DATABASE = "database"
    SCAN = "scan"
    UNKNOWN = "unknown"


class VulnRadarError(Exception):
    """Base exception class for VulnRadar errors"""

    def __init__(
        self,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        original_error: Optional[Exception] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.category = category
        self.original_error = original_error
        self.context = context or {}

        if original_error:
            self.__cause__ = original_error

    def __str__(self):
        return f"[{self.severity.value.upper()}] {self.message}"


class NetworkError(VulnRadarError):
    """Network-related errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.NETWORK
        super().__init__(message, **kwargs)


class AuthenticationError(VulnRadarError):
    """Authentication-related errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.AUTHENTICATION
        kwargs["severity"] = kwargs.get("severity", ErrorSeverity.HIGH)
        super().__init__(message, **kwargs)


class ValidationError(VulnRadarError):
    """Input validation errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.VALIDATION
        super().__init__(message, **kwargs)


class AccessError(VulnRadarError):
    """Permission/authorization errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.PERMISSION
        kwargs["severity"] = kwargs.get("severity", ErrorSeverity.HIGH)
        super().__init__(message, **kwargs)


class ResourceError(VulnRadarError):
    """Resource-related errors (memory, disk, etc.)"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.RESOURCE
        super().__init__(message, **kwargs)


class ConfigurationError(VulnRadarError):
    """Configuration-related errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.CONFIGURATION
        kwargs["severity"] = kwargs.get("severity", ErrorSeverity.HIGH)
        super().__init__(message, **kwargs)


class ScanTimeoutError(VulnRadarError):
    """Timeout-related errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.TIMEOUT
        super().__init__(message, **kwargs)


class ParseError(VulnRadarError):
    """Parsing-related errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.PARSE
        super().__init__(message, **kwargs)


class DatabaseError(VulnRadarError):
    """Database-related errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.DATABASE
        super().__init__(message, **kwargs)


class ScanError(VulnRadarError):
    """Scan execution errors"""

    def __init__(self, message: str, **kwargs):
        kwargs["category"] = ErrorCategory.SCAN
        super().__init__(message, **kwargs)


class ErrorHandler:
    """
    Centralized error handler that manages error logging,
    user feedback, and secure error reporting.
    """

    # ReDoS-safe sensitive data patterns
    SENSITIVE_PATTERNS = [
        # Match passwords - limited to 200 chars to prevent ReDoS
        (
            re.compile(
                r'(password["\']?\s*[:=]\s*["\'])([^"\']{1,200})(["\'])', re.IGNORECASE
            ),
            r"\1[REDACTED]\3",
        ),
        # API keys - limited length
        (
            re.compile(
                r'(api[_-]?key["\']?\s*[:=]\s*["\'])([^"\']{1,200})(["\'])',
                re.IGNORECASE,
            ),
            r"\1[REDACTED]\3",
        ),
        # Tokens - limited length
        (
            re.compile(
                r'(token["\']?\s*[:=]\s*["\'])([^"\']{1,200})(["\'])', re.IGNORECASE
            ),
            r"\1[REDACTED]\3",
        ),
        # Secrets - limited length
        (
            re.compile(
                r'(secret["\']?\s*[:=]\s*["\'])([^"\']{1,200})(["\'])', re.IGNORECASE
            ),
            r"\1[REDACTED]\3",
        ),
        # Auth - limited length
        (
            re.compile(
                r'(auth["\']?\s*[:=]\s*["\'])([^"\']{1,200})(["\'])', re.IGNORECASE
            ),
            r"\1[REDACTED]\3",
        ),
        # Add database connection strings
        (
            re.compile(
                r"((?:mysql|postgresql|mongodb)://[^:]+:)([^@]{1,200})(@)",
                re.IGNORECASE,
            ),
            r"\1[REDACTED]\3",
        ),
        # Add Bearer tokens
        (
            re.compile(r"(Bearer\s+)([A-Za-z0-9\-._~+/]{10,200})", re.IGNORECASE),
            r"\1[REDACTED]",
        ),
    ]

    # Enhanced path patterns
    PATH_PATTERNS = [
        # Unix home directories
        (re.compile(r"/home/[^/]+/"), "/home/[USER]/"),
        # Windows user directories
        (re.compile(r"C:\\Users\\[^\\]+\\"), r"C:\Users\[USER]\\"),
        # Temporary directories
        (re.compile(r"/tmp/[^/]+/"), "/tmp/[TEMP]/"),  # nosec: B108
        (re.compile(r"/var/tmp/[^/]+/"), "/var/tmp/[TEMP]/"),  # nosec: B108
        # Common project paths
        (re.compile(r"/opt/[^/]+/"), "/opt/[APP]/"),
    ]

    def __init__(
        self,
        debug_mode: bool = False,
        log_file: Optional[Path] = None,
        rate_limited: bool = True,
    ):
        """
        Initialize error handler.

        Args:
            debug_mode: If True, show detailed error information
            log_file: Optional file to log errors to
            rate_limited: If True, prevent log spam from repeated errors
        """
        self.debug_mode = debug_mode
        self.log_file = log_file
        self.rate_limited = rate_limited

        # Thread-safe error counting with proper lock
        self._error_counts: Dict[ErrorCategory, int] = defaultdict(int)
        self._counts_lock = Lock()

        # Rate limiting for repeated errors
        self._recent_errors: Dict[str, float] = {}
        self._rate_limit_lock = Lock()

        # Check if output supports color
        self._color_enabled = sys.stdout.isatty()

    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        user_message: Optional[str] = None,
        log_traceback: bool = True,
    ) -> Dict[str, Any]:
        """
        Handle an error with appropriate logging and user feedback.

        Args:
            error: The exception that occurred
            context: Additional context about where/how error occurred
            user_message: User-friendly message to display
            log_traceback: Whether to log full traceback

        Returns:
            Dict containing error information for reporting
        """
        context = context or {}

        # Classify the error
        if isinstance(error, VulnRadarError):
            severity = error.severity
            category = error.category
            message = error.message
        else:
            severity, category = self._classify_error(error)
            message = str(error)

        # Update error counts with proper locking
        with self._counts_lock:
            self._error_counts[category] += 1
            current_count = self._error_counts[category]

        # Sanitize sensitive data from message
        safe_message = self._sanitize_message(message)
        safe_context = self._sanitize_context(context)

        # Check if we should log (rate limiting)
        should_log = not self.rate_limited or self._should_log(error)

        if should_log:
            self._log_error(
                error=error,
                severity=severity,
                category=category,
                message=safe_message,
                context=safe_context,
                log_traceback=log_traceback,
            )

        # Generate user-friendly message
        if user_message:
            display_message = user_message
        else:
            display_message = self._generate_user_message(category, safe_message)

        # Build error info dictionary
        error_info = {
            "severity": severity.value,
            "category": category.value,
            "message": safe_message,
            "user_message": display_message,
            "context": safe_context,
            "recoverable": self._is_recoverable(error),
            "count": current_count,
        }

        if self.debug_mode:
            error_info["traceback"] = traceback.format_exc()

        return error_info

    def _classify_error(self, error: Exception) -> tuple[ErrorSeverity, ErrorCategory]:
        """
        Classify error based on type and message.

        Args:
            error: The exception to classify

        Returns:
            Tuple of (severity, category)
        """
        error_type = type(error).__name__
        error_msg = str(error).lower()

        # Network errors
        if error_type in ["ConnectionError", "TimeoutError", "HTTPError"]:
            return ErrorSeverity.MEDIUM, ErrorCategory.NETWORK

        # Authentication errors
        if "authentication" in error_msg or "unauthorized" in error_msg:
            return ErrorSeverity.HIGH, ErrorCategory.AUTHENTICATION

        # Validation errors
        if error_type == "ValueError" or "invalid" in error_msg:
            return ErrorSeverity.LOW, ErrorCategory.VALIDATION

        # Permission errors
        if "permission" in error_msg or "forbidden" in error_msg:
            return ErrorSeverity.HIGH, ErrorCategory.PERMISSION

        # Timeout errors
        if "timeout" in error_msg or error_type == "TimeoutError":
            return ErrorSeverity.MEDIUM, ErrorCategory.TIMEOUT

        # Parse errors
        if any(x in error_type.lower() for x in ["parse", "json", "xml", "decode"]):
            return ErrorSeverity.LOW, ErrorCategory.PARSE

        # Database errors
        if any(x in error_msg for x in ["database", "sql", "query"]):
            return ErrorSeverity.HIGH, ErrorCategory.DATABASE

        # Default
        return ErrorSeverity.MEDIUM, ErrorCategory.UNKNOWN

    def _sanitize_message(self, message: str) -> str:
        """
        FIX: Remove sensitive data from error messages with ReDoS protection.

        Args:
            message: Original error message

        Returns:
            Sanitized message
        """
        # Limit message length to prevent ReDoS
        if len(message) > 5000:
            message = message[:5000] + "... [truncated]"

        sanitized = message

        # Apply sensitive patterns with try-except for safety
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            try:
                sanitized = pattern.sub(replacement, sanitized)
            except Exception as e:
                logger.warning(f"Failed to apply sanitization pattern: {e}")
                # Continue with other patterns

        # Apply path patterns
        for pattern, replacement in self.PATH_PATTERNS:
            try:
                sanitized = pattern.sub(replacement, sanitized)
            except Exception as e:
                logger.warning(f"Failed to apply path pattern: {e}")

        # Remove newlines to prevent log injection
        sanitized = sanitized.replace("\n", " ").replace("\r", " ")

        # Remove ANSI codes to prevent terminal injection
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        sanitized = ansi_escape.sub("", sanitized)

        return sanitized

    def _sanitize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize context dictionary.

        Args:
            context: Original context

        Returns:
            Sanitized context
        """
        sanitized = {}
        for key, value in context.items():
            # Sanitize both key and value
            safe_key = self._sanitize_message(str(key))
            safe_value = self._sanitize_message(str(value))
            sanitized[safe_key] = safe_value

        return sanitized

    def _generate_user_message(self, category: ErrorCategory, safe_message: str) -> str:
        """
        Generate a user-friendly error message.

        Args:
            category: Error category
            safe_message: Sanitized error message

        Returns:
            User-friendly message
        """
        default_messages = {
            ErrorCategory.NETWORK: "Network connection error. Please check your connection and try again.",
            ErrorCategory.AUTHENTICATION: "Authentication failed. Please check your credentials.",
            ErrorCategory.VALIDATION: "Invalid input provided. Please check your parameters.",
            ErrorCategory.PERMISSION: "Insufficient permissions to perform this operation.",
            ErrorCategory.RESOURCE: "System resource error. Please try again later.",
            ErrorCategory.CONFIGURATION: "Configuration error. Please check your settings.",
            ErrorCategory.TIMEOUT: "Operation timed out. Please try again.",
            ErrorCategory.PARSE: "Failed to parse response. The target may have returned invalid data.",
            ErrorCategory.DATABASE: "Database error occurred. Please contact support.",
            ErrorCategory.SCAN: "Scan error occurred. Please check the target and try again.",
            ErrorCategory.UNKNOWN: "An unexpected error occurred. Please try again.",
        }

        base_message = default_messages.get(
            category, default_messages[ErrorCategory.UNKNOWN]
        )

        # Append safe message if it's useful
        if (
            safe_message
            and len(safe_message) < MAX_SAFE_MESSAGE_LENGTH
            and not any(
                x in safe_message.lower()
                for x in ["traceback", "exception", "error at"]
            )
        ):
            return f"{base_message} Details: {safe_message}"

        return base_message

    def _is_recoverable(self, error: Exception) -> bool:
        """
        Determine if an error is recoverable.

        Args:
            error: The exception to check

        Returns:
            True if error is recoverable
        """
        recoverable_types = [
            "TimeoutError",
            "ConnectionError",
            "ConnectionResetError",
            "BrokenPipeError",
            "ScanTimeoutError",
        ]

        if type(error).__name__ in recoverable_types:
            return True

        error_msg = str(error).lower()
        recoverable_messages = ["timeout", "temporary", "retry", "unavailable"]

        return any(msg in error_msg for msg in recoverable_messages)

    def _should_log(self, error: Exception) -> bool:
        """
        Determine if error should be logged (prevents log spam).

        Args:
            error: The exception to check

        Returns:
            True if error should be logged
        """
        # Create better hash using first 100 chars
        error_hash = f"{type(error).__name__}:{str(error)[:100]}"
        now = time()

        with self._rate_limit_lock:
            if error_hash in self._recent_errors:
                last_time = self._recent_errors[error_hash]
                if now - last_time < ERROR_DEDUP_WINDOW_SECONDS:
                    return False

            self._recent_errors[error_hash] = now

            # Clean up old entries
            cutoff = now - ERROR_CLEANUP_WINDOW_SECONDS
            self._recent_errors = {
                k: v for k, v in self._recent_errors.items() if v > cutoff
            }

        return True

    def _log_error(
        self,
        error: Exception,
        severity: ErrorSeverity,
        category: ErrorCategory,
        message: str,
        context: Dict[str, Any],
        log_traceback: bool,
    ):
        """
        Log error details to the logging system.

        Args:
            error: The exception
            severity: Error severity
            category: Error category
            message: Sanitized message
            context: Additional context
            log_traceback: Whether to log traceback
        """
        log_msg = f"[{category.value.upper()}] {message}"

        if context:
            log_msg += f" | Context: {context}"

        # Only use colors if terminal supports it
        if self._color_enabled:
            if severity == ErrorSeverity.CRITICAL:
                logger.critical(f"{Fore.RED}{log_msg}{Style.RESET_ALL}")
            elif severity == ErrorSeverity.HIGH:
                logger.error(f"{Fore.RED}{log_msg}{Style.RESET_ALL}")
            elif severity == ErrorSeverity.MEDIUM:
                logger.warning(f"{Fore.YELLOW}{log_msg}{Style.RESET_ALL}")
            else:
                logger.info(f"{Fore.BLUE}{log_msg}{Style.RESET_ALL}")
        else:
            # Plain logging without colors
            if severity == ErrorSeverity.CRITICAL:
                logger.critical(log_msg)
            elif severity == ErrorSeverity.HIGH:
                logger.error(log_msg)
            elif severity == ErrorSeverity.MEDIUM:
                logger.warning(log_msg)
            else:
                logger.info(log_msg)

        # Log traceback for high severity or debug mode
        if log_traceback and (
            severity.value in ["high", "critical"] or self.debug_mode
        ):
            logger.debug(f"Traceback: {traceback.format_exc()}")

    def get_error_counts(self) -> Dict[str, int]:
        """
        FIX: Get error counts thread-safely.

        Returns:
            Dictionary of error counts by category
        """
        with self._counts_lock:
            return dict(self._error_counts)  # type: ignore


class AsyncErrorHandler(ErrorHandler):
    """Async version of ErrorHandler with async context manager support."""

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Handle exceptions in async context manager.

        Only suppresses VulnRadarError, not system exceptions.
        """
        if exc_val is not None:
            # Don't suppress system exceptions
            if isinstance(exc_val, (SystemExit, KeyboardInterrupt, GeneratorExit)):
                return False

            self.handle_error(exc_val)

            # Only suppress VulnRadarError
            if isinstance(exc_val, VulnRadarError):
                return True

        return False


def handle_errors(
    error_handler: Optional[ErrorHandler] = None,
    user_message: Optional[str] = None,
    raise_on_error: bool = False,
    return_on_error: Any = None,
    log_traceback: bool = True,
):
    """
    Decorator for handling errors in functions.

    Args:
        error_handler: ErrorHandler instance to use
        user_message: Custom user message
        raise_on_error: Whether to re-raise the error after handling
        return_on_error: Value to return if error occurs
        log_traceback: Whether to log traceback
    """
    # Use global error handler if none provided
    if error_handler is None:
        error_handler = get_global_error_handler()

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_info = error_handler.handle_error(
                    e,
                    context={"function": func.__name__},
                    user_message=user_message,
                    log_traceback=log_traceback,
                )

                if raise_on_error:
                    raise

                return return_on_error if return_on_error is not None else error_info

        return wrapper

    return decorator


def handle_async_errors(
    error_handler: Optional[ErrorHandler] = None,
    user_message: Optional[str] = None,
    raise_on_error: bool = False,
    return_on_error: Any = None,
    log_traceback: bool = True,
):
    """
    Decorator for handling errors in async functions.

    Args:
        error_handler: ErrorHandler instance to use
        user_message: Custom user message
        raise_on_error: Whether to re-raise the error after handling
        return_on_error: Value to return if error occurs
        log_traceback: Whether to log traceback
    """
    # Use global error handler if none provided
    if error_handler is None:
        error_handler = get_global_error_handler()

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                error_info = error_handler.handle_error(
                    e,
                    context={"function": func.__name__},
                    user_message=user_message,
                    log_traceback=log_traceback,
                )

                if raise_on_error:
                    raise

                return return_on_error if return_on_error is not None else error_info

        return wrapper

    return decorator


# Global error handler instance
_global_error_handler: Optional[ErrorHandler] = None
_global_error_handler_lock = Lock()


def get_global_error_handler() -> ErrorHandler:
    """
    Get the global error handler instance with thread-safe initialization.

    Returns:
        Global ErrorHandler instance
    """
    global _global_error_handler

    if _global_error_handler is None:
        with _global_error_handler_lock:
            # Double-check locking
            if _global_error_handler is None:
                _global_error_handler = ErrorHandler()

    return _global_error_handler
