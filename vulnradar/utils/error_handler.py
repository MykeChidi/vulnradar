# vulnradar/utils/error_handler.py - Secure Error Handling Module

import functools
import traceback
import re
from enum import Enum
from threading import Lock
from collections import defaultdict
from time import time 
from typing import Any, Callable, Dict, Optional
from pathlib import Path
from colorama import Fore, Style

from .logger import setup_logger

# Initialize logger
logger = setup_logger("Error_logs")


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
        context: Optional[Dict[str, Any]] = None
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
        kwargs['category'] = ErrorCategory.NETWORK
        super().__init__(message, **kwargs)


class AuthenticationError(VulnRadarError):
    """Authentication-related errors"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.AUTHENTICATION
        kwargs['severity'] = kwargs.get('severity', ErrorSeverity.HIGH)
        super().__init__(message, **kwargs)


class ValidationError(VulnRadarError):
    """Input validation errors"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.VALIDATION
        super().__init__(message, **kwargs)


class AccessError(VulnRadarError):
    """Permission/authorization errors"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.PERMISSION
        kwargs['severity'] = kwargs.get('severity', ErrorSeverity.HIGH)
        super().__init__(message, **kwargs)


class ResourceError(VulnRadarError):
    """Resource-related errors (memory, disk, etc.)"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.RESOURCE
        super().__init__(message, **kwargs)


class ConfigurationError(VulnRadarError):
    """Configuration-related errors"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.CONFIGURATION
        kwargs['severity'] = kwargs.get('severity', ErrorSeverity.HIGH)
        super().__init__(message, **kwargs)


class ScanTimeoutError(VulnRadarError):
    """Timeout-related errors"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.TIMEOUT
        super().__init__(message, **kwargs)


class ParseError(VulnRadarError):
    """Parsing-related errors"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.PARSE
        super().__init__(message, **kwargs)


class DatabaseError(VulnRadarError):
    """Database-related errors"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.DATABASE
        super().__init__(message, **kwargs)


class ScanError(VulnRadarError):
    """Scan execution errors"""
    def __init__(self, message: str, **kwargs):
        kwargs['category'] = ErrorCategory.SCAN
        super().__init__(message, **kwargs)


class ErrorHandler:
    """
    Centralized error handler that manages error logging, 
    user feedback, and secure error reporting.
    """
    
    # Sensitive data patterns to redact from error messages
    SENSITIVE_PATTERNS = [
        (re.compile(r'(password["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
        (re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
        (re.compile(r'(token["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
        (re.compile(r'(secret["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
        (re.compile(r'(auth["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
    ]

    # Path patterns
    PATH_PATTERNS = [
        (re.compile(r'/home/[^/]+/'), '/home/[USER]/'),
        (re.compile(r'C:\\Users\\[^\\]+\\'), r'C:\\Users\[USER]\\'),
    ]
    
    def __init__(self, debug_mode: bool = False, log_file: Optional[Path] = None, rate_limited:bool = True):
        """
        Initialize error handler.
        
        Args:
            debug_mode: If True, show detailed error information
            log_file: Optional file to log errors to
            enable_rate_limiting: If True, prevent log spam from repeated errors
        """
        self.debug_mode = debug_mode
        self.log_file = log_file
        self.rate_limited = rate_limited

        # Thread safe error counting
        self.error_counts: Dict[ErrorCategory, int] = defaultdict(int)
        self._counts_lock = Lock()

        # Rate limiting for repeated errors
        self._recent_errors: Dict[str, float] = {}
        self._rate_limit_lock = Lock()
        
    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        user_message: Optional[str] = None,
        log_traceback: bool = True
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
        
        # Update error counts (thread-safe)
        with self._counts_lock:
            self.error_counts[category] += 1

        # Sanitize error message
        safe_message = self._sanitize_message(message)
        
        # Log the error (with rate limiting if enabled)
        if not self.rate_limited or self._should_log(error):
            self._log_error(error, severity, category, safe_message, context, log_traceback)
        
        # Prepare error response
        error_response = {
            "error": True,
            "message": user_message or self._get_user_message(category, safe_message),
            "severity": severity.value,
            "category": category.value,
            "recoverable": self._is_recoverable(error),
        }
        
        # Add debug info if in debug mode
        if self.debug_mode:
            error_response["debug_info"] = {
                "type": type(error).__name__,
                "original_message": message,
                "context": context,
                "traceback": traceback.format_exc() if log_traceback else None
            }
        
        return error_response
    
    def _classify_error(self, error: Exception) -> tuple[ErrorSeverity, ErrorCategory]:
        """
        Classify an error by severity and category, checking the entire exception chain.
        
        Args:
            error: The exception to classify
            
        Returns:
            Tuple of (severity, category)
        """
        # Check the entire exception chain
        current: Optional[Exception] = error
        while current is not None:
            severity, category = self._classify_single_error(current)
            if category != ErrorCategory.UNKNOWN:
                return severity, category
            current = getattr(current, '__cause__', None) or getattr(current, '__context__', None)
        
        # Default if nothing in chain matches
        return ErrorSeverity.MEDIUM, ErrorCategory.UNKNOWN
    
    def _classify_single_error(self, error: Exception) -> tuple[ErrorSeverity, ErrorCategory]:
        """
        Classify an error by severity and category.
        
        Args:
            error: The exception to classify
            
        Returns:
            Tuple of (severity, category)
        """
        error_type = type(error).__name__
        error_msg = str(error).lower()
        
        # Network errors
        if any(x in error_type.lower() for x in ['connection', 'timeout', 'network']):
            return ErrorSeverity.MEDIUM, ErrorCategory.NETWORK
        
        # Authentication errors
        if any(x in error_msg for x in ['unauthorized', 'forbidden', 'authentication']):
            return ErrorSeverity.HIGH, ErrorCategory.AUTHENTICATION
        
        # Permission errors
        if any(x in error_msg for x in ['permission', 'access denied', 'forbidden']):
            return ErrorSeverity.HIGH, ErrorCategory.PERMISSION
        
        # Validation errors
        if any(x in error_type.lower() for x in ['validation', 'value', 'type']):
            return ErrorSeverity.LOW, ErrorCategory.VALIDATION
        
        # Resource errors
        if any(x in error_msg for x in ['memory', 'disk', 'space', 'resource']):
            return ErrorSeverity.HIGH, ErrorCategory.RESOURCE
        
        # Timeout errors
        if 'timeout' in error_msg:
            return ErrorSeverity.MEDIUM, ErrorCategory.TIMEOUT
        
        # Parse errors
        if any(x in error_type.lower() for x in ['parse', 'json', 'xml', 'decode']):
            return ErrorSeverity.LOW, ErrorCategory.PARSE
        
        # Database errors
        if any(x in error_msg for x in ['database', 'sql', 'query']):
            return ErrorSeverity.HIGH, ErrorCategory.DATABASE
        
        # Default
        return ErrorSeverity.MEDIUM, ErrorCategory.UNKNOWN
    
    def _sanitize_message(self, message: str) -> str:
        """
        Remove sensitive information from error messages.
        
        Args:
            message: Original error message
            
        Returns:
            Sanitized message
        """
        sanitized = message
        
        # Redact sensitive patterns
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        
        # Redact file paths that might contain usernames
        for pattern, replacement in self.PATH_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        
        # Redact IP addresses in some contexts
        if 'internal' in sanitized.lower() or 'private' in sanitized.lower():
            sanitized = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_REDACTED]', sanitized)
        
        return sanitized
    
    def _get_user_message(self, category: ErrorCategory, safe_message: str) -> str:
        """
        Generate a user-friendly error message.
        
        Args:
            category: Error category
            safe_message: Sanitized error message
            
        Returns:
            User-friendly message
        """
        # Default messages for each category
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
        
        base_message = default_messages.get(category, default_messages[ErrorCategory.UNKNOWN])
        
        # If safe_message provides useful info, append it
        if safe_message and len(safe_message) < 200 and not any(
            x in safe_message.lower() for x in ['traceback', 'exception', 'error at']
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
        # Network and timeout errors are usually recoverable
        recoverable_types = [
            'TimeoutError',
            'ConnectionError',
            'ConnectionResetError',
            'BrokenPipeError',
            'ScanTimeoutError'
        ]
        
        if type(error).__name__ in recoverable_types:
            return True
        
        # Check for specific error messages
        error_msg = str(error).lower()
        recoverable_messages = ['timeout', 'temporary', 'retry', 'unavailable']
        
        return any(msg in error_msg for msg in recoverable_messages)
    
    def _should_log(self, error: Exception) -> bool:
        """
        Determine if error should be logged (prevents log spam).
        
        Args:
            error: The exception to check
            
        Returns:
            True if error should be logged
        """
        error_hash = f"{type(error).__name__}:{str(error)[:50]}"
        now = time()
        
        with self._rate_limit_lock:
            if error_hash in self._recent_errors:
                if now - self._recent_errors[error_hash] < 60:  # Within 1 minute
                    return False
            
            self._recent_errors[error_hash] = now
            
            # Clean up old entries (older than 5 minutes)
            cutoff = now - 300
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
        log_traceback: bool
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
        
        # Choose logging level based on severity
        if severity == ErrorSeverity.CRITICAL:
            logger.critical(f"{Fore.RED} {log_msg} {Style.RESET_ALL}")
        elif severity == ErrorSeverity.HIGH:
            logger.error(f"{Fore.RED} {log_msg} {Style.RESET_ALL}")
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning(f"{Fore.YELLOW} {log_msg} {Style.RESET_ALL}")
        else:
            logger.info(f"{Fore.BLUE} {log_msg} {Style.RESET_ALL}")
        
        # Log traceback for high severity errors or in debug mode
        if log_traceback and (severity.value in ['high', 'critical'] or self.debug_mode):
            logger.debug(f"Trace: {traceback.format_exc()}")


class AsyncErrorHandler(ErrorHandler):
    """Async version of ErrorHandler with async context manager support."""
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Handle exceptions in async context manager."""
        if exc_val is not None:
            self.handle_error(exc_val)
            return True  # Suppress exception
        return False
    

def handle_errors(
    error_handler: Optional[ErrorHandler] = None,
    user_message: Optional[str] = None,
    raise_on_error: bool = False,
    return_on_error: Any = None,
    log_traceback: bool = True
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
    if error_handler is None:
        error_handler = ErrorHandler()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_info = error_handler.handle_error(
                    e,
                    context={},
                    user_message=user_message,
                    log_traceback=log_traceback
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
    log_traceback: bool = True
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
    # Ensure we use an AsyncErrorHandler internally
    if error_handler is None:
        error_handler = AsyncErrorHandler()
    elif not isinstance(error_handler, AsyncErrorHandler):
        error_handler = AsyncErrorHandler()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                error_info = error_handler.handle_error(
                    e,
                    context={},
                    user_message=user_message,
                    log_traceback=log_traceback
                )
                
                if raise_on_error:
                    raise
                
                return return_on_error if return_on_error is not None else error_info
        
        return wrapper
    
    return decorator


# Global error handler instance
_global_error_handler = ErrorHandler()


def get_global_error_handler() -> ErrorHandler:
    """Get the global error handler instance."""
    return _global_error_handler
