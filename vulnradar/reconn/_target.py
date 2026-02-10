# vulnradar/reconn/_target.py - ReconTarget class for managing target information in vulnerability scans.
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from ..utils.error_handler import ValidationError, get_global_error_handler
from ..utils.logger import setup_logger

# Initialize logger and error handler
logger = setup_logger("recon", log_to_file=False)
error_handler = get_global_error_handler()


@dataclass
class ReconTarget:
    """Data class to store target information"""

    url: str
    hostname: str
    ip: Optional[str] = None
    port: int = 80
    is_https: bool = False

    def __post_init__(self):
        """Validate all target attributes."""
        try:
            # Validate URL format
            parsed = urlparse(self.url)
            if not parsed.scheme or not parsed.netloc:
                error_msg = f"Invalid URL format: {self.url}"
                logger.error(error_msg)
                error_handler.handle_error(
                    ValidationError(error_msg),
                    context={"url": self.url, "validation_type": "url_format"},
                )
                raise ValueError(error_msg)

            # Validate scheme
            if parsed.scheme not in ["http", "https"]:
                error_msg = (
                    f"Invalid URL scheme: {parsed.scheme}. Must be http or https"
                )
                logger.error(error_msg)
                error_handler.handle_error(
                    ValidationError(error_msg),
                    context={"scheme": parsed.scheme, "validation_type": "scheme"},
                )
                raise ValueError(error_msg)

            # Validate port range
            if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
                error_msg = (
                    f"Invalid port: {self.port}. Must be integer between 1-65535"
                )
                logger.error(error_msg)
                error_handler.handle_error(
                    ValidationError(error_msg),
                    context={"port": self.port, "validation_type": "port_range"},
                )
                raise ValueError(error_msg)

            # Validate hostname
            if not self.hostname:
                error_msg = "Hostname cannot be empty"
                logger.error(error_msg)
                error_handler.handle_error(
                    ValidationError(error_msg),
                    context={"validation_type": "hostname_empty"},
                )
                raise ValueError(error_msg)

            logger.debug(f"Target validated: {self.url}")
        except ValueError:
            raise
