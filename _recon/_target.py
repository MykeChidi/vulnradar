# vulnscan/_recon/_target.py - ReconTarget class for managing target information in vulnerability scans.
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
from utils.logger import setup_logger


# Initialize logger
logger = setup_logger("recon", log_to_file=False)

@dataclass
class ReconTarget:
    """Data class to store target information"""
    url: str
    hostname: str
    ip: Optional[str] = None
    port: int = 80
    is_https: bool = False

    def __post_init__(self):
        # Validate URL format
        parsed = urlparse(self.url)
        if not parsed.scheme or not parsed.netloc:
            logger.error(f"Invalid URL: {self.url}")
        
        # Validate port range
        if not 1 <= self.port <= 65535:
            logger.error(f"Invalid port: {self.port}")
