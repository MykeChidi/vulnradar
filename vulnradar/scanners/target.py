# vulnradar/scanners/target.py

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScanTarget:
    """
    Lightweight target descriptor for scanner modules only.
    Design boundary (enforced by convention, not code).
    """

    url: str
    hostname: str
    scheme: str
    port: int
    is_https: bool
    technologies: dict = field(default_factory=dict)

    @classmethod
    def from_url(cls, url: str) -> "ScanTarget":
        """Build a ScanTarget from a raw URL string. No DNS lookup performed."""
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        is_https = scheme == "https"
        port = parsed.port or (443 if is_https else 80)
        return cls(
            url=url,
            hostname=parsed.hostname or "",
            scheme=scheme,
            port=port,
            is_https=is_https,
        )

    @property
    def base_url(self) -> str:
        """Return scheme://hostname:port with no path component."""
        return f"{self.scheme}://{self.hostname}:{self.port}"
