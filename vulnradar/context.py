# vulnradar/context.py

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

import aiohttp

from .models.finding import Finding
from .scanners.target import ScanTarget
from .utils.cache import ScanCache
from .utils.rate_limit import RateLimiter

if TYPE_CHECKING:
    from .auth.base import BaseAuthProvider  # type: ignore[import]


@dataclass
class ScanContext:
    """
    Shared state and shared async resources for a single scan run.

    VulnRadar creates one ScanContext per scan and passes it into every
    scanner via BaseScanner.attach_context().  No scanner creates its own
    aiohttp.ClientSession, Semaphore, or RateLimiter.
    """

    # Identity
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: ScanTarget = field(default=None)  # type: ignore[assignment]
    options: dict = field(default_factory=dict)

    # Shared async resources — set by VulnRadar before passing to scanners
    session: aiohttp.ClientSession = field(repr=False, default=None)  # type: ignore[assignment]
    semaphore: asyncio.Semaphore = field(repr=False, default=None)  # type: ignore[assignment]
    rate_limiter: RateLimiter = field(repr=False, default=None)  # type: ignore[assignment]

    # Accumulated scan state
    findings: list[Finding] = field(default_factory=list)
    endpoints: set[str] = field(default_factory=set)
    technologies: dict = field(default_factory=dict)

    # Optional components (None until the relevant phase is implemented)
    cache: Optional[ScanCache] = None
    auth_provider: Optional["BaseAuthProvider"] = None  # populated in Phase 3

    def add_finding(self, finding: Finding) -> None:
        """Stamp the scan_id on the finding and append it to the findings list."""
        finding.scan_id = self.scan_id
        self.findings.append(finding)

    def add_endpoint(self, url: str) -> None:
        self.endpoints.add(url)

    async def ensure_authenticated(self) -> None:
        """
        Re-authenticate if the session has expired.
        No-op if no auth provider is configured (Phase 3 concern).
        """
        if self.auth_provider is not None:
            if not await self.auth_provider.is_authenticated(self.session):
                success = await self.auth_provider.reauthenticate(self.session)
                if not success:
                    raise RuntimeError("Re-authentication failed mid-scan")
