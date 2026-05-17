# vulnradar/scanners/open_redirect.py

from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp

from ..models.finding import Finding
from ..models.severity import Severity
from ..models.standards import get_standards
from ..utils.error_handler import get_global_error_handler, handle_async_errors
from . import payloads
from .base import BaseScanner

error_handler = get_global_error_handler()

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Canary domain used in all redirect payloads.  Must not resolve to a real
# service — we only check whether it appears in the response chain.
_CANARY_DOMAIN: str = "vulnradar-canary.example.com"
_CANARY_URL: str = f"https://{_CANARY_DOMAIN}"

# Patterns that confirm an unvalidated redirect has occurred.
_LOCATION_PATTERN: re.Pattern[str] = re.compile(
    r"https?://" + re.escape(_CANARY_DOMAIN),
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────


class OpenRedirectScanner(BaseScanner):
    """Scan for open redirect vulnerabilities (CWE-601)."""

    def __init__(
        self,
        headers: Optional[Dict] = None,
        timeout: int = 10,
    ) -> None:
        super().__init__(headers, timeout)

    # ── public: scan ──────────────────────────────────────────────────────

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Open redirect scan encountered an error",
        return_on_error=[],
    )
    async def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for open redirect vulnerabilities.

        Args:
            url: Fully-qualified URL to test.

        Returns:
            List of ``Finding`` objects, one per confirmed redirect parameter.
        """
        findings: List[Finding] = []

        redirect_params = self._extract_redirect_params(url)
        if not redirect_params:
            return findings

        for param_name in redirect_params:
            finding = await self._test_redirect_param(url, param_name)
            if finding is not None:
                findings.append(finding)

        return findings

    # ── public: validate ──────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-inject the canary URL into the parameter named in the payload
        and confirm the redirect still occurs.

        Args:
            url:      URL where the vulnerability was originally found.
            payload:  The injected URL from the original finding.
            evidence: The Location header value from the original finding.

        Returns:
            True if the redirect is still present.
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            # Find a redirect param in the URL
            redirect_param = next(
                (p for p in params if p.lower() in payloads.open_redirect_params), None
            )
            if redirect_param is None:
                return bool(_CANARY_DOMAIN in evidence)

            params[redirect_param] = [_CANARY_URL]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            async with self.session.get(test_url, allow_redirects=False) as response:
                location = response.headers.get("Location", "")
                return _LOCATION_PATTERN.search(location) is not None

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    # ── private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _extract_redirect_params(url: str) -> List[str]:
        """
        Return the names of query parameters in ``url`` that match the known
        redirect-parameter list.

        Args:
            url: URL to inspect.

        Returns:
            List of matching parameter names (may be empty).
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            return [p for p in params if p.lower() in payloads.open_redirect_params]
        except Exception:
            return []

    async def _test_redirect_param(
        self,
        url: str,
        param_name: str,
    ) -> Optional[Finding]:
        """
        Inject the canary URL into ``param_name`` and check for an
        unvalidated redirect.

        Args:
            url:        Base URL under test.
            param_name: Name of the parameter to inject into.

        Returns:
            A ``Finding`` if the redirect is confirmed, ``None`` otherwise.
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param_name] = [_CANARY_URL]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            async with self.session.get(
                test_url,
                allow_redirects=False,  # inspect the raw redirect, not the destination
            ) as response:
                location = response.headers.get("Location", "")

                if not _LOCATION_PATTERN.search(location):
                    return None

                standards = get_standards("Open Redirect")
                return Finding(
                    type="Open Redirect",
                    severity=Severity.MEDIUM,
                    endpoint=url,
                    parameter=param_name,
                    method="GET",
                    payload=_CANARY_URL,
                    evidence=(
                        f"Parameter '{param_name}' caused an unvalidated redirect. "
                        f"Location header: {location}"
                    ),
                    description=(
                        f"The parameter '{param_name}' accepts an arbitrary URL and "
                        "redirects the user to it without validation. An attacker can "
                        "craft a link that appears to point to a legitimate site but "
                        "delivers the user to a phishing or malware page."
                    ),
                    remediation=(
                        "Maintain a server-side allowlist of permitted redirect "
                        "destinations. Reject or sanitise any redirect URL whose "
                        "host does not appear on the allowlist. Never forward raw "
                        "user input as a Location header value."
                    ),
                    **standards,
                )

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
