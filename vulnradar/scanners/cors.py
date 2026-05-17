# vulnradar/scanners/cors.py

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

import aiohttp

from ..models.finding import Finding
from ..models.severity import Severity
from ..models.standards import get_standards
from ..utils.error_handler import get_global_error_handler, handle_async_errors
from .base import BaseScanner

error_handler = get_global_error_handler()

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Origin values injected in turn to test reflection.
_ATTACKER_ORIGINS: List[str] = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",  # Some servers reflect null — allows same-site iframe attacks
]

# The ``Origin`` that looks like a subdomain bypass attempt.
_SUBDOMAIN_BYPASS: str = "https://target.evil.com"

# CORS-related headers we inspect.
_ACAO_HEADER = "Access-Control-Allow-Origin"
_ACAC_HEADER = "Access-Control-Allow-Credentials"


class CORSScanner(BaseScanner):
    """Scan for CORS misconfiguration vulnerabilities (CWE-942)."""

    def __init__(
        self,
        headers: Optional[Dict] = None,
        timeout: int = 10,
    ) -> None:
        super().__init__(headers, timeout)

    # ── public: scan ──────────────────────────────────────────────────────

    @handle_async_errors(
        error_handler=error_handler,
        user_message="CORS scan encountered an error",
        return_on_error=[],
    )
    async def scan(self, url: str) -> List[Finding]:
        """
        Run CORS misconfiguration checks on a single URL.

        Args:
            url: Fully-qualified URL to test.

        Returns:
            List of ``Finding`` objects.
        """
        findings: List[Finding] = []

        # Test 1: wildcard origin
        finding = await self._check_wildcard_origin(url)
        if finding:
            findings.append(finding)
            # Wildcard already covers origin reflection — skip subsequent tests
            return findings

        # Test 2: origin reflection for each attacker-controlled origin
        for origin in _ATTACKER_ORIGINS:
            finding = await self._check_reflected_origin(url, origin)
            if finding:
                findings.append(finding)

        return findings

    # ── public: validate ──────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-send the injected ``Origin`` header and confirm the server still
        reflects it.

        Args:
            url:      URL where the misconfiguration was found.
            payload:  The ``Origin`` value that was injected (from the finding).
            evidence: The ``ACAO`` header value from the original finding.

        Returns:
            True if the CORS misconfiguration is still present.
        """
        try:
            inject_origin = payload if payload else _ATTACKER_ORIGINS[0]
            async with self.session.get(
                url, headers={"Origin": inject_origin}
            ) as response:
                acao = response.headers.get(_ACAO_HEADER, "")
                return acao in ("*", inject_origin)

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    # ── private helpers ───────────────────────────────────────────────────

    async def _check_wildcard_origin(self, url: str) -> Optional[Finding]:
        """
        Check whether the endpoint returns ``Access-Control-Allow-Origin: *``
        with ``Access-Control-Allow-Credentials: true``.

        ``* + credentials`` is always a misconfiguration (browsers will refuse
        to honour it, but some older HTTP clients will not).

        A wildcard alone is ``Low`` severity; combined with credentials it is
        ``Critical``.
        """
        try:
            async with self.session.get(
                url, headers={"Origin": "https://vulnradar-probe.example.com"}
            ) as response:
                acao = response.headers.get(_ACAO_HEADER, "")
                acac = response.headers.get(_ACAC_HEADER, "").lower()

                if acao != "*":
                    return None

                credentials_allowed = acac == "true"
                severity = Severity.CRITICAL if credentials_allowed else Severity.LOW

                standards = get_standards("CORS Misconfiguration")
                return Finding(
                    type="CORS Misconfiguration",
                    severity=severity,
                    endpoint=url,
                    method="GET",
                    payload="Origin: https://vulnradar-probe.example.com",
                    evidence=(
                        f"{_ACAO_HEADER}: {acao} | "
                        f"{_ACAC_HEADER}: {acac or 'not set'}"
                    ),
                    description=(
                        "The endpoint returns a wildcard CORS policy "
                        f"(``{_ACAO_HEADER}: *``). "
                        + (
                            "Combined with ``Access-Control-Allow-Credentials: true`` "
                            "this allows any origin to make credentialed cross-origin "
                            "requests, potentially exposing session tokens and user data."
                            if credentials_allowed
                            else "This allows any origin to read the response body, "
                            "which may expose sensitive data to attacker-controlled pages."
                        )
                    ),
                    remediation=(
                        "Replace the wildcard with an explicit allowlist of trusted "
                        "origins. Never combine ``Access-Control-Allow-Origin: *`` "
                        "with ``Access-Control-Allow-Credentials: true``."
                    ),
                    **standards,
                )

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None

    async def _check_reflected_origin(
        self,
        url: str,
        inject_origin: str,
    ) -> Optional[Finding]:
        """
        Inject a controlled ``Origin`` header and check whether the server
        reflects it back verbatim in ``Access-Control-Allow-Origin``.

        Reflected origin + credentials allowed → ``High``
        Reflected origin alone → ``Medium``

        Args:
            url:           URL to probe.
            inject_origin: Attacker-controlled origin string to inject.
        """
        try:
            async with self.session.get(
                url, headers={"Origin": inject_origin}
            ) as response:
                acao = response.headers.get(_ACAO_HEADER, "")
                acac = response.headers.get(_ACAC_HEADER, "").lower()

                if acao != inject_origin:
                    return None

                credentials_allowed = acac == "true"
                severity = Severity.HIGH if credentials_allowed else Severity.MEDIUM

                standards = get_standards("CORS Misconfiguration")
                return Finding(
                    type="CORS Misconfiguration",
                    severity=severity,
                    endpoint=url,
                    method="GET",
                    payload=f"Origin: {inject_origin}",
                    evidence=(
                        f"{_ACAO_HEADER}: {acao} | "
                        f"{_ACAC_HEADER}: {acac or 'not set'}"
                    ),
                    description=(
                        f"The endpoint reflects the attacker-controlled origin "
                        f"``{inject_origin}`` in ``{_ACAO_HEADER}``. "
                        + (
                            "Because ``Access-Control-Allow-Credentials: true`` is "
                            "also set, an attacker can make credentialed cross-origin "
                            "requests from any page they control, gaining access to "
                            "authenticated API responses, session tokens, and user data."
                            if credentials_allowed
                            else "An attacker can read non-credentialed responses from a "
                            "page they control, potentially exposing sensitive data."
                        )
                    ),
                    remediation=(
                        "Validate the ``Origin`` header against a server-side "
                        "allowlist of trusted domains before echoing it into "
                        "``Access-Control-Allow-Origin``. "
                        "Do not trust the ``Origin`` header blindly."
                    ),
                    **standards,
                )

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
