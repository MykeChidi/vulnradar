# vulnradar/scanners/jwt_scanner.py

from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import Dict, List, Optional, Tuple

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

# Header names and cookie names commonly used to carry JWT tokens.
_JWT_HEADERS: List[str] = [
    "Authorization",
    "X-Auth-Token",
    "X-Access-Token",
    "X-JWT",
    "X-Token",
]
_JWT_COOKIE_NAMES: List[str] = [
    "token",
    "jwt",
    "access_token",
    "id_token",
    "auth_token",
    "session_token",
]

# Pattern that identifies a JWT string: three Base64URL-encoded segments
# separated by dots.
_JWT_PATTERN: re.Pattern[str] = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)

# Field names in the JWT payload that commonly hold sensitive material.
_SENSITIVE_FIELDS: List[str] = [
    "password",
    "passwd",
    "secret",
    "private_key",
    "api_key",
    "token",
    "credentials",
    "ssn",
    "credit_card",
]

# Algorithms considered weak for secret-based tokens.
_WEAK_ALGORITHMS: List[str] = ["HS256", "HS384"]


# ─────────────────────────────────────────────────────────────────────────────
# JWT utilities
# ─────────────────────────────────────────────────────────────────────────────


def _b64url_decode(segment: str) -> bytes:
    """
    Decode a Base64URL-encoded segment without padding.

    Args:
        segment: A Base64URL string (no padding required).

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If decoding fails.
    """
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment)


def _decode_jwt(token: str) -> Optional[Tuple[Dict, Dict]]:
    """
    Decode a JWT token into its header and payload dictionaries.

    Does not verify the signature — this is intentional, as we are
    inspecting the token structure, not authenticating it.

    Args:
        token: A raw JWT string.

    Returns:
        ``(header_dict, payload_dict)`` on success, ``None`` on failure.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload

    except Exception:
        return None


def _build_none_alg_token(token: str):
    """
    Construct a modified JWT with ``alg: none`` and an empty signature.

    The body (payload) is kept identical to the original so that the server
    processes the same claims.

    Args:
        token: Original JWT string.

    Returns:
        Modified JWT string with ``alg: none`` and no signature, or the
        original token if modification fails.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return token

        # Build a new header with alg: none (try both "none" and "None")
        original_header = json.loads(_b64url_decode(parts[0]))
        for alg_value in ("none", "None", "NONE"):
            modified_header = {**original_header, "alg": alg_value}
            encoded_header = (
                base64.urlsafe_b64encode(
                    json.dumps(modified_header, separators=(",", ":")).encode()
                )
                .rstrip(b"=")
                .decode()
            )
            # Empty signature
            yield f"{encoded_header}.{parts[1]}."

    except Exception:
        yield token


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────


class JWTScanner(BaseScanner):
    """Scan for JWT misconfiguration vulnerabilities (CWE-347)."""

    def __init__(
        self,
        headers: Optional[Dict] = None,
        timeout: int = 10,
    ) -> None:
        super().__init__(headers, timeout)

    # ── public: scan ──────────────────────────────────────────────────────

    @handle_async_errors(
        error_handler=error_handler,
        user_message="JWT scan encountered an error",
        return_on_error=[],
    )
    async def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for JWT misconfiguration.

        Args:
            url: Fully-qualified URL to test.

        Returns:
            List of ``Finding`` objects.
        """
        findings: List[Finding] = []

        tokens = await self._collect_tokens(url)
        if not tokens:
            return findings

        for token in tokens:
            decoded = _decode_jwt(token)
            if decoded is None:
                continue

            header, payload = decoded

            # Check 1: alg:none attack
            none_finding = await self._check_alg_none(url, token, header, payload)
            if none_finding:
                findings.append(none_finding)

            # Check 2: sensitive data in payload
            sensitive_findings = self._check_sensitive_data(url, token, payload)
            findings.extend(sensitive_findings)

            # Check 3: weak algorithm
            weak_alg_finding = self._check_weak_algorithm(url, token, header)
            if weak_alg_finding:
                findings.append(weak_alg_finding)

            # Check 4: missing expiry
            exp_finding = self._check_missing_expiry(url, token, payload)
            if exp_finding:
                findings.append(exp_finding)

        return findings

    # ── public: validate ──────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-fetch the URL and confirm the same JWT issue is still present.

        Args:
            url:      URL where the vulnerability was found.
            payload:  The JWT token from the original finding.
            evidence: Evidence string from the original finding.

        Returns:
            True if the issue persists.
        """
        try:
            tokens = await self._collect_tokens(url)
            if not tokens:
                return False

            for token in tokens:
                decoded = _decode_jwt(token)
                if decoded is None:
                    continue
                _, claims = decoded
                # Re-check whichever condition was originally flagged
                if "alg: none" in evidence:
                    result = await self._check_alg_none(url, token, {}, claims)
                    if result:
                        return True
                elif "sensitive" in evidence.lower():
                    findings = self._check_sensitive_data(url, token, claims)
                    if findings:
                        return True
                else:
                    return True

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

        return False

    # ── private: token collection ─────────────────────────────────────────

    async def _collect_tokens(self, url: str) -> List[str]:
        """
        Fetch ``url`` and extract all JWT tokens from the response headers
        and cookies.

        Args:
            url: URL to probe.

        Returns:
            List of raw JWT strings found (may be empty).
        """
        tokens: List[str] = []

        try:
            async with self.session.get(url) as response:
                # Check response headers
                for header_name in _JWT_HEADERS:
                    value = response.headers.get(header_name, "")
                    # Strip "Bearer " prefix if present
                    value = re.sub(r"(?i)^bearer\s+", "", value).strip()
                    for match in _JWT_PATTERN.finditer(value):
                        tokens.append(match.group())

                # Check cookies
                for cookie in response.cookies.values():
                    if cookie.key.lower() in _JWT_COOKIE_NAMES:
                        for match in _JWT_PATTERN.finditer(cookie.value):
                            tokens.append(match.group())

                # Check response body (APIs sometimes embed tokens in JSON)
                body = await self._safe_read(response)
                for match in _JWT_PATTERN.finditer(body):
                    candidate = match.group()
                    if candidate not in tokens:
                        tokens.append(candidate)

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        return tokens

    # ── private: individual checks ────────────────────────────────────────

    async def _check_alg_none(
        self,
        url: str,
        token: str,
        header: Dict,
        payload_claims: Dict,
    ) -> Optional[Finding]:
        """
        Send ``alg: none`` variants of the token and check whether the server
        still returns a successful response (2xx).

        Args:
            url:            Endpoint to test.
            token:          Original JWT string.
            header:         Decoded JWT header.
            payload_claims: Decoded JWT payload claims.

        Returns:
            A ``Finding`` if the attack succeeds, ``None`` otherwise.
        """
        try:
            for modified_token in _build_none_alg_token(token):
                inject_headers = {"Authorization": f"Bearer {modified_token}"}

                async with self.session.get(url, headers=inject_headers) as response:
                    if response.status in range(200, 300):
                        standards = get_standards("JWT Misconfiguration")
                        return Finding(
                            type="JWT Misconfiguration",
                            severity=Severity.CRITICAL,
                            endpoint=url,
                            method="GET",
                            payload=modified_token,
                            evidence=(
                                f"Server returned HTTP {response.status} for a JWT "
                                f"with alg: none and no signature."
                            ),
                            description=(
                                "The server accepted a JWT token with the ``alg`` "
                                "field set to ``none`` and an empty signature. "
                                "This means the server is not verifying the token "
                                "signature. An attacker can forge arbitrary claims "
                                "(e.g. ``admin: true``) without knowing the signing "
                                "secret."
                            ),
                            remediation=(
                                "Reject any JWT whose ``alg`` header is ``none``, "
                                "``None``, or ``NONE``. Enforce a strict allowlist "
                                "of permitted algorithms (e.g. only ``RS256``)."
                            ),
                            **standards,
                        )

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        return None

    def _check_sensitive_data(
        self,
        url: str,
        token: str,
        payload_claims: Dict,
    ) -> List[Finding]:
        """
        Inspect the decoded JWT payload for fields whose names suggest they
        hold sensitive material (passwords, secrets, keys).

        Args:
            url:            Endpoint where the token was collected.
            token:          Original JWT string.
            payload_claims: Decoded JWT payload claims.

        Returns:
            List of ``Finding`` objects (one per sensitive field found).
        """
        findings: List[Finding] = []

        for field_name, field_value in payload_claims.items():
            if field_name.lower() in _SENSITIVE_FIELDS:
                standards = get_standards("JWT Misconfiguration")
                findings.append(
                    Finding(
                        type="JWT Misconfiguration",
                        severity=Severity.HIGH,
                        endpoint=url,
                        method="GET",
                        payload=token[:80] + "..." if len(token) > 80 else token,
                        evidence=(
                            f"JWT payload contains sensitive field: '{field_name}'. "
                            f"JWT payloads are Base64-encoded (not encrypted) and "
                            f"readable by anyone who holds the token."
                        ),
                        description=(
                            f"The JWT token payload contains a field named '{field_name}' "
                            "which may contain sensitive data. JWT payloads are only "
                            "Base64-encoded, not encrypted. Any party that receives the "
                            "token can decode and read the payload without the signing key."
                        ),
                        remediation=(
                            f"Remove sensitive fields (such as '{field_name}') from JWT "
                            "payloads. If sensitive data must travel in a token, use JWE "
                            "(JSON Web Encryption) instead of JWS (JSON Web Signature)."
                        ),
                        **standards,
                    )
                )

        return findings

    def _check_weak_algorithm(
        self,
        url: str,
        token: str,
        header: Dict,
    ) -> Optional[Finding]:
        """
        Flag tokens signed with HMAC-based algorithms (HS256 / HS384) as
        potentially vulnerable to brute-force if the secret is short.

        Args:
            url:    Endpoint where the token was collected.
            token:  Original JWT string.
            header: Decoded JWT header.

        Returns:
            A ``Finding`` if a weak algorithm is detected, ``None`` otherwise.
        """
        alg = header.get("alg", "")

        if alg not in _WEAK_ALGORITHMS:
            return None

        standards = get_standards("JWT Misconfiguration")
        return Finding(
            type="JWT Misconfiguration",
            severity=Severity.LOW,
            endpoint=url,
            method="GET",
            payload=token[:80] + "..." if len(token) > 80 else token,
            evidence=f"JWT header: alg={alg}",
            description=(
                f"The JWT token uses the ``{alg}`` algorithm, which relies on a "
                "symmetric shared secret. If the secret is short or predictable "
                "it can be recovered by offline brute-force. Additionally, "
                "symmetric algorithms require the secret to be shared with every "
                "service that validates the token, widening the attack surface."
            ),
            remediation=(
                "Prefer asymmetric algorithms such as ``RS256`` or ``ES256``. "
                "If HMAC must be used, ensure the secret is at least 256 bits "
                "of cryptographically random data."
            ),
            tags=[alg],
            **standards,
        )

    def _check_missing_expiry(
        self,
        url: str,
        token: str,
        payload_claims: Dict,
    ) -> Optional[Finding]:
        """
        Flag tokens that carry no ``exp`` (expiry) claim.

        Args:
            url:            Endpoint where the token was collected.
            token:          Original JWT string.
            payload_claims: Decoded JWT payload claims.

        Returns:
            A ``Finding`` if ``exp`` is absent, ``None`` otherwise.
        """
        if "exp" in payload_claims:
            return None

        standards = get_standards("JWT Misconfiguration")
        return Finding(
            type="JWT Misconfiguration",
            severity=Severity.MEDIUM,
            endpoint=url,
            method="GET",
            payload=token[:80] + "..." if len(token) > 80 else token,
            evidence="JWT payload has no 'exp' (expiry) claim.",
            description=(
                "The JWT token does not contain an ``exp`` claim. "
                "Without an expiry the token is valid indefinitely. "
                "If the token is stolen or leaked through logs, error "
                "messages, or a data breach, the attacker can use it "
                "forever without the ability to invalidate it server-side."
            ),
            remediation=(
                "Always include an ``exp`` claim in every JWT. "
                "Choose the shortest lifetime that satisfies your use-case "
                "(e.g. 15 minutes for access tokens, 7 days for refresh "
                "tokens). Validate the ``exp`` claim on every request."
            ),
            **standards,
        )
