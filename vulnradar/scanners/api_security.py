# vulnradar/scanners/api_security.py

import asyncio
import json
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from ..utils.error_handler import ScanError, get_global_error_handler
from . import payloads
from .contextual import ContextualScanner, EndpointContext

error_handler = get_global_error_handler()


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITING CHECK PARAMETERS
# ─────────────────────────────────────────────────────────────────────────────

# How many requests to send in the rate-limit test
_RATE_LIMIT_REQUEST_COUNT = 20

# Time window (seconds) to send them in
_RATE_LIMIT_TIME_WINDOW = 5

# If more than this many succeed with 200, there's no rate limiting
_RATE_LIMIT_SUCCESS_THRESHOLD = 18  # Allow 2 failures for network jitter


# ─────────────────────────────────────────────────────────────────────────────
# EXCESSIVE DATA EXPOSURE THRESHOLD
# ─────────────────────────────────────────────────────────────────────────────

# If authenticated response is this many bytes larger than unauthenticated,
# flag it as excessive data exposure
_EXCESSIVE_DATA_THRESHOLD = 10240  # 10KB


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────


class APISecurityScanner(ContextualScanner):
    """Scan for API-specific security vulnerabilities."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    # ── public: discover ──────────────────────────────────────────────────

    async def discover(self, urls: List[str]) -> EndpointContext:
        """
        Classify endpoints and build baseline data for API security checks.

        Reuses IDOR's _classify_endpoints to find API patterns, then probes
        each to determine:
          - Response size (for excessive data exposure detection)
          - Whether it requires authentication (for missing auth detection)
          - Whether it's rate-limited (for rate limiting detection)

        Populates self.context with:
          - api_endpoints: {url: {size: int, requires_auth: bool, rate_limited: bool}}
          - non_production_endpoints: [url, ...]
        """
        # Initialize context
        self.context = EndpointContext(
            id_endpoints={},
            schemas={},
            methods={},
        )
        # Add API-specific context fields
        self.context.api_endpoints = {}
        self.context.non_production_endpoints = []

        # Classify endpoints using IDOR's pattern detection
        self._classify_endpoints(urls)

        # Identify non-production endpoints
        for url in urls:
            path = urlparse(url).path.lower()
            if any(pattern in path for pattern in payloads.api_non_production_patterns):
                self.context.non_production_endpoints.append(url)

        # Probe each potential API endpoint
        api_candidates = []
        for url in urls:
            path = urlparse(url).path.lower()
            # Consider it an API if it has /api/, /v[0-9]/, or is JSON-like
            if (
                "/api/" in path
                or any(f"/v{i}/" in path for i in range(10))
                or url in self.context.id_endpoints
            ):
                api_candidates.append(url)

        for url in api_candidates:
            # Probe to determine baseline characteristics
            result = await self._probe_endpoint(url)
            if result:
                self.context.api_endpoints[url] = result

        return self.context

    # ── public: scan ──────────────────────────────────────────────────────

    async def scan(self, url: str) -> List[Dict]:
        """
        Run four API security checks on a single URL.

        Only runs if the URL is in our api_endpoints map (discovered during
        the discover() phase).
        """
        if not self.context or not self.context.api_endpoints:
            return []

        # Skip URLs we didn't identify as APIs during discovery
        if url not in self.context.api_endpoints:
            return []

        findings: List[Dict] = []
        baseline = self.context.api_endpoints[url]

        try:
            # Check 1: Missing rate limiting
            findings.extend(await self._check_rate_limiting(url))

            # Check 2: Excessive data exposure
            findings.extend(await self._check_excessive_data(url, baseline))

            # Check 3: Missing endpoint authentication
            findings.extend(await self._check_missing_auth(url, baseline))

            # Check 4: Improper asset management (non-production endpoints)
            if url in self.context.non_production_endpoints:
                findings.extend(await self._check_non_production(url))

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"APISecurityScanner error on {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return findings

    # ── public: validate ──────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-run the specific check that triggered the original finding.

        payload is JSON: {
            "check_type": "rate_limiting" | "excessive_data" | "missing_auth" | "non_production",
            "threshold": (for rate_limiting, excessive_data),
            ... (check-specific fields)
        }
        """
        try:
            meta = json.loads(payload)
            check_type = meta["check_type"]

            if check_type == "rate_limiting":
                # Re-test rate limiting
                findings = await self._check_rate_limiting(url)
                return len(findings) > 0

            elif check_type == "excessive_data":
                # Re-test data exposure
                baseline = {"size": meta.get("baseline_size", 0)}
                findings = await self._check_excessive_data(url, baseline)
                return len(findings) > 0

            elif check_type == "missing_auth":
                # Re-test missing auth
                baseline = {"requires_auth": meta.get("requires_auth", True)}
                findings = await self._check_missing_auth(url, baseline)
                return len(findings) > 0

            elif check_type == "non_production":
                # Re-test non-production detection
                findings = await self._check_non_production(url)
                return len(findings) > 0

            return bool(evidence)

        except (json.JSONDecodeError, KeyError):
            return bool(evidence)

    # ── private: discovery helpers ────────────────────────────────────────

    async def _probe_endpoint(self, url: str) -> Optional[Dict]:
        """
        Probe an endpoint to determine baseline characteristics.

        Returns: {
            "size": response body length,
            "requires_auth": whether it returns 401/403 without auth,
            "rate_limited": whether initial probe got rate-limited
        }
        """
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                async with session.get(url) as response:
                    body = await self._safe_read(response)
                    return {
                        "size": len(body),
                        "requires_auth": response.status in (401, 403),
                        "rate_limited": response.status == 429,
                    }

        except Exception:
            return None

    # ── private: check 1 — rate limiting ──────────────────────────────────

    async def _check_rate_limiting(self, url: str) -> List[Dict]:
        """
        Send 20 rapid requests to test for rate limiting.

        If more than 18 succeed with 200, there's no rate limiting.
        """
        findings = []

        try:
            start_time = time.time()
            tasks = []

            # Fire 20 requests concurrently
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                for _ in range(_RATE_LIMIT_REQUEST_COUNT):
                    tasks.append(session.get(url))

                responses = await asyncio.gather(*tasks, return_exceptions=True)

            elapsed = time.time() - start_time

            # Count successes
            success_count = 0
            for r in responses:
                if isinstance(r, aiohttp.ClientResponse) and r.status == 200:
                    success_count += 1

            # If we sent 20 requests in <5 seconds and most succeeded, no rate limit
            if (
                elapsed <= _RATE_LIMIT_TIME_WINDOW
                and success_count >= _RATE_LIMIT_SUCCESS_THRESHOLD
            ):
                findings.append(
                    {
                        "type": "API Security",
                        "endpoint": url,
                        "severity": "Medium",
                        "description": (
                            f"Missing rate limiting detected on API endpoint. Sent {_RATE_LIMIT_REQUEST_COUNT} "
                            f"requests in {elapsed:.2f} seconds, {success_count} succeeded with 200 status. "
                            f"No rate limiting (429 Too Many Requests) was enforced. This enables "
                            f"brute force attacks, enumeration, and denial of service."
                        ),
                        "evidence": (
                            f"Rapid-fire test: {_RATE_LIMIT_REQUEST_COUNT} requests to {url} in "
                            f"{elapsed:.2f}s. Success rate: {success_count}/{_RATE_LIMIT_REQUEST_COUNT}. "
                            f"Expected: rate limiting (429) after ~10-15 requests. Observed: no throttling."
                        ),
                        "remediation": (
                            "Implement rate limiting on all API endpoints. Use algorithms like "
                            "token bucket or sliding window. Recommended limits: 60-100 requests/minute "
                            "per IP or API key. Return 429 Too Many Requests with Retry-After header "
                            "when limits are exceeded."
                        ),
                        "payload": json.dumps(
                            {
                                "check_type": "rate_limiting",
                                "request_count": _RATE_LIMIT_REQUEST_COUNT,
                                "time_window": _RATE_LIMIT_TIME_WINDOW,
                                "success_count": success_count,
                                "elapsed": elapsed,
                            }
                        ),
                    }
                )

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"Rate limiting check failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return findings

    # ── private: check 2 — excessive data exposure ────────────────────────

    async def _check_excessive_data(self, url: str, baseline: Dict) -> List[Dict]:
        """
        Compare authenticated vs unauthenticated response sizes.

        If authenticated response is >10KB larger, flag excessive data exposure.
        """
        findings = []

        try:
            # Get authenticated response (with our headers)
            auth_result = await self._fetch_with_auth(url)
            if not auth_result:
                return []
            auth_status, auth_body = auth_result
            auth_size = len(auth_body)

            # Get unauthenticated response (no headers)
            unauth_result = await self._fetch_without_auth(url)
            if not unauth_result:
                return []
            unauth_status, unauth_body = unauth_result
            unauth_size = len(unauth_body)

            # If authenticated response is substantially larger, flag it
            size_diff = auth_size - unauth_size
            if size_diff > _EXCESSIVE_DATA_THRESHOLD:
                findings.append(
                    {
                        "type": "API Security",
                        "endpoint": url,
                        "severity": "High",
                        "description": (
                            f"Excessive data exposure detected. Authenticated response is {size_diff} "
                            f"bytes larger than unauthenticated response ({auth_size} vs {unauth_size}). "
                            f"The API may be returning sensitive fields (password_hash, SSN, internal IDs) "
                            f"that should be filtered. Only return data the client needs."
                        ),
                        "evidence": (
                            f"GET {url} with authentication returned {auth_size} bytes. "
                            f"Same request without authentication returned {unauth_size} bytes. "
                            f"Difference: {size_diff} bytes (>{_EXCESSIVE_DATA_THRESHOLD} threshold). "
                            f"Likely exposing sensitive fields unnecessarily."
                        ),
                        "remediation": (
                            "Implement field filtering in API responses. Use DTOs (Data Transfer Objects) "
                            "to explicitly define which fields are exposed. Never return password_hash, "
                            "tokens, internal IDs, or PII unless specifically requested. Use GraphQL-style "
                            "field selection or JSON:API sparse fieldsets."
                        ),
                        "payload": json.dumps(
                            {
                                "check_type": "excessive_data",
                                "auth_size": auth_size,
                                "unauth_size": unauth_size,
                                "size_diff": size_diff,
                                "baseline_size": baseline.get("size", 0),
                            }
                        ),
                    }
                )

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"Excessive data check failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return findings

    # ── private: check 3 — missing endpoint authentication ────────────────

    async def _check_missing_auth(self, url: str, baseline: Dict) -> List[Dict]:
        """
        Test if endpoint responds to unauthenticated requests.

        If baseline says it requires auth but unauth request returns 200 with
        real data, the endpoint is missing authentication.
        """
        findings = []

        # Only test endpoints that we believe should require auth
        if not baseline.get("requires_auth", False):
            return []

        try:
            # Send request without authentication
            result = await self._fetch_without_auth(url)
            if not result:
                return []

            status, body = result

            # If it returns 200 with substantial data, auth is missing
            if status == 200 and len(body) > 100:
                findings.append(
                    {
                        "type": "API Security",
                        "endpoint": url,
                        "severity": "Critical",
                        "description": (
                            f"Missing endpoint authentication detected. API endpoint {url} "
                            f"returned 200 OK with {len(body)} bytes of data without any "
                            f"authentication headers. This endpoint should require authentication "
                            f"but accepts unauthenticated requests. Attackers can access sensitive "
                            f"data without credentials."
                        ),
                        "evidence": (
                            f"GET {url} without Authorization header returned status 200 with "
                            f"{len(body)} bytes of response data. Expected: 401 Unauthorized or "
                            f"403 Forbidden. Observed: full response returned to unauthenticated client."
                        ),
                        "remediation": (
                            "Enforce authentication on all sensitive API endpoints. Verify JWT/OAuth "
                            "tokens, API keys, or session cookies before processing requests. Return "
                            "401 Unauthorized for missing credentials, 403 Forbidden for invalid ones. "
                            "Never assume clients will 'just know' to send auth headers."
                        ),
                        "payload": json.dumps(
                            {
                                "check_type": "missing_auth",
                                "status": status,
                                "body_length": len(body),
                                "requires_auth": baseline.get("requires_auth", False),
                            }
                        ),
                    }
                )

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"Missing auth check failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return findings

    # ── private: check 4 — improper asset management ──────────────────────

    async def _check_non_production(self, url: str) -> List[Dict]:
        """
        Flag non-production API endpoints (dev, test, staging, etc.).

        These often have weaker security controls and expose internal functionality.
        """
        findings = []

        try:
            # Test if the endpoint is actually accessible
            result = await self._fetch_with_auth(url)
            if not result:
                return []

            status, body = result

            # If it returns 200 with real data, it's accessible
            if status == 200 and len(body) > 100:
                path = urlparse(url).path
                matched_pattern = next(
                    (
                        p
                        for p in payloads.api_non_production_patterns
                        if p in path.lower()
                    ),
                    "non-production",
                )

                findings.append(
                    {
                        "type": "API Security",
                        "endpoint": url,
                        "severity": "Medium",
                        "description": (
                            f"Improper asset management detected. Non-production API endpoint "
                            f"is publicly accessible: {url}. Path contains '{matched_pattern}', "
                            f"which typically indicates development, testing, or staging environments. "
                            f"These endpoints often have weaker security controls and expose internal "
                            f"functionality or debugging information."
                        ),
                        "evidence": (
                            f"GET {url} returned status 200 with {len(body)} bytes of data. "
                            f"Path pattern '{matched_pattern}' indicates non-production environment. "
                            f"These endpoints should not be exposed in production."
                        ),
                        "remediation": (
                            "Remove or restrict access to non-production API endpoints. Use separate "
                            "subdomains (dev.example.com) with IP whitelisting or VPN access. "
                            "Never deploy development, testing, or staging endpoints to production. "
                            "Document and version all public APIs properly (/api/v1/, /api/v2/). "
                            "Deprecate old versions gracefully."
                        ),
                        "payload": json.dumps(
                            {
                                "check_type": "non_production",
                                "matched_pattern": matched_pattern,
                                "status": status,
                                "body_length": len(body),
                            }
                        ),
                    }
                )

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"Non-production check failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return findings

    # ── private: submission helpers ───────────────────────────────────────

    async def _fetch_with_auth(self, url: str) -> Optional[tuple]:
        """Fetch with authentication headers. Returns (status, body) or None."""
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                async with session.get(url) as response:
                    body = await self._safe_read(response)
                    return (response.status, body)

        except Exception:
            return None

    async def _fetch_without_auth(self, url: str) -> Optional[tuple]:
        """Fetch without authentication headers. Returns (status, body) or None."""
        try:
            # Use empty headers (no Authorization, no cookies)
            async with aiohttp.ClientSession(
                headers={}, timeout=self.timeout
            ) as session:
                async with session.get(url) as response:
                    body = await self._safe_read(response)
                    return (response.status, body)

        except Exception:
            return None
