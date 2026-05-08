# vulnradar/scanners/security_misconfig.py

import json
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

from ..utils.error_handler import NetworkError, ScanError, get_global_error_handler
from . import payloads
from .base import BaseScanner
from . import payloads

error_handler = get_global_error_handler()


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY MISCONFIGURATION CHECKS
#
# Sensitive paths, file lists, and header checks are imported from payloads module
# ─────────────────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────────────────
# SECURITY-HEADER CHECKS
#
# Each entry: (header_name, check_fn, severity, missing_description)
#
# check_fn(value) → (passed: bool, detail: str)
#   value  — the header value, or None if the header is absent
#   passed — True means the header is present and correctly configured
#   detail — appended to the finding evidence when passed is False
# ─────────────────────────────────────────────────────────────────────────────


def _check_hsts(value: Optional[str]) -> Tuple[bool, str]:
    """Strict-Transport-Security must be present with a max-age directive."""
    if value is None:
        return (False, "Header is entirely absent")
    if "max-age" not in value.lower():
        return (False, f"Present but missing max-age directive (value: '{value}')")
    return (True, "")


def _check_x_content_type(value: Optional[str]) -> Tuple[bool, str]:
    """X-Content-Type-Options must be 'nosniff'."""
    if value is None:
        return (False, "Header is entirely absent")
    if value.strip().lower() != "nosniff":
        return (False, f"Value is '{value}' — must be 'nosniff'")
    return (True, "")


def _check_x_frame_options(value: Optional[str]) -> Tuple[bool, str]:
    """X-Frame-Options must be DENY or SAMEORIGIN."""
    if value is None:
        return (False, "Header is entirely absent")
    if value.strip().lower() not in ("deny", "sameorigin"):
        return (False, f"Value is '{value}' — must be DENY or SAMEORIGIN")
    return (True, "")


def _check_csp(value: Optional[str]) -> Tuple[bool, str]:
    """Content-Security-Policy must be present and non-empty."""
    if value is None:
        return (False, "Header is entirely absent")
    if not value.strip():
        return (False, "Header is present but empty")
    return (True, "")


def _check_referrer_policy(value: Optional[str]) -> Tuple[bool, str]:
    """Referrer-Policy must be a recognised safe value."""
    if value is None:
        return (False, "Header is entirely absent")
    safe = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if value.strip().lower() not in safe:
        return (False, f"Value is '{value}' — not a recognised safe policy")
    return (True, "")


def _check_permissions_policy(value: Optional[str]) -> Tuple[bool, str]:
    """Permissions-Policy must be present and non-empty."""
    if value is None:
        return (False, "Header is entirely absent")
    if not value.strip():
        return (False, "Header is present but empty")
    return (True, "")


_HEADER_CHECKS: List[
    Tuple[str, Callable[[Optional[str]], Tuple[bool, str]], str, str]
] = [
    (
        "Strict-Transport-Security",
        _check_hsts,
        "Medium",
        "Missing HSTS allows man-in-the-middle downgrade attacks from HTTPS to HTTP",
    ),
    (
        "X-Content-Type-Options",
        _check_x_content_type,
        "Medium",
        "Missing X-Content-Type-Options allows MIME-sniffing attacks",
    ),
    (
        "X-Frame-Options",
        _check_x_frame_options,
        "Medium",
        "Missing X-Frame-Options allows clickjacking via iFrame embedding",
    ),
    (
        "Content-Security-Policy",
        _check_csp,
        "Medium",
        "Missing CSP allows XSS, inline script injection, and data exfiltration",
    ),
    (
        "Referrer-Policy",
        _check_referrer_policy,
        "Low",
        "Missing Referrer-Policy leaks sensitive URL fragments to third-party sites",
    ),
    (
        "Permissions-Policy",
        _check_permissions_policy,
        "Low",
        "Missing Permissions-Policy leaves browser feature access ungoverned",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────


class SecurityMisconfigScanner(BaseScanner):
    """
    Scan for security misconfigurations.

    Seven independent check categories.  scan() fetches the target URL once,
    runs the header / body checks on that response, then probes sensitive
    paths at the origin.  No payload injection.  No session state.
    """

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    # ── public: scan ──────────────────────────────────────────────────────

    async def scan(self, url: str) -> List[Dict]:
        """
        Run all misconfig checks against a single URL.

        Origin-relative path probes (sensitive files, admin panels, etc.)
        are anchored to scheme://host — not to whatever sub-path scan()
        was called with.
        """
        findings: List[Dict] = []
        origin = self._extract_origin(url)

        try:
            # One fetch for header + body checks
            response_data = await self._fetch(url)
            if response_data is None:
                return []

            status, headers, body = response_data

            # ── checks on the response we already have ────────────────────
            findings.extend(self._check_security_headers(url, headers))
            findings.extend(self._check_directory_listing(url, status, body))
            findings.extend(self._check_verbose_errors(url, status, body))

            # ── checks that probe additional paths at the origin ──────────
            findings.extend(await self._check_exposed_files(origin))
            findings.extend(await self._check_admin_panels(origin))
            findings.extend(await self._check_test_files(origin))
            findings.extend(await self._check_api_docs(origin))

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"SecurityMisconfigScanner error on {url}: {str(e)}",
                    original_error=e,
                ),
                context={"url": url},
            )

        return findings

    # ── public: validate ──────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-fetch the specific URL from the finding and confirm the
        misconfiguration is still present.

        payload is JSON with at minimum:
            check      — which check category produced the finding
            probe_url  — the exact URL that was fetched (may differ from
                         the endpoint if it was a path probe)
        Header-check findings also include header_name so we can re-run
        only that one header's check function.
        """
        try:
            meta = json.loads(payload)
            check = meta.get("check", "")
            probe_url = meta.get("probe_url", url)

            response_data = await self._fetch(probe_url)
            if response_data is None:
                return False

            status, headers, body = response_data

            if check == "security_headers":
                header_name = meta.get("header_name", "")
                for hdr_name, check_fn, _, _ in _HEADER_CHECKS:
                    if hdr_name == header_name:
                        passed, _ = check_fn(headers.get(hdr_name))
                        return not passed  # finding valid ↔ check still fails
                return False

            elif check == "directory_listing":
                body_lo = body.lower()
                return any(ind in body_lo for ind in payloads.security_misconfig_dir_listing_indicators)

            elif check == "verbose_errors":
                body_lo = body.lower()
                return any(
                    pattern in body_lo for pattern, _ in payloads.security_misconfig_verbose_error_indicators
                )

            elif check in ("exposed_file", "admin_panel", "test_file", "api_docs"):
                # Path-probe findings: still valid if the path still returns
                # 200 with a non-trivial body
                return status == 200 and len(body) > 50

            # Unknown check type — trust original evidence
            return bool(evidence)

        except (json.JSONDecodeError, KeyError):
            return bool(evidence)

    # ─── check 1: security headers ────────────────────────────────────────

    def _check_security_headers(self, url: str, headers: Dict[str, str]) -> List[Dict]:
        """
        Run every header check in _HEADER_CHECKS.

        Each failed check is an independent finding.  Fixing one header
        should not require a re-scan to see the others.
        """
        findings: List[Dict] = []

        for header_name, check_fn, severity, missing_desc in _HEADER_CHECKS:
            passed, detail = check_fn(headers.get(header_name))
            if passed:
                continue

            findings.append(
                {
                    "type": "Security Misconfiguration",
                    "endpoint": url,
                    "severity": severity,
                    "description": (
                        f"Missing or weak security header: {header_name}. "
                        f"{missing_desc}."
                    ),
                    "evidence": (
                        f"Response from {url} — {header_name} check: {detail}."
                    ),
                    "remediation": (
                        f"Add or correct the {header_name} header on all responses from "
                        f"this origin. See the OWASP Secure Headers Project for "
                        f"recommended values: "
                        f"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"  # noqa
                    ),
                    "payload": json.dumps(
                        {
                            "check": "security_headers",
                            "probe_url": url,
                            "header_name": header_name,
                        }
                    ),
                }
            )

        return findings

    # ─── check 2: directory listing ────────────────────────────────────────

    def _check_directory_listing(self, url: str, status: int, body: str) -> List[Dict]:
        """
        Detect server-generated directory indexes.

        Only fires on 200 — a 403 or 301 means the server is correctly
        refusing to list.
        """
        if status != 200:
            return []

        body_lo = body.lower()
        for indicator in payloads.security_misconfig_dir_listing_indicators:
            if indicator in body_lo:
                return [
                    {
                        "type": "Security Misconfiguration",
                        "endpoint": url,
                        "severity": "High",
                        "description": (
                            "Directory listing is enabled. The server renders file and "
                            "folder names in the response, exposing the site structure."
                        ),
                        "evidence": (
                            f"Response from {url} (status 200) contains the directory-listing "
                            f"indicator: '{indicator}'."
                        ),
                        "remediation": (
                            "Disable directory listing in your web-server configuration. "
                            "Apache: set 'Options -Indexes' in the relevant Directory block. "
                            "Nginx: remove 'autoindex on;'. "
                            "Always serve an explicit index document or return 403 for "
                            "paths that have no one."
                        ),
                        "payload": json.dumps(
                            {
                                "check": "directory_listing",
                                "probe_url": url,
                            }
                        ),
                    }
                ]

        return []

    # ─── check 3: verbose error pages ─────────────────────────────────────

    def _check_verbose_errors(self, url: str, status: int, body: str) -> List[Dict]:
        """
        Detect stack traces and internal exception details.

        Only fires on 4xx/5xx — a 200 containing "traceback" in normal
        application content would be a false positive.  All matched
        indicators are collected into a single finding so the operator
        sees the full picture at once.
        """
        if status < 400:
            return []

        body_lo = body.lower()
        matched: List[str] = []
        for pattern, label in payloads.security_misconfig_verbose_error_indicators:
            if pattern in body_lo:
                matched.append(label)

        if not matched:
            return []

        return [
            {
                "type": "Security Misconfiguration",
                "endpoint": url,
                "severity": "Medium",
                "description": (
                    "Verbose error page discloses internal stack trace or exception "
                    "details. This information aids attackers in mapping application "
                    "internals, library versions, and file paths."
                ),
                "evidence": (
                    f"Response from {url} (status {status}) contains: "
                    + ", ".join(matched)
                    + "."
                ),
                "remediation": (
                    "Configure custom error pages for all 4xx and 5xx status codes. "
                    "Never expose stack traces, exception class names, or internal file "
                    "paths to end users in production. Set DEBUG=False (Django/Flask), "
                    "or the equivalent flag for your framework."
                ),
                "payload": json.dumps(
                    {
                        "check": "verbose_errors",
                        "probe_url": url,
                    }
                ),
            }
        ]

    # ─── check 4: exposed sensitive files ─────────────────────────────────

    async def _check_exposed_files(self, origin: str) -> List[Dict]:
        """
        Probe every path in the credential, .git, and backup lists.

        A 200 with ≥ 30 bytes of body is a hit.  The threshold filters out
        redirect stub pages and empty responses that some servers return
        with a 200 status.
        """
        findings: List[Dict] = []

        for file_list in (payloads.security_misconfig_credential_files, payloads.security_misconfig_git_exposure, payloads.security_misconfig_backup_files):
            for path, severity, description in file_list:
                probe_url = f"{origin}/{path}"
                result = await self._probe_path(probe_url)
                if result is None:
                    continue

                resp_status, resp_body = result
                if resp_status != 200 or len(resp_body) < 30:
                    continue

                # Truncate body in evidence to keep findings compact
                body_preview = resp_body[:200]

                findings.append(
                    {
                        "type": "Security Misconfiguration",
                        "endpoint": probe_url,
                        "severity": severity,
                        "description": f"Exposed sensitive file: {path} — {description}.",
                        "evidence": (
                            f"GET {probe_url} returned status 200 with {len(resp_body)} bytes. "
                            f"Body preview: {body_preview}"
                        ),
                        "remediation": (
                            f"Remove or deny access to {path}. Add it to your web-server "
                            f"deny rules and to .gitignore. Audit your deployment pipeline "
                            f"to ensure sensitive files are never copied into the document root."
                        ),
                        "payload": json.dumps(
                            {
                                "check": "exposed_file",
                                "probe_url": probe_url,
                            }
                        ),
                    }
                )

        return findings

    # ─── check 5: default admin panels ────────────────────────────────────

    async def _check_admin_panels(self, origin: str) -> List[Dict]:
        """
        Probe well-known admin-panel paths.

        A 200 with > 50 bytes means the panel (or its login page) is
        reachable without prior authentication at the network level.
        A 401/403 means access control is in place — not a finding.
        """
        findings: List[Dict] = []

        for path, severity, description in payloads.security_misconfig_admin_panels:
            probe_url = f"{origin}/{path}"
            result = await self._probe_path(probe_url)
            if result is None:
                continue

            resp_status, resp_body = result
            if resp_status != 200 or len(resp_body) <= 50:
                continue

            findings.append(
                {
                    "type": "Security Misconfiguration",
                    "endpoint": probe_url,
                    "severity": severity,
                    "description": f"Default admin panel is accessible: {path} — {description}.",
                    "evidence": (
                        f"GET {probe_url} returned status 200 with {len(resp_body)} bytes of content."
                    ),
                    "remediation": (
                        "Move the admin panel to a non-default, non-guessable path. "
                        "Restrict access by source-IP whitelist or require VPN. "
                        "Ensure strong authentication (MFA) is enforced on all admin routes."
                    ),
                    "payload": json.dumps(
                        {
                            "check": "admin_panel",
                            "probe_url": probe_url,
                        }
                    ),
                }
            )

        return findings

    # ─── check 6: test / debug files ──────────────────────────────────────

    async def _check_test_files(self, origin: str) -> List[Dict]:
        """
        Probe well-known test, debug, and framework-introspection paths.

        Same 200 + > 50 bytes threshold as admin panels.
        """
        findings: List[Dict] = []

        for path, severity, description in payloads.security_misconfig_test_files:
            probe_url = f"{origin}/{path}"
            result = await self._probe_path(probe_url)
            if result is None:
                continue

            resp_status, resp_body = result
            if resp_status != 200 or len(resp_body) <= 50:
                continue

            findings.append(
                {
                    "type": "Security Misconfiguration",
                    "endpoint": probe_url,
                    "severity": severity,
                    "description": f"Test or debug file is accessible in production: {path} — {description}.",
                    "evidence": (
                        f"GET {probe_url} returned status 200 with {len(resp_body)} bytes of content."
                    ),
                    "remediation": (
                        f"Remove {path} from the production environment. Add test and debug "
                        f"paths to your deployment exclude list. Set up CI/CD pipeline checks "
                        f"that fail if any known-dangerous file is present in the build artefact."
                    ),
                    "payload": json.dumps(
                        {
                            "check": "test_file",
                            "probe_url": probe_url,
                        }
                    ),
                }
            )

        return findings

    # ─── check 7: exposed API documentation ───────────────────────────────

    async def _check_api_docs(self, origin: str) -> List[Dict]:
        """
        Probe well-known API-documentation and introspection paths.

        Exposed API docs in production hand attackers a complete blueprint
        of every endpoint, parameter type, and data structure.
        """
        findings: List[Dict] = []

        for path, severity, description in payloads.security_misconfig_api_docs:
            probe_url = f"{origin}/{path}"
            result = await self._probe_path(probe_url)
            if result is None:
                continue

            resp_status, resp_body = result
            if resp_status != 200 or len(resp_body) <= 50:
                continue

            findings.append(
                {
                    "type": "Security Misconfiguration",
                    "endpoint": probe_url,
                    "severity": severity,
                    "description": f"API documentation is exposed: {path} — {description}.",
                    "evidence": (
                        f"GET {probe_url} returned status 200 with {len(resp_body)} bytes of content."
                    ),
                    "remediation": (
                        f"Disable or restrict access to {path} in production. If API docs are "
                        f"needed by internal teams, serve them only on an internal network "
                        f"segment or behind authentication."
                    ),
                    "payload": json.dumps(
                        {
                            "check": "api_docs",
                            "probe_url": probe_url,
                        }
                    ),
                }
            )

        return findings

    # ─── shared helpers ───────────────────────────────────────────────────

    async def _fetch(self, url: str) -> Optional[Tuple[int, Dict[str, str], str]]:
        """
        Fetch a URL and return (status, headers_dict, body_text).

        Used for the initial scan() fetch and for validate() re-fetches.
        Returns None on network failure.
        """
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                async with session.get(url) as response:
                    body = await self._safe_read(response)
                    headers = dict(response.headers)
                    return (response.status, headers, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(f"Fetch failed for {url}: {str(e)}", original_error=e),
                context={"url": url},
            )
            return None

    async def _probe_path(self, url: str) -> Optional[Tuple[int, str]]:
        """
        Lightweight GET for sensitive-path probing.  Returns (status, body).

        Single chokepoint for all path probes — timeout, error handling,
        and redirect behaviour (aiohttp follows redirects by default) are
        all consistent.  Returns None on network error.
        """
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                async with session.get(url) as response:
                    body = await self._safe_read(response)
                    return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(f"Probe failed for {url}: {str(e)}", original_error=e),
                context={"url": url},
            )
            return None

    @staticmethod
    def _extract_origin(url: str) -> str:
        """
        Extract scheme://host from any URL.

        All path probes are relative to this — misconfig files always
        live at the document root, not nested under sub-paths.
        """
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
