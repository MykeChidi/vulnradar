# vulnradar/scanners/ldap_injection.py

import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode

import aiohttp

from ..models.finding import Finding
from ..models.severity import Severity
from ..models.standards import get_standards
from ..utils.error_handler import NetworkError, ScanError, get_global_error_handler
from . import payloads
from .base import BaseScanner

error_handler = get_global_error_handler()


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# Payloads and error indicators are imported from payloads module
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that indicate a login form successfully authenticated after
# injecting an auth-bypass payload.  These are heuristics — different apps
# use different redirect patterns / success messages.
# ─────────────────────────────────────────────────────────────────────────────

_AUTH_SUCCESS_INDICATORS: List[str] = [
    "welcome",
    "dashboard",
    "logged in",
    "login successful",
    "authentication successful",
    "home page",
    "user profile",
    "account",
    "my account",
]


# ─────────────────────────────────────────────────────────────────────────────
# WILDCARD ENUMERATION THRESHOLD
#
# If the response length for a wildcard payload differs by more than this
# many bytes from the baseline (zzznomatch*), it's a significant difference
# indicating the wildcard was evaluated by LDAP.
# ─────────────────────────────────────────────────────────────────────────────

_WILDCARD_LENGTH_THRESHOLD = 100


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────


class LDAPInjectionScanner(BaseScanner):
    """Scan for LDAP Injection vulnerabilities."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    # ── public: scan ──────────────────────────────────────────────────────

    async def scan(self, url: str) -> List[Finding]:
        """
        Test a single URL for LDAP injection.

        Extracts forms and URL parameters, injects LDAP payloads, checks
        for error messages, auth bypass, and wildcard enumeration oracles.
        """
        findings: List[Finding] = []

        try:
            # Test 1: forms (most common injection vector for LDAP — login forms)
            forms = await self._get_form_inputs(url)
            for form in forms:
                findings.extend(await self._test_form(url, form))

            # Test 2: URL parameters
            params = await self._extract_parameters(url)
            if params:
                findings.extend(await self._test_params(url, params))

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"LDAPInjectionScanner error on {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return findings

    # ── public: validate ──────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-submit the specific payload that triggered the original finding.

        payload is JSON: {
            "method": "GET" | "POST",
            "target_url": url (for forms, may differ from endpoint),
            "injection_point": param/field name,
            "payload_value": the specific LDAP payload,
            "technique": "error_based" | "auth_bypass" | "wildcard",
            ... (technique-specific fields)
        }
        """
        try:
            meta = json.loads(payload)
            method = meta["method"]
            target_url = meta["target_url"]
            injection_point = meta["injection_point"]
            payload_value = meta["payload_value"]
            technique = meta["technique"]

            # Re-submit
            if method.upper() == "POST":
                data = meta.get("form_data", {})
                data[injection_point] = payload_value
                result = await self._submit_form(target_url, data)
            else:
                params = meta.get("params", {})
                params[injection_point] = payload_value
                result = await self._submit_get(target_url, params)

            if result is None:
                return False

            status, body = result

            # Re-check the same technique
            if technique == "error_based":
                return self._has_ldap_error(body)
            elif technique == "auth_bypass":
                baseline_status = meta.get("baseline_status", 401)
                return self._indicates_auth_success(status, baseline_status, body)
            elif technique == "wildcard":
                baseline_len = meta.get("baseline_length", 0)
                return abs(len(body) - baseline_len) > _WILDCARD_LENGTH_THRESHOLD

            return bool(evidence)

        except (json.JSONDecodeError, KeyError):
            return bool(evidence)

    # ── private: form testing ─────────────────────────────────────────────

    async def _test_form(self, page_url: str, form: Dict) -> List[Finding]:
        """
        Test a single form for LDAP injection.

        Three technique passes:
          1. Error-based: inject error_based payloads, check for LDAP errors
          2. Auth bypass: if it looks like a login form, inject auth_bypass
             payloads, compare status/body to baseline
          3. Wildcard: inject wildcard payloads, compare response lengths
        """
        findings: List[Finding] = []

        action = form["action"]
        method = form["method"]  # noqa
        inputs = form["inputs"]

        if not inputs:
            return []

        # Build baseline: submit the form with benign values
        baseline_data = {inp["name"]: "test" for inp in inputs}
        baseline_result = await self._submit_form(action, baseline_data)
        if baseline_result is None:
            return []

        baseline_status, baseline_body = baseline_result

        # Determine if this looks like a login form
        is_login_form = self._looks_like_login_form(inputs)

        # Test each input field
        for inp in inputs:
            field_name = inp["name"]

            # Pass 1: error-based
            for payload_val, category, why in payloads.ldap_injection_payloads:
                if category != "error_based":
                    continue

                inject_data = dict(baseline_data)
                inject_data[field_name] = payload_val

                result = await self._submit_form(action, inject_data)
                if result is None:
                    continue

                inject_status, inject_body = result

                if self._has_ldap_error(inject_body):
                    findings.append(
                        Finding(
                            type="LDAP Injection",
                            endpoint=action,
                            severity=Severity.HIGH,
                            description=(
                                f"Error-based LDAP injection detected in form field '{field_name}'. "
                                f"Payload: '{payload_val}'. {why}."
                            ),
                            evidence=(
                                f"POST {action} with {field_name}='{payload_val}' returned LDAP error "
                                f"in response body. Response status: {inject_status}. "
                                f"LDAP error indicator found in response."
                            ),
                            remediation=(
                                "Sanitize all user input before using it in LDAP queries. Use "
                                "parameterized LDAP queries or escape special characters "
                                "( ) * \\ & | ! according to RFC 4515. Never concatenate user "
                                "input directly into LDAP filter strings."
                            ),
                            payload={
                                "method": "POST",
                                "target_url": action,
                                "injection_point": field_name,
                                "payload_value": payload_val,
                                "technique": "error_based",
                                "form_data": baseline_data,
                            },
                            method="POST",
                            **get_standards("LDAP Injection"),
                        )
                    )
                    break  # one finding per field is enough

            # Pass 2: auth bypass (only if this is a login form)
            if is_login_form:
                for payload_val, category, why in payloads.ldap_injection_payloads:
                    if category != "auth_bypass":
                        continue

                    inject_data = dict(baseline_data)
                    inject_data[field_name] = payload_val

                    result = await self._submit_form(action, inject_data)
                    if result is None:
                        continue

                    inject_status, inject_body = result

                    if self._indicates_auth_success(
                        inject_status, baseline_status, inject_body
                    ):
                        findings.append(
                            Finding(
                                type="LDAP Injection",
                                endpoint=action,
                                severity=Severity.CRITICAL,
                                description=(
                                    f"LDAP authentication bypass detected in form field '{field_name}'. "
                                    f"Payload: '{payload_val}'. {why}. The server accepted the login "
                                    f"despite the injected filter manipulation."
                                ),
                                evidence=(
                                    f"POST {action} with {field_name}='{payload_val}' changed response "
                                    f"from status {baseline_status} to {inject_status}. Response body "
                                    f"contains auth-success indicators. This suggests the LDAP filter "
                                    f"was rewritten to bypass authentication."
                                ),
                                remediation=(
                                    "Sanitize all authentication input before building LDAP filters. "
                                    "Use parameterized queries or escape all LDAP meta-characters. "
                                    "Implement server-side authorization checks independent of LDAP "
                                    "filter results."
                                ),
                                payload={
                                    "method": "POST",
                                    "target_url": action,
                                    "injection_point": field_name,
                                    "payload_value": payload_val,
                                    "technique": "auth_bypass",
                                    "baseline_status": baseline_status,
                                    "form_data": baseline_data,
                                },
                                method="POST",
                                **get_standards("LDAP Injection"),
                            )
                        )
                        break  # one finding per field

            # Pass 3: wildcard enumeration (only if NOT a login form —
            # login forms usually lock out after multiple attempts)
            if not is_login_form:
                # First get a baseline length with a known-nonexistent wildcard
                wildcard_baseline_data = dict(baseline_data)
                wildcard_baseline_data[field_name] = "zzznomatch*"
                wc_baseline_result = await self._submit_form(
                    action, wildcard_baseline_data
                )
                if wc_baseline_result is None:
                    continue
                wc_baseline_status, wc_baseline_body = wc_baseline_result
                wc_baseline_len = len(wc_baseline_body)

                # Now test each wildcard payload
                for payload_val, category, why in payloads.ldap_injection_payloads:
                    if category != "wildcard" or payload_val == "zzznomatch*":
                        continue

                    inject_data = dict(baseline_data)
                    inject_data[field_name] = payload_val

                    result = await self._submit_form(action, inject_data)
                    if result is None:
                        continue

                    inject_status, inject_body = result
                    inject_len = len(inject_body)

                    if abs(inject_len - wc_baseline_len) > _WILDCARD_LENGTH_THRESHOLD:
                        findings.append(
                            Finding(
                                type="LDAP Injection",
                                endpoint=action,
                                severity=Severity.MEDIUM,
                                description=(
                                    f"LDAP wildcard enumeration detected in form field '{field_name}'. "
                                    f"Payload: '{payload_val}'. {why}. Response length differs "
                                    f"significantly from baseline, indicating the wildcard was "
                                    f"evaluated by the LDAP server."
                                ),
                                evidence=(
                                    f"POST {action} with {field_name}='{payload_val}' returned "
                                    f"{inject_len} bytes. Baseline (zzznomatch*) returned "
                                    f"{wc_baseline_len} bytes. Difference: {abs(inject_len - wc_baseline_len)} bytes. "
                                    f"This is a response-length oracle for LDAP attribute enumeration."
                                ),
                                remediation=(
                                    "Sanitize wildcard characters (* and \\) in LDAP filter input. "
                                    "If wildcards are a legitimate feature, ensure the response does "
                                    "not reveal whether a match occurred via timing or length side channels."
                                ),
                                payload={
                                    "method": "POST",
                                    "target_url": action,
                                    "injection_point": field_name,
                                    "payload_value": payload_val,
                                    "technique": "wildcard",
                                    "baseline_length": wc_baseline_len,
                                    "form_data": baseline_data,
                                },
                                method="POST",
                                **get_standards("LDAP Injection"),
                            )
                        )
                        break  # one finding per field

        return findings

    # ── private: URL parameter testing ────────────────────────────────────

    async def _test_params(self, url: str, params: Dict[str, str]) -> List[Finding]:
        """
        Test URL parameters for LDAP injection.

        Same three techniques as forms, but submitted via GET query strings.
        """
        findings: List[Finding] = []

        # Baseline
        baseline_result = await self._submit_get(url, params)
        if baseline_result is None:
            return []
        baseline_status, baseline_body = baseline_result

        # Test each parameter
        for param_name in params:
            # Pass 1: error-based
            for payload_val, category, why in payloads.ldap_injection_payloads:
                if category != "error_based":
                    continue

                inject_params = dict(params)
                inject_params[param_name] = payload_val

                result = await self._submit_get(url, inject_params)
                if result is None:
                    continue

                inject_status, inject_body = result

                if self._has_ldap_error(inject_body):
                    findings.append(
                        Finding(
                            type="LDAP Injection",
                            endpoint=url,
                            severity=Severity.HIGH,
                            description=(
                                f"Error-based LDAP injection detected in URL parameter '{param_name}'. "
                                f"Payload: '{payload_val}'. {why}."
                            ),
                            evidence=(
                                f"GET {url}?{param_name}={payload_val} returned LDAP error in "
                                f"response body. Status: {inject_status}."
                            ),
                            remediation=(
                                "Sanitize all URL parameter input before using it in LDAP queries. "
                                "Escape LDAP special characters or use parameterized queries."
                            ),
                            payload={
                                "method": "GET",
                                "target_url": url,
                                "injection_point": param_name,
                                "payload_value": payload_val,
                                "technique": "error_based",
                                "params": params,
                            },
                            method="GET",
                            **get_standards("LDAP Injection"),
                        )
                    )
                    break

            # Pass 2: wildcard enumeration
            # (Skip auth bypass for URL params — auth is typically form-based)
            wildcard_baseline_params = dict(params)
            wildcard_baseline_params[param_name] = "zzznomatch*"
            wc_baseline_result = await self._submit_get(url, wildcard_baseline_params)
            if wc_baseline_result is None:
                continue
            wc_baseline_status, wc_baseline_body = wc_baseline_result
            wc_baseline_len = len(wc_baseline_body)

            for payload_val, category, why in payloads.ldap_injection_payloads:
                if category != "wildcard" or payload_val == "zzznomatch*":
                    continue

                inject_params = dict(params)
                inject_params[param_name] = payload_val

                result = await self._submit_get(url, inject_params)
                if result is None:
                    continue

                inject_status, inject_body = result
                inject_len = len(inject_body)

                if abs(inject_len - wc_baseline_len) > _WILDCARD_LENGTH_THRESHOLD:
                    findings.append(
                        Finding(
                            type="LDAP Injection",
                            endpoint=url,
                            severity=Severity.MEDIUM,
                            description=(
                                f"LDAP wildcard enumeration detected in URL parameter '{param_name}'. "
                                f"Payload: '{payload_val}'. {why}."
                            ),
                            evidence=(
                                f"GET {url}?{param_name}={payload_val} returned {inject_len} bytes. "
                                f"Baseline returned {wc_baseline_len} bytes. Difference: "
                                f"{abs(inject_len - wc_baseline_len)} bytes. Response-length oracle."
                            ),
                            remediation=(
                                "Sanitize wildcard characters in LDAP queries. Avoid leaking match "
                                "results via response length side channels."
                            ),
                            payload={
                                "method": "GET",
                                "target_url": url,
                                "injection_point": param_name,
                                "payload_value": payload_val,
                                "technique": "wildcard",
                                "baseline_length": wc_baseline_len,
                                "params": params,
                            },
                            method="GET",
                            **get_standards("LDAP Injection"),
                        )
                    )
                    break

        return findings

    # ── private: detection helpers ───────────────────────────────────────

    @staticmethod
    def _has_ldap_error(body: str) -> bool:
        """Check if the response body contains LDAP error indicators."""
        body_lo = body.lower()
        return any(
            indicator in body_lo
            for indicator in payloads.ldap_injection_error_indicators
        )

    @staticmethod
    def _indicates_auth_success(
        inject_status: int, baseline_status: int, inject_body: str
    ) -> bool:
        """
        Determine if an auth-bypass payload succeeded.

        Two signals:
          1. Status changed from 401/403 to 200/302
          2. Response body contains auth-success phrases
        """
        # Signal 1: status change
        if baseline_status in (401, 403) and inject_status in (200, 302):
            return True

        # Signal 2: success phrases in body
        body_lo = inject_body.lower()
        if any(phrase in body_lo for phrase in _AUTH_SUCCESS_INDICATORS):
            return True

        return False

    @staticmethod
    def _looks_like_login_form(inputs: List[Dict]) -> bool:
        """
        Heuristic: does this form look like a login form?

        Checks for username/password field naming patterns.
        """
        field_names = [inp["name"].lower() for inp in inputs]
        has_username = any(
            name in field_names
            for name in ("username", "user", "login", "email", "uid")
        )
        has_password = any(
            name in field_names for name in ("password", "pass", "pwd", "passwd")
        )
        return has_username and has_password

    # ── private: submission helpers ───────────────────────────────────────

    async def _submit_form(
        self, url: str, data: Dict[str, str]
    ) -> Optional[Tuple[int, str]]:
        """
        POST a form with the given data.  Returns (status, body) or None on error.
        """
        try:
            async with self.session.post(url, data=data) as response:
                body = await self._safe_read(response)
                return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"LDAP injection form submit failed for {url}: {str(e)}",
                    original_error=e,
                ),
                context={"url": url},
            )
            return None

    async def _submit_get(
        self, url: str, params: Dict[str, str]
    ) -> Optional[Tuple[int, str]]:
        """
        GET a URL with the given query parameters.  Returns (status, body) or None.
        """
        try:
            query_string = urlencode(params)
            full_url = (
                f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"
            )

            async with self.session.get(full_url) as response:
                body = await self._safe_read(response)
                return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"LDAP injection GET failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return None
