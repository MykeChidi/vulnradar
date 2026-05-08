# vulnradar/scanners/nosql.py

import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode

import aiohttp

from ..utils.error_handler import NetworkError, ScanError, get_global_error_handler
from . import payloads
from .base import BaseScanner

error_handler = get_global_error_handler()


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# Payloads and error indicators are imported from payloads module
# ─────────────────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────────────────
# AUTH-BYPASS INDICATORS
#
# Patterns that indicate a login form successfully authenticated after
# injecting an auth-bypass payload.
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
    "logout",
]


# ─────────────────────────────────────────────────────────────────────────────
# COMPARISON ORACLE THRESHOLD
#
# If the response length for a comparison payload differs by more than this
# many bytes from the baseline, it's a significant difference indicating the
# operator was evaluated by the database.
# ─────────────────────────────────────────────────────────────────────────────

_COMPARISON_LENGTH_THRESHOLD = 100


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────


class NoSQLInjectionScanner(BaseScanner):
    """Scan for NoSQL Injection vulnerabilities."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    # ── public: scan ──────────────────────────────────────────────────────

    async def scan(self, url: str) -> List[Dict]:
        """
        Test a single URL for NoSQL injection.

        Extracts forms and URL parameters, injects NoSQL operator payloads,
        checks for error messages, auth bypass, and response-length oracles.
        """
        findings: List[Dict] = []

        try:
            # Test 1: forms (most common injection vector — login forms, search forms)
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
                    f"NoSQLInjectionScanner error on {url}: {str(e)}", original_error=e
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
            "target_url": url,
            "injection_point": param/field name,
            "payload_value": the specific NoSQL payload,
            "payload_format": "json" | "url_operator",
            "technique": "error_based" | "auth_bypass" | "comparison",
            ... (technique-specific fields)
        }
        """
        try:
            meta = json.loads(payload)
            method = meta["method"]
            target_url = meta["target_url"]
            injection_point = meta["injection_point"]
            payload_value = meta["payload_value"]
            payload_format = meta.get("payload_format", "json")
            technique = meta["technique"]

            # Re-submit
            if method.upper() == "POST":
                if payload_format == "json":
                    # JSON body
                    result = await self._submit_json(
                        target_url, {injection_point: payload_value}
                    )
                else:
                    # Form data
                    data = meta.get("form_data", {})
                    data[injection_point] = payload_value
                    result = await self._submit_form(target_url, data)
            else:
                params = meta.get("params", {})
                if payload_format == "url_operator":
                    # URL-encoded operator syntax: param[$ne]=value
                    operator = meta.get("operator", "")
                    params[f"{injection_point}{operator}"] = payload_value
                else:
                    params[injection_point] = payload_value
                result = await self._submit_get(target_url, params)

            if result is None:
                return False

            status, body = result

            # Re-check the same technique
            if technique == "error_based":
                return self._has_nosql_error(body)
            elif technique == "auth_bypass":
                baseline_status = meta.get("baseline_status", 401)
                return self._indicates_auth_success(status, baseline_status, body)
            elif technique == "comparison":
                baseline_len = meta.get("baseline_length", 0)
                return abs(len(body) - baseline_len) > _COMPARISON_LENGTH_THRESHOLD

            return bool(evidence)

        except (json.JSONDecodeError, KeyError):
            return bool(evidence)

    # ── private: form testing ─────────────────────────────────────────────

    async def _test_form(self, page_url: str, form: Dict) -> List[Dict]:
        """
        Test a single form for NoSQL injection.

        Three technique passes:
          1. Error-based: inject error_based payloads, check for NoSQL errors
          2. Auth bypass: if it looks like a login form, inject auth_bypass
             payloads, compare status/body to baseline
          3. Comparison: inject comparison payloads, compare response lengths
        """
        findings: List[Dict] = []

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

        # Check if the endpoint accepts JSON
        accepts_json = await self._accepts_json(action)

        # Test each input field
        for inp in inputs:
            field_name = inp["name"]

            # Pass 1: error-based (both JSON and form encoding)
            for payload_val, category, why in payloads.nosql_injection_payloads:
                if category != "error_based":
                    continue

                # Try JSON format first (if endpoint accepts JSON)
                if accepts_json:
                    try:
                        payload_obj = json.loads(payload_val)
                        json_body = {field_name: payload_obj}
                        result = await self._submit_json(action, json_body)
                        if result:
                            inject_status, inject_body = result
                            if self._has_nosql_error(inject_body):
                                findings.append(
                                    {
                                        "type": "NoSQL Injection",
                                        "endpoint": action,
                                        "severity": "High",
                                        "description": (
                                            f"Error-based NoSQL injection detected in form field '{field_name}'. "
                                            f"Payload: {payload_val}. {why}."
                                        ),
                                        "evidence": (
                                            f"POST {action} with JSON body containing {field_name}={payload_val} "
                                            f"returned NoSQL error in response. Status: {inject_status}."
                                        ),
                                        "remediation": (
                                            "Validate and sanitize all user input before using it in NoSQL queries. "
                                            "Use parameterized queries or ODM/ORM libraries that escape operators. "
                                            "Never pass user-controlled JSON directly to database queries."
                                        ),
                                        "payload": json.dumps(
                                            {
                                                "method": "POST",
                                                "target_url": action,
                                                "injection_point": field_name,
                                                "payload_value": payload_obj,
                                                "payload_format": "json",
                                                "technique": "error_based",
                                                "form_data": baseline_data,
                                            }
                                        ),
                                    }
                                )
                                break  # one finding per field is enough
                    except json.JSONDecodeError:
                        pass

                # Try form-encoded format (URL-encoded JSON string)
                inject_data = dict(baseline_data)
                inject_data[field_name] = payload_val
                result = await self._submit_form(action, inject_data)
                if result:
                    inject_status, inject_body = result
                    if self._has_nosql_error(inject_body):
                        findings.append(
                            {
                                "type": "NoSQL Injection",
                                "endpoint": action,
                                "severity": "High",
                                "description": (
                                    f"Error-based NoSQL injection detected in form field '{field_name}'. "
                                    f"Payload: {payload_val}. {why}."
                                ),
                                "evidence": (
                                    f"POST {action} with {field_name}={payload_val} returned NoSQL error. "
                                    f"Status: {inject_status}."
                                ),
                                "remediation": (
                                    "Validate and sanitize all user input before using it in NoSQL queries. "
                                    "Never parse JSON from form fields without validation."
                                ),
                                "payload": json.dumps(
                                    {
                                        "method": "POST",
                                        "target_url": action,
                                        "injection_point": field_name,
                                        "payload_value": payload_val,
                                        "payload_format": "form",
                                        "technique": "error_based",
                                        "form_data": baseline_data,
                                    }
                                ),
                            }
                        )
                        break

            if findings:
                break  # one finding per form is enough

            # Pass 2: auth bypass (only if this is a login form)
            if is_login_form and accepts_json:
                for payload_val, category, why in payloads.nosql_injection_payloads:
                    if category != "auth_bypass":
                        continue

                    try:
                        payload_obj = json.loads(payload_val)
                        json_body = {field_name: payload_obj}
                        result = await self._submit_json(action, json_body)
                        if result:
                            inject_status, inject_body = result
                            if self._indicates_auth_success(
                                inject_status, baseline_status, inject_body
                            ):
                                findings.append(
                                    {
                                        "type": "NoSQL Injection",
                                        "endpoint": action,
                                        "severity": "Critical",
                                        "description": (
                                            f"NoSQL authentication bypass detected in form field '{field_name}'. "
                                            f"Payload: {payload_val}. {why}. The server accepted the login "
                                            f"despite the injected operator."
                                        ),
                                        "evidence": (
                                            f"POST {action} with JSON {field_name}={payload_val} changed response "
                                            f"from status {baseline_status} to {inject_status}. Response contains "
                                            f"auth-success indicators."
                                            f"NoSQL query was rewritten to bypass authentication."
                                        ),
                                        "remediation": (
                                            "Sanitize all authentication input before building NoSQL queries. "
                                            "Use parameterized queries or validate that input contains only expected "
                                            "types (strings, not objects). Implement server-side authorization checks "
                                            "independent of database query results."
                                        ),
                                        "payload": json.dumps(
                                            {
                                                "method": "POST",
                                                "target_url": action,
                                                "injection_point": field_name,
                                                "payload_value": payload_obj,
                                                "payload_format": "json",
                                                "technique": "auth_bypass",
                                                "baseline_status": baseline_status,
                                                "form_data": baseline_data,
                                            }
                                        ),
                                    }
                                )
                                break  # one finding per field
                    except json.JSONDecodeError:
                        continue

            if findings:
                break

            # Pass 3: comparison oracle (only if NOT a login form and accepts JSON)
            if not is_login_form and accepts_json:
                # Get baseline length with a benign value
                try:
                    benign_json = {field_name: "test"}
                    comp_baseline_result = await self._submit_json(action, benign_json)
                    if comp_baseline_result:
                        comp_baseline_status, comp_baseline_body = comp_baseline_result
                        comp_baseline_len = len(comp_baseline_body)

                        # Test comparison payloads
                        for payload_val, category, why in payloads.nosql_injection_payloads:
                            if category != "comparison":
                                continue

                            payload_obj = json.loads(payload_val)
                            json_body = {field_name: payload_obj}
                            result = await self._submit_json(action, json_body)
                            if result:
                                inject_status, inject_body = result
                                inject_len = len(inject_body)

                                if (
                                    abs(inject_len - comp_baseline_len)
                                    > _COMPARISON_LENGTH_THRESHOLD
                                ):
                                    findings.append(
                                        {
                                            "type": "NoSQL Injection",
                                            "endpoint": action,
                                            "severity": "Medium",
                                            "description": (
                                                f"NoSQL comparison oracle detected in form field '{field_name}'. "
                                                f"Payload: {payload_val}. {why}. Response length differs "
                                                f"significantly from baseline, indicating the operator was "
                                                f"evaluated by the database."
                                            ),
                                            "evidence": (
                                                f"POST {action} with JSON {field_name}={payload_val} returned "
                                                f"{inject_len} bytes. Baseline returned {comp_baseline_len} bytes. "
                                                f"Difference: {abs(inject_len - comp_baseline_len)} bytes. "
                                                f"Response-length oracle for NoSQL operator evaluation."
                                            ),
                                            "remediation": (
                                                "Validate that all input values are the expected type (string, number)"
                                                "Reject objects and operators. "
                                                "Avoid leaking query results via response "
                                                "length side channels."
                                            ),
                                            "payload": json.dumps(
                                                {
                                                    "method": "POST",
                                                    "target_url": action,
                                                    "injection_point": field_name,
                                                    "payload_value": payload_obj,
                                                    "payload_format": "json",
                                                    "technique": "comparison",
                                                    "baseline_length": comp_baseline_len,
                                                    "form_data": baseline_data,
                                                }
                                            ),
                                        }
                                    )
                                    break
                except json.JSONDecodeError:
                    continue

            if findings:
                break

        return findings

    # ── private: URL parameter testing ────────────────────────────────────

    async def _test_params(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """
        Test URL parameters for NoSQL injection.

        Same three techniques as forms, plus URL-encoded operator syntax
        (param[$ne]=value).
        """
        findings: List[Dict] = []

        # Baseline
        baseline_result = await self._submit_get(url, params)
        if baseline_result is None:
            return []
        baseline_status, baseline_body = baseline_result  # noqa
        baseline_len = len(baseline_body)  # noqa

        # Test each parameter
        for param_name in params:
            # Pass 1: error-based (JSON string format)
            for payload_val, category, why in payloads.nosql_injection_payloads:
                if category != "error_based":
                    continue

                inject_params = dict(params)
                inject_params[param_name] = payload_val
                result = await self._submit_get(url, inject_params)
                if result:
                    inject_status, inject_body = result
                    if self._has_nosql_error(inject_body):
                        findings.append(
                            {
                                "type": "NoSQL Injection",
                                "endpoint": url,
                                "severity": "High",
                                "description": (
                                    f"Error-based NoSQL injection detected in URL parameter '{param_name}'. "
                                    f"Payload: {payload_val}. {why}."
                                ),
                                "evidence": (
                                    f"GET {url}?{param_name}={payload_val} returned NoSQL error. "
                                    f"Status: {inject_status}."
                                ),
                                "remediation": (
                                    "Sanitize all URL parameter input before using it in NoSQL queries. "
                                    "Validate input types and reject operator objects."
                                ),
                                "payload": json.dumps(
                                    {
                                        "method": "GET",
                                        "target_url": url,
                                        "injection_point": param_name,
                                        "payload_value": payload_val,
                                        "payload_format": "url_param",
                                        "technique": "error_based",
                                        "params": params,
                                    }
                                ),
                            }
                        )
                        break

            if findings:
                break

            # Pass 2: URL-encoded operator syntax (param[$ne]=value)
            for operator, value, why in payloads.nosql_injection_url_operator_payloads:
                inject_params = dict(params)
                inject_params[f"{param_name}{operator}"] = value
                result = await self._submit_get(url, inject_params)
                if result:
                    inject_status, inject_body = result
                    if self._has_nosql_error(inject_body):
                        findings.append(
                            {
                                "type": "NoSQL Injection",
                                "endpoint": url,
                                "severity": "High",
                                "description": (
                                    f"NoSQL injection detected in URL parameter '{param_name}' via URL-encoded "
                                    f"operator syntax. Payload: {param_name}{operator}={value}. {why}."
                                ),
                                "evidence": (
                                    f"GET {url}?{param_name}{operator}={value} returned NoSQL error. "
                                    f"Status: {inject_status}. Framework parsed URL-encoded operator."
                                ),
                                "remediation": (
                                    "Reject URL parameters that contain operator syntax ([$..]) unless "
                                    "explicitly whitelisted. Validate parameter names, not just values."
                                ),
                                "payload": json.dumps(
                                    {
                                        "method": "GET",
                                        "target_url": url,
                                        "injection_point": param_name,
                                        "payload_value": value,
                                        "payload_format": "url_operator",
                                        "operator": operator,
                                        "technique": "error_based",
                                        "params": params,
                                    }
                                ),
                            }
                        )
                        break

            if findings:
                break

        return findings

    # ── private: detection helpers ───────────────────────────────────────

    @staticmethod
    def _has_nosql_error(body: str) -> bool:
        """Check if the response body contains NoSQL error indicators."""
        body_lo = body.lower()
        return any(indicator in body_lo for indicator in payloads.nosql_injection_error_indicators)

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

    async def _accepts_json(self, url: str) -> bool:
        """
        Test if an endpoint accepts JSON by sending a simple JSON body.

        Returns True if the server doesn't reject it with 415 Unsupported Media Type.
        """
        try:
            json_headers = dict(self.headers)
            json_headers["Content-Type"] = "application/json"

            async with aiohttp.ClientSession(
                headers=json_headers, timeout=self.timeout
            ) as session:
                test_body = json.dumps({"test": "value"})
                async with session.post(url, data=test_body) as response:
                    # If status is NOT 415, the endpoint accepts JSON
                    return response.status != 415

        except Exception:
            return False

    # ── private: submission helpers ───────────────────────────────────────

    async def _submit_form(
        self, url: str, data: Dict[str, str]
    ) -> Optional[Tuple[int, str]]:
        """POST a form with form-encoded data.  Returns (status, body) or None."""
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                async with session.post(url, data=data) as response:
                    body = await self._safe_read(response)
                    return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"NoSQL injection form submit failed for {url}: {str(e)}",
                    original_error=e,
                ),
                context={"url": url},
            )
            return None

    async def _submit_json(self, url: str, data: Dict) -> Optional[Tuple[int, str]]:
        """POST a JSON body.  Returns (status, body) or None."""
        try:
            json_headers = dict(self.headers)
            json_headers["Content-Type"] = "application/json"

            async with aiohttp.ClientSession(
                headers=json_headers, timeout=self.timeout
            ) as session:
                async with session.post(url, json=data) as response:
                    body = await self._safe_read(response)
                    return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"NoSQL injection JSON submit failed for {url}: {str(e)}",
                    original_error=e,
                ),
                context={"url": url},
            )
            return None

    async def _submit_get(
        self, url: str, params: Dict[str, str]
    ) -> Optional[Tuple[int, str]]:
        """GET with query parameters.  Returns (status, body) or None."""
        try:
            query_string = urlencode(params)
            full_url = (
                f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"
            )

            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                async with session.get(full_url) as response:
                    body = await self._safe_read(response)
                    return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"NoSQL injection GET failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return None
