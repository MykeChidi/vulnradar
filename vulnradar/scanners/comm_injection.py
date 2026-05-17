# vulnradar/scanners/comm_injection.py - Command Injection Scanner

import asyncio
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin

import aiohttp

from ..models.finding import Finding
from ..models.severity import Severity
from ..models.standards import get_standards
from ..utils.error_handler import (
    ScanError,
    get_global_error_handler,
    handle_async_errors,
)
from ..utils.timing import is_time_based_hit, measure_baseline
from . import payloads
from .base import BaseScanner

# Setup error handler
error_handler = get_global_error_handler()


class CommandInjectionScanner(BaseScanner):
    """Scanner for command injection vulnerabilities."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        """Initialize the command injection scanner."""
        super().__init__(headers, timeout)

        # Common command injection payloads
        self.payloads = payloads.comm_injection_payloads

        # Evidence patterns to look for in responses
        self.evidence_patterns = payloads.comm_injection_evidence_patterns

        # Compile regex patterns for better performance
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.evidence_patterns
        ]

        # Parameters commonly vulnerable to command injection
        self.vulnerable_params = payloads.comm_injection_vulnerable_params

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Command injection scan encountered an error",
        return_on_error=[],
    )
    async def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for command injection vulnerabilities.

        Args:
            url: URL to scan

        Returns:
            List[Finding]: List of vulnerability findings
        """
        vulnerabilities: List[Finding] = []

        try:
            # Test GET parameters
            get_vulns = await self._test_get_parameters(url)
            vulnerabilities.extend(get_vulns)

            # Test POST forms
            form_vulns = await self._test_forms(url)
            vulnerabilities.extend(form_vulns)

            # Test JSON endpoints
            json_vulns = await self._test_json_endpoints(url)
            vulnerabilities.extend(json_vulns)

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"Error scanning '{url}' for command injection: {str(e)}",
                    original_error=e,
                ),
                context={"url": url, "scanner": "CMD"},
            )

        return vulnerabilities

    async def _test_get_parameters(self, url: str) -> List[Finding]:
        """Test GET parameters for command injection."""
        vulnerabilities: List[Finding] = []

        # Extract existing parameters
        params = await self._extract_parameters(url)

        if not params:
            return vulnerabilities

        # Test each parameter
        for param_name, original_value in params.items():
            # Skip if parameter name doesn't look vulnerable
            if not any(
                vuln_param in param_name.lower()
                for vuln_param in self.vulnerable_params
            ):
                continue

            try:
                baseline = await measure_baseline(lambda: self.session.get(url))
            except Exception:
                baseline = 0.0

            for payload in self.payloads:
                try:
                    # Create test parameters
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Build URL with test parameters
                    base_url = url.split("?")[0]
                    param_string = "&".join(
                        [f"{k}={v}" for k, v in test_params.items()]
                    )
                    test_url = f"{base_url}?{param_string}"

                    # Time the request for time-based detection
                    start_time = time.monotonic()

                    async with self.session.get(test_url) as response:
                        response_time = time.monotonic() - start_time
                        response_text = await self._safe_read(response)

                        # Check for evidence of command execution
                        evidence = self._check_evidence(response_text, payload)

                        if evidence or self._is_time_based_vulnerable(
                            payload, response_time, baseline
                        ):
                            standards = get_standards("Command Injection")
                            vulnerability = Finding(
                                type="Command Injection",
                                severity=Severity.HIGH,
                                endpoint=url,
                                parameter=param_name,
                                method="GET",
                                payload=payload,
                                evidence=evidence
                                or f"Time delay detected: {response_time:.2f}s (baseline: {baseline:.2f}s)",
                                description=f"Command injection vulnerability found in GET parameter '{param_name}'",
                                remediation="Implement proper input validation and sanitization. "
                                "Use parameterized queries or prepared statements. "
                                "Avoid executing user input as system commands.",
                                **standards,
                            )
                            vulnerabilities.append(vulnerability)
                            break  # Found vulnerability, no need to test more payloads for this parameter

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

        return vulnerabilities

    async def _test_forms(self, url: str) -> List[Finding]:
        """Test POST forms for command injection."""
        vulnerabilities: List[Finding] = []

        # Get forms from the page
        forms = await self._get_form_inputs(url)

        if not forms:
            return vulnerabilities

        for form in forms:
            action_url = form.get("action", url)
            method = form.get("method", "post").lower()

            # Make sure action URL is absolute
            if not action_url.startswith(("http://", "https://")):
                action_url = urljoin(url, action_url)

            # Test each input in the form
            for input_info in form.get("inputs", []):
                input_name = input_info.get("name", "")
                input_type = input_info.get("type", "")

                # Skip certain input types
                if input_type in ["hidden", "submit", "button", "reset", "image"]:
                    continue

                # Focus on parameters that might be vulnerable
                if not any(
                    vuln_param in input_name.lower()
                    for vuln_param in self.vulnerable_params
                ):
                    continue

                try:
                    baseline = await measure_baseline(lambda: self.session.get(url))
                except Exception:
                    baseline = 0.0

                for payload in self.payloads:
                    try:
                        # Build form data
                        form_data = {}
                        for inp in form.get("inputs", []):
                            if inp.get("name"):
                                if inp.get("name") == input_name:
                                    form_data[inp.get("name")] = payload
                                else:
                                    form_data[inp.get("name")] = inp.get("value", "")

                        # Time the request
                        start_time = time.monotonic()

                        if method == "post":
                            async with self.session.post(
                                action_url, data=form_data
                            ) as response:
                                response_time = time.monotonic() - start_time
                                response_text = await self._safe_read(response)
                        else:
                            # Handle GET forms
                            async with self.session.get(
                                action_url, params=form_data
                            ) as response:
                                response_time = time.monotonic() - start_time
                                response_text = await self._safe_read(response)

                        # Check for evidence
                        evidence = self._check_evidence(response_text, payload)

                        if evidence or self._is_time_based_vulnerable(
                            payload, response_time, baseline
                        ):
                            standards = get_standards("Command Injection")
                            vulnerability = Finding(
                                type="Command Injection",
                                severity=Severity.HIGH,
                                endpoint=action_url,
                                parameter=input_name,
                                method=method.upper(),
                                payload=payload,
                                evidence=evidence
                                or f"Time delay detected: {response_time:.2f}s (baseline: {baseline:.2f}s)",
                                description=f"Command injection vulnerability found in form parameter '{input_name}'",
                                remediation="Implement proper input validation and sanitization."
                                "Use parameterized queries or prepared statements. "
                                "Avoid executing user input as system commands.",
                                **standards,
                            )
                            vulnerabilities.append(vulnerability)
                            break  # Found vulnerability, no need to test more payloads

                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue

        return vulnerabilities

    async def _test_json_endpoints(self, url: str) -> List[Finding]:
        """Test JSON endpoints for command injection."""
        vulnerabilities: List[Finding] = []

        # Common JSON parameter names that might be vulnerable
        json_test_params = {
            "command": "test",
            "cmd": "test",
            "exec": "test",
            "execute": "test",
            "system": "test",
            "shell": "test",
            "file": "test.txt",
            "filename": "test.txt",
            "path": "/tmp/test",
            "directory": "/tmp",
            "url": "http://example.com",  # nosec B108
            "host": "example.com",
            "ping": "example.com",
            "backup": "test.zip",
            "restore": "test.zip",
            "input": "test",
            "data": "test",
            "value": "test",
            "content": "test",
            "message": "test",
        }

        for param_name, base_value in json_test_params.items():
            try:
                baseline = await measure_baseline(lambda: self.session.get(url))
            except Exception:
                baseline = 0.0

            for payload in self.payloads[
                :10
            ]:  # Test fewer payloads for JSON to avoid too many requests
                try:
                    # Create JSON payload
                    json_payload = {param_name: payload}

                    # Time the request
                    start_time = time.monotonic()

                    headers = self.headers.copy()
                    headers["Content-Type"] = "application/json"

                    async with self.session.post(
                        url, json=json_payload, headers=headers
                    ) as response:
                        response_time = time.monotonic() - start_time
                        response_text = await self._safe_read(response)

                        # Check for evidence
                        evidence = self._check_evidence(response_text, payload)

                        if evidence or self._is_time_based_vulnerable(
                            payload, response_time, baseline
                        ):
                            standards = get_standards("Command Injection")
                            vulnerability = Finding(
                                type="Command Injection",
                                severity=Severity.HIGH,
                                endpoint=url,
                                parameter=param_name,
                                method="POST",
                                payload=payload,
                                evidence=evidence
                                or f"Time delay detected: {response_time:.2f}s (baseline: {baseline:.2f}s)",
                                description=f"Command injection vulnerability found in JSON parameter '{param_name}'",
                                remediation="Implement proper input validation and sanitization. "
                                "Use parameterized queries or prepared statements. "
                                "Avoid executing user input as system commands.",
                                **standards,
                            )
                            vulnerabilities.append(vulnerability)
                            break  # Found vulnerability, no need to test more payloads

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

        return vulnerabilities

    def _check_evidence(self, response_text: str, payload: str) -> Optional[str]:
        """
        Check response for evidence of command execution.

        Args:
            response_text: HTTP response text
            payload: Payload that was sent

        Returns:
            str: Evidence found, or None if no evidence
        """
        # Check against compiled patterns
        for compiled_pattern in self.compiled_patterns:
            match = compiled_pattern.search(response_text)
            if match:
                return f"Command execution evidence found: {match.group(0)[:100]}"

        # Check for specific command outputs based on payload
        if "whoami" in payload.lower():
            # Look for common usernames in the response
            username_patterns = [
                r"\b(root|administrator|system|daemon|www-data|apache|nginx|mysql|postgres)\b",
                r"\b[a-z][a-z0-9_-]{2,15}\b",  # Common username pattern
            ]
            for username_pattern in username_patterns:
                if re.search(username_pattern, response_text, re.IGNORECASE):
                    return f"Potential username found in response: {username_pattern}"

        if "ls" in payload.lower() or "dir" in payload.lower():
            # Look for directory listing patterns
            dir_patterns = [
                r"\b(bin|etc|usr|var|tmp|home|root|dev|proc|sys|windows|program files|users)\b",
                r"\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}",  # Date/time format
                r"\b\d+\s+bytes?\b",  # File size
            ]
            for dir_pattern in dir_patterns:
                if re.search(dir_pattern, response_text, re.IGNORECASE):
                    return f"Directory listing evidence: {dir_pattern}"

        if "cat" in payload.lower() or "type" in payload.lower():
            # Look for file content patterns
            file_patterns = [
                r"root:x:0:0:",  # /etc/passwd
                r"\[boot loader\]",  # Windows boot.ini
                r"for 16-bit app support",  # Windows system.ini
            ]
            for file_pattern in file_patterns:
                if re.search(file_pattern, response_text, re.IGNORECASE):
                    return f"File content evidence: {file_pattern}"

        return None

    def _is_time_based_vulnerable(
        self, payload: str, response_time: float, baseline: float = 0.0
    ) -> bool:
        """
        Check if response time indicates time-based command injection.

        Args:
            payload: Payload that was sent
            response_time: Response time in seconds
            baseline: Baseline response time in seconds
        Returns:
            bool: True if time-based vulnerability is detected
        """
        # Check if payload contains sleep/delay commands
        payload_lower = payload.lower()

        # Only flag time-based if the payload actually contains a sleep/delay
        # command.  Without this guard, any slow server response on any payload
        # would be flagged, producing high false-positive rates.
        time_based_keywords = ("sleep", "ping -n", "timeout")
        if not any(kw in payload_lower for kw in time_based_keywords):
            return False

        # Extract the expected sleep duration from the payload.
        # Matches:  sleep 5 / sleep(5) / ping -n 5 / timeout 5
        duration_match = (
            re.search(r"sleep[\s(]+(\d+)", payload, re.IGNORECASE)
            or re.search(r"ping\s+-n\s+(\d+)", payload, re.IGNORECASE)
            or re.search(r"timeout\s+(\d+)", payload, re.IGNORECASE)
        )

        if duration_match:
            expected_sleep = float(duration_match.group(1))
        else:
            # Payload contains a time-based keyword but no parseable duration.
            # Use a conservative default.
            expected_sleep = 5.0

        return is_time_based_hit(
            response_time,
            baseline=baseline,
            expected_sleep=expected_sleep,
        )

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Command injection validation encountered an error",
        return_on_error=False,
    )
    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate a command injection vulnerability.

        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability

        Returns:
            bool: True if vulnerability is confirmed
        """
        try:
            # Try different methods based on original finding
            methods_to_try = ["GET", "POST"]

            for method in methods_to_try:
                try:
                    if method == "GET":
                        # Test as GET parameter
                        test_url = f"{url}{'&' if '?' in url else '?'}test={payload}"
                        async with self.session.get(test_url) as response:
                            response_text = await self._safe_read(response)
                    else:
                        # Test as POST data
                        async with self.session.post(
                            url, data={"test": payload}
                        ) as response:
                            response_text = await self._safe_read(response)

                    # Check if we can reproduce the evidence
                    if self._check_evidence(response_text, payload):
                        return True

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

            # If we can't reproduce the exact evidence, try a simple validation payload
            validation_payload = "; echo 'VALIDATION_TEST_12345'"

            async with self.session.get(
                f"{url}{'&' if '?' in url else '?'}test={validation_payload}"
            ) as response:
                response_text = await self._safe_read(response)

            # Look for our validation string
            if "VALIDATION_TEST_12345" in response_text:
                return True

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"Error validating command injection at {url}: {str(e)}",
                    original_error=e,
                ),
                context={"url": url, "scanner": "CMD"},
            )

        return False
