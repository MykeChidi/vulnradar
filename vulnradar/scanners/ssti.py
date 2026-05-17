# vulnradar/scanners/ssti.py

from __future__ import annotations

import asyncio
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


# Confirmation probe result for the second expression (3*3 = 9)
_CONFIRMATION_RESULT: str = "9"


class SSTIScanner(BaseScanner):
    """Scan for Server-Side Template Injection vulnerabilities (CWE-94)."""

    def __init__(
        self,
        headers: Optional[Dict] = None,
        timeout: int = 10,
    ) -> None:
        super().__init__(headers, timeout)

    # ── public: scan ──────────────────────────────────────────────────────

    @handle_async_errors(
        error_handler=error_handler,
        user_message="SSTI scan encountered an error",
        return_on_error=[],
    )
    async def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for SSTI vulnerabilities.

        Args:
            url: Fully-qualified URL to test.

        Returns:
            List of ``Finding`` objects.
        """
        findings: List[Finding] = []

        get_findings = await self._test_get_params(url)
        findings.extend(get_findings)

        post_findings = await self._test_forms(url)
        findings.extend(post_findings)

        return findings

    # ── public: validate ──────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-inject the original payload and confirm the evaluated result is
        still present in the response.

        Args:
            url:      URL where the vulnerability was found.
            payload:  The template expression that was injected.
            evidence: The evaluated output that was found (e.g. ``"49"``).

        Returns:
            True if the expression is still evaluated server-side.
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if not params:
                return False

            param_name = next(iter(params))
            params[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            async with self.session.get(test_url) as response:
                body = await self._safe_read(response)
                return evidence in body

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    # ── private helpers ───────────────────────────────────────────────────

    async def _test_get_params(self, url: str) -> List[Finding]:
        """Inject SSTI payloads into each URL query parameter."""
        findings: List[Finding] = []

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return findings

        if not params:
            return findings

        for param_name in params:
            finding = await self._probe_param(url, param_name, "GET")
            if finding is not None:
                findings.append(finding)

        return findings

    async def _test_forms(self, url: str) -> List[Finding]:
        """Inject SSTI payloads into POST form fields."""
        findings: List[Finding] = []
        forms = await self._get_form_inputs(url)

        for form in forms:
            action_url: str = form.get("action") or url
            for input_field in form.get("inputs", []):
                input_name: str = input_field.get("name", "")
                if not input_name:
                    continue

                finding = await self._probe_form_field(
                    url,
                    action_url,
                    form,
                    input_name,
                )
                if finding is not None:
                    findings.append(finding)

        return findings

    async def _probe_param(
        self,
        url: str,
        param_name: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Test a single URL parameter with all SSTI payloads.

        Returns the first confirmed ``Finding``, or ``None``.
        """
        try:
            parsed = urlparse(url)
            base_params = parse_qs(parsed.query, keep_blank_values=True)

            for payload, confirm_payload, expected, engine in payloads.ssti_payloads:
                # Primary probe
                test_params = {**base_params, param_name: [payload]}
                test_url = urlunparse(
                    parsed._replace(query=urlencode(test_params, doseq=True))
                )

                async with self.session.get(test_url) as response:
                    body = await self._safe_read(response)

                if expected not in body:
                    continue

                # Confirmation probe — different expression, same result check
                confirm_params = {**base_params, param_name: [confirm_payload]}
                confirm_url = urlunparse(
                    parsed._replace(query=urlencode(confirm_params, doseq=True))
                )

                async with self.session.get(confirm_url) as response:
                    confirm_body = await self._safe_read(response)

                # Both the primary and confirmation expressions must evaluate
                if (
                    _CONFIRMATION_RESULT not in confirm_body
                    and expected not in confirm_body
                ):
                    continue

                standards = get_standards("SSTI")
                return Finding(
                    type="SSTI",
                    severity=Severity.CRITICAL,
                    endpoint=url,
                    parameter=param_name,
                    method=method,
                    payload=payload,
                    evidence=(
                        f"Template expression '{payload}' evaluated to '{expected}' "
                        f"in parameter '{param_name}'. "
                        f"Likely engine: {engine}."
                    ),
                    description=(
                        f"Server-Side Template Injection in parameter '{param_name}'. "
                        f"The server evaluated the arithmetic expression '{payload}' "
                        f"and returned '{expected}'. "
                        "An attacker can escalate this to remote code execution "
                        "by injecting engine-specific system-access primitives."
                    ),
                    remediation=(
                        "Never pass unsanitised user input to a template rendering "
                        "function. Use a sandboxed template environment, or render "
                        "user-supplied data as plain text rather than as a template "
                        "expression."
                    ),
                    tags=[engine],
                    **standards,
                )

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        return None

    async def _probe_form_field(
        self,
        page_url: str,
        action_url: str,
        form: Dict,
        field_name: str,
    ) -> Optional[Finding]:
        """
        Test a single POST form field with all SSTI payloads.

        Returns the first confirmed ``Finding``, or ``None``.
        """
        try:
            base_data: Dict[str, str] = {
                inp["name"]: inp.get("value", "test")
                for inp in form.get("inputs", [])
                if inp.get("name")
            }

            for payload, confirm_payload, expected, engine in payloads.ssti_payloads:
                test_data = {**base_data, field_name: payload}

                async with self.session.post(action_url, data=test_data) as response:
                    body = await self._safe_read(response)

                if expected not in body:
                    continue

                # Confirmation probe
                confirm_data = {**base_data, field_name: confirm_payload}
                async with self.session.post(action_url, data=confirm_data) as response:
                    confirm_body = await self._safe_read(response)

                if (
                    _CONFIRMATION_RESULT not in confirm_body
                    and expected not in confirm_body
                ):
                    continue

                standards = get_standards("SSTI")
                return Finding(
                    type="SSTI",
                    severity=Severity.CRITICAL,
                    endpoint=action_url,
                    parameter=field_name,
                    method="POST",
                    payload=payload,
                    evidence=(
                        f"Template expression '{payload}' evaluated to '{expected}' "
                        f"in form field '{field_name}'. "
                        f"Likely engine: {engine}."
                    ),
                    description=(
                        f"Server-Side Template Injection in form field '{field_name}'. "
                        f"The server evaluated the arithmetic expression '{payload}' "
                        f"and returned '{expected}'."
                    ),
                    remediation=(
                        "Never pass unsanitised user input to a template rendering "
                        "function. Use a sandboxed template environment or render "
                        "user-supplied data as plain text."
                    ),
                    tags=[engine],
                    **standards,
                )

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        return None
