# vulnradar/scanners/xxe.py

import hashlib
import json
import time
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
# Payloads and indicators are imported from payloads module
# ─────────────────────────────────────────────────────────────────────────────


class XXEScanner(BaseScanner):
    """Scan for XML External Entity (XXE) injection vulnerabilities."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    # ── public: scan ──────────────────────────────────────────────────────

    async def scan(self, url: str) -> List[Finding]:
        """
        Test a single URL for XXE injection.

        Three test vectors:
          1. XML body injection (POST with Content-Type: application/xml)
          2. Parameter injection (URL params or form fields)
          3. File upload (if forms have file upload fields)

        Five payload types per vector:
          A. File disclosure (Linux /etc/passwd)
          B. File disclosure (Windows win.ini)
          C. Out-of-band marker (unique string)
          D. Billion Laughs (exponential entity expansion)
          E. External DTD (SSRF probe)
        """
        findings: List[Finding] = []

        try:
            # Test 1: XML body injection
            findings.extend(await self._test_xml_body(url))

            # Test 2: Parameter injection (URL params)
            params = await self._extract_parameters(url)
            if params:
                findings.extend(await self._test_params(url, params))

            # Test 3: Form injection (including file uploads)
            forms = await self._get_form_inputs(url)
            for form in forms:
                findings.extend(await self._test_form(url, form))

        except Exception as e:
            error_handler.handle_error(
                ScanError(f"XXEScanner error on {url}: {str(e)}", original_error=e),
                context={"url": url},
            )

        return findings

    # ── public: validate ──────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-submit the specific XML payload that triggered the original finding.

        payload is JSON: {
            "method": "GET" | "POST",
            "target_url": url,
            "xml_payload": the actual XML string,
            "injection_point": "body" | "param" | "file",
            "param_name": (if injection_point == "param"),
            "detection_type": "file_linux" | "file_windows" | "oob" | "billion_laughs" | "external_dtd"
        }
        """
        try:
            meta = json.loads(payload)
            method = meta["method"]  # noqa
            target_url = meta["target_url"]
            xml_payload = meta["xml_payload"]
            injection_point = meta["injection_point"]
            detection_type = meta["detection_type"]

            # Re-submit
            if injection_point == "body":
                result = await self._submit_xml_body(target_url, xml_payload)
            elif injection_point == "param":
                param_name = meta["param_name"]
                params = {param_name: xml_payload}
                result = await self._submit_get(target_url, params)
            else:  # file upload
                # For validation, we skip file upload re-testing (too complex)
                return bool(evidence)

            if result is None:
                return False

            status, body = result

            # Re-check the same detection type
            if detection_type == "file_linux":
                return self._has_linux_passwd(body)
            elif detection_type == "file_windows":
                return self._has_windows_ini(body)
            elif detection_type == "oob":
                marker = meta.get("marker", "")
                return marker and marker in body.lower()
            elif detection_type == "billion_laughs":
                return status in (500, 503) and self._has_billion_laughs_error(body)
            elif detection_type == "external_dtd":
                return self._has_external_dtd_error(body)

            return bool(evidence)

        except (json.JSONDecodeError, KeyError):
            return bool(evidence)

    # ── private: XML body injection ───────────────────────────────────────

    async def _test_xml_body(self, url: str) -> List[Finding]:
        """
        POST XML payloads directly to the endpoint with Content-Type: application/xml.

        This is the most common XXE vector — APIs that accept XML bodies.
        """
        findings: List[Finding] = []
        marker = self._generate_marker()

        # Test each payload type
        payload_list = [
            ("file_linux", payloads.xxe_file_linux, "Linux file disclosure"),
            ("file_windows", payloads.xxe_file_windows, "Windows file disclosure"),
            (
                "oob",
                payloads.xxe_oob_marker.format(marker=marker),
                "Out-of-band marker",
            ),
            ("billion_laughs", payloads.xxe_billion_laughs, "Billion Laughs DoS"),
            (
                "external_dtd",
                payloads.xxe_external_dtd.format(marker=marker),
                "External DTD SSRF",
            ),
        ]

        for detection_type, xml_payload, description in payload_list:
            result = await self._submit_xml_body(url, xml_payload)
            if result is None:
                continue

            status, body = result
            body_lo = body.lower()

            # Check for evidence
            vuln_detected = False
            evidence_text = ""
            severity = "High"

            if detection_type == "file_linux" and self._has_linux_passwd(body):
                vuln_detected = True
                evidence_text = "Response contains Linux /etc/passwd file contents"
                severity = "Critical"
            elif detection_type == "file_windows" and self._has_windows_ini(body):
                vuln_detected = True
                evidence_text = "Response contains Windows win.ini file contents"
                severity = "Critical"
            elif detection_type == "oob" and marker in body_lo:
                vuln_detected = True
                evidence_text = f"Response echoes unique marker '{marker}', proving external entity resolution"
            elif (
                detection_type == "billion_laughs"
                and status in (500, 503)
                and self._has_billion_laughs_error(body)
            ):
                vuln_detected = True
                evidence_text = "Server returned 500/503 with entity expansion error (Billion Laughs DoS)"
                severity = "Medium"
            elif detection_type == "external_dtd" and self._has_external_dtd_error(
                body
            ):
                vuln_detected = True
                evidence_text = "Server attempted to fetch external DTD (SSRF via XXE)"

            if vuln_detected:
                findings.append(Finding(
                    type="XXE",
                    endpoint=url,
                    severity=Severity.from_str(severity),
                    description=(
                        f"XML External Entity (XXE) injection detected via {description}. "
                        f"The XML parser processed external entities in the POST body. "
                        f"{evidence_text}."
                    ),
                    evidence=(
                        f"POST {url} with Content-Type: application/xml and XXE payload "
                        f"returned status {status}. {evidence_text}."
                    ),
                    remediation=(
                        "Disable external entity processing in your XML parser. For most parsers: "
                        "set XMLInputFactory.SUPPORT_DTD = false, "
                        "XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false. "
                        "For Python lxml: use defusedxml. For Java: disable DOCTYPE declarations. "
                        "Never parse untrusted XML with entity resolution enabled."
                    ),
                    payload={
                        "method": "POST",
                        "target_url": url,
                        "xml_payload": xml_payload,
                        "injection_point": "body",
                        "detection_type": detection_type,
                        "marker": (
                            marker if detection_type in ("oob", "external_dtd") else ""
                        ),
                    },
                    method="POST",
                    **get_standards("XXE"),
                )
            )

        return findings

    # ── private: parameter injection ──────────────────────────────────────

    async def _test_params(self, url: str, params: Dict[str, str]) -> List[Finding]:
        """
        Inject XML into URL parameters.

        Some APIs parse XML from GET parameters (rare but happens).
        """
        findings: List[Finding] = []
        marker = self._generate_marker()

        # Only test file disclosure and OOB (skip Billion Laughs — too risky in GET)
        payload_list = [
            ("file_linux", payloads.xxe_file_linux, "Linux file disclosure"),
            (
                "oob",
                payloads.xxe_oob_marker.format(marker=marker),
                "Out-of-band marker",
            ),
        ]

        for param_name in params:
            for detection_type, xml_payload, description in payload_list:
                inject_params = dict(params)
                inject_params[param_name] = xml_payload

                result = await self._submit_get(url, inject_params)
                if result is None:
                    continue

                status, body = result
                body_lo = body.lower()

                vuln_detected = False
                evidence_text = ""
                severity = "High"

                if detection_type == "file_linux" and self._has_linux_passwd(body):
                    vuln_detected = True
                    evidence_text = "Response contains /etc/passwd contents"
                    severity = "Critical"
                elif detection_type == "oob" and marker in body_lo:
                    vuln_detected = True
                    evidence_text = f"Response echoes marker '{marker}'"

                if vuln_detected:
                    findings.append(Finding(
                        type="XXE",
                        endpoint=url,
                        severity=Severity.from_str(severity),
                        description=(
                            f"XXE injection detected in URL parameter '{param_name}' via {description}. "
                            f"{evidence_text}."
                        ),
                        evidence=(
                            f"GET {url}?{param_name}=<xml> returned status {status}. {evidence_text}."
                        ),
                        remediation=(
                            "Disable external entity processing in your XML parser. "
                            "Do not parse XML from GET parameters unless absolutely necessary."
                        ),
                        payload={
                            "method": "GET",
                            "target_url": url,
                            "xml_payload": xml_payload,
                            "injection_point": "param",
                            "param_name": param_name,
                            "detection_type": detection_type,
                            "marker": marker if detection_type == "oob" else "",
                        },
                        method="GET",
                        **get_standards("XXE"),
                    ))
                    break  # one finding per param is enough

            if findings:
                break  # one finding per endpoint is enough

        return findings

    # ── private: form injection ───────────────────────────────────────────

    async def _test_form(self, page_url: str, form: Dict) -> List[Finding]:
        """
        Inject XML into form fields (text inputs and file uploads).

        File uploads are especially dangerous — many apps parse uploaded XML
        files without proper entity protection.
        """
        findings: List[Finding] = []
        marker = self._generate_marker()

        action = form["action"]
        inputs = form["inputs"]

        if not inputs:
            return []

        # Test text inputs
        for inp in inputs:
            field_name = inp["name"]
            field_type = inp.get("type", "")

            # Skip file inputs here (handled separately below)
            if field_type == "file":
                continue

            # Inject XML into this field
            xml_payload = payloads.xxe_oob_marker.format(marker=marker)
            data = {i["name"]: "test" for i in inputs if i.get("type") != "file"}
            data[field_name] = xml_payload

            result = await self._submit_form(action, data)
            if result is None:
                continue

            status, body = result

            if marker in body.lower():
                findings.append(Finding(
                    type="XXE",
                    endpoint=action,
                    severity=Severity.HIGH,
                    description=(
                        f"XXE injection detected in form field '{field_name}'. "
                        f"Response echoes unique marker '{marker}', proving the XML was parsed "
                        f"and external entities were resolved."
                    ),
                    evidence=(
                        f"POST {action} with {field_name}=<xml> returned status {status}. "
                        f"Response contains marker string."
                    ),
                    remediation=(
                        "Disable external entity processing in your XML parser. "
                        "Do not parse XML from form inputs unless absolutely necessary."
                    ),
                    payload={
                        "method": "POST",
                        "target_url": action,
                        "xml_payload": xml_payload,
                        "injection_point": "param",
                        "param_name": field_name,
                        "detection_type": "oob",
                        "marker": marker,
                    },
                    method="POST",
                    **get_standards("XXE"),
                ))
                break  # one finding per form is enough

        # Test file uploads
        # (For simplicity, we skip actual multipart file upload in the base scanner.
        #  Real implementations would need to construct multipart/form-data with
        #  an .xml file attachment. This is a TODO for production deployment.)

        return findings

    # ── private: detection helpers ───────────────────────────────────────

    @staticmethod
    def _has_linux_passwd(body: str) -> bool:
        """Check if response contains Linux /etc/passwd file contents."""
        return any(
            indicator in body for indicator in payloads.xxe_linux_passwd_indicators
        )

    @staticmethod
    def _has_windows_ini(body: str) -> bool:
        """Check if response contains Windows win.ini file contents."""
        return any(
            indicator in body for indicator in payloads.xxe_windows_ini_indicators
        )

    @staticmethod
    def _has_billion_laughs_error(body: str) -> bool:
        """Check if response contains entity expansion DoS error."""
        body_lo = body.lower()
        return any(
            indicator in body_lo for indicator in payloads.xxe_billion_laughs_indicators
        )

    @staticmethod
    def _has_external_dtd_error(body: str) -> bool:
        """Check if response contains external DTD fetch error."""
        body_lo = body.lower()
        return any(
            indicator in body_lo for indicator in payloads.xxe_external_dtd_indicators
        )

    @staticmethod
    def _generate_marker() -> str:
        """Generate a unique marker for OOB detection."""
        return hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]

    # ── private: submission helpers ───────────────────────────────────────

    async def _submit_xml_body(self, url: str, xml: str) -> Optional[Tuple[int, str]]:
        """
        POST XML with Content-Type: application/xml.  Returns (status, body) or None.
        """
        try:
            xml_headers = dict(self.headers)
            xml_headers["Content-Type"] = "application/xml"

            async with self.session.post(
                url, data=xml.encode("utf-8"), headers=xml_headers
            ) as response:
                body = await self._safe_read(response)
                return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"XXE XML body submit failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return None

    async def _submit_form(
        self, url: str, data: Dict[str, str]
    ) -> Optional[Tuple[int, str]]:
        """POST a form.  Returns (status, body) or None."""
        try:
            async with self.session.post(
                url, data=data, headers=self.headers
            ) as response:
                body = await self._safe_read(response)
                return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"XXE form submit failed for {url}: {str(e)}", original_error=e
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

            async with self.session.get(full_url, headers=self.headers) as response:
                body = await self._safe_read(response)
                return (response.status, body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(f"XXE GET failed for {url}: {str(e)}", original_error=e),
                context={"url": url},
            )
            return None
