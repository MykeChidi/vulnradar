# tests/security/conftest.py - Pytest fixtures for security tests

import pytest
from tests.factories import (
    BLIND_SQLI_PAYLOADS,
    DOM_XSS_PAYLOADS,
    COMMAND_INJECTION_BLIND_PAYLOADS,
    SSRF_BYPASS_PAYLOADS,
    ENCODING_BYPASS_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    FILE_INCLUSION_PAYLOADS,
)

# Define header injection payloads since they're not in payloads.py
header_injection_payloads_list = [
    "test\r\nSet-Cookie: admin=true",
    "test\r\nContent-Length: 0",
    "test\nLocation: http://attacker.com",
    "test\r\nX-Original-URL: /admin",
    "test\r\nX-Rewrite-URL: /admin",
]


class InputValidatorBypassTester:
    """Helper class for testing input validator bypass techniques."""
    
    def __init__(self):
        """Initialize the tester with payload mappings."""
        # Import the payloads here to avoid fixture conflicts
        from vulnradar.scanners.payloads import (
            ssrf_payloads as ssrf_payload_data,
            path_traversal_payloads as path_traversal_payload_data,
        )
        
        self.payload_map = {
            "ssrf": ssrf_payload_data,
            "path_traversal": path_traversal_payload_data,
            "header_injection": header_injection_payloads_list,
        }
    
    def get_payloads(self, payload_type: str):
        """Get payloads for a specific type."""
        return self.payload_map.get(payload_type, [])


class XSSReportValidator:
    """Helper class for validating XSS prevention in reports."""
    
    def contains_unescaped_html(self, content: str) -> bool:
        """Check if content contains unescaped HTML that could lead to XSS."""
        # For the test, we want to detect if content contains dangerous HTML tags
        # that SHOULD be escaped in reports
        dangerous_patterns = [
            "<script",
            "<iframe",
            "<img",
            "<svg",
            "onerror=",
            "onload=",
            "onclick=",
            "javascript:",
        ]
        
        content_lower = content.lower()
        for pattern in dangerous_patterns:
            if pattern in content_lower:
                # The pattern exists - this should be escaped in reports
                # Return True to indicate unescaped HTML is present
                return True
        
        return False


@pytest.fixture
def blind_sqli_payloads():
    """Provide blind SQLi payloads for testing."""
    return BLIND_SQLI_PAYLOADS


@pytest.fixture
def dom_xss_payloads():
    """Provide DOM XSS payloads for testing."""
    return DOM_XSS_PAYLOADS


@pytest.fixture
def command_injection_blind_payloads():
    """Provide command injection payloads for testing."""
    return COMMAND_INJECTION_BLIND_PAYLOADS


@pytest.fixture
def ssrf_bypass_payloads():
    """Provide SSRF bypass payloads for testing."""
    return SSRF_BYPASS_PAYLOADS


@pytest.fixture
def encoding_bypass_payloads():
    """Provide encoding bypass payloads for testing."""
    return ENCODING_BYPASS_PAYLOADS


@pytest.fixture
def header_injection_payloads():
    """Provide header injection payloads for testing."""
    return header_injection_payloads_list


@pytest.fixture
def path_traversal_payloads():
    """Provide path traversal payloads for testing."""
    return PATH_TRAVERSAL_PAYLOADS


@pytest.fixture
def file_inclusion_payloads():
    """Provide file inclusion payloads for testing."""
    return FILE_INCLUSION_PAYLOADS


@pytest.fixture
def input_validator_bypass_tester():
    """Provide an input validator bypass tester."""
    return InputValidatorBypassTester()


@pytest.fixture
def xss_report_validator():
    """Provide an XSS report validator."""
    return XSSReportValidator()
