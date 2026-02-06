# tests/unit/test_xss.py - XSS scanner test suite

from vulnradar.scanners.xss import XSSScanner
import pytest


@pytest.mark.unit
class TestXSSScanner:
    """Unit tests for XSSScanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner initializes with payloads."""
        scanner = XSSScanner()
        
        assert len(scanner.payloads) > 0
    
    def test_check_for_xss_reflection(self):
        """Test XSS reflection detection."""
        scanner = XSSScanner()
        
        payload = "<script>alert('xss')</script>"
        
        # Should detect direct reflection
        assert scanner._check_for_xss_reflection(
            f"Your search: {payload}",
            payload
        )
        
        # Should detect HTML encoded reflection
        encoded = "&lt;script&gt;alert('xss')&lt;/script&gt;"
        assert scanner._check_for_xss_reflection(
            f"Your search: {encoded}",
            payload
        )
        
        # Should not detect false positives
        assert not scanner._check_for_xss_reflection(
            "Welcome to our website",
            payload
        )
    
    def test_extract_payload_parts(self):
        """Test payload part extraction."""
        scanner = XSSScanner()
        
        payload = "<script>alert('test')</script>"
        parts = scanner._extract_payload_parts(payload)
        
        assert "script" in parts
        assert "alert" in parts
    
    def test_extract_reflection_snippet(self):
        """Test reflection snippet extraction."""
        scanner = XSSScanner()
        
        payload = "<script>alert('xss')</script>"
        response = f"Search results for: {payload} not found"
        
        snippet = scanner._extract_reflection_snippet(response, payload)
        
        assert payload in snippet
        assert ">>>" in snippet and "<<<" in snippet
