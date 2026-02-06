# tests/unit/test_csrf.py - CSRF scanner test suite

from vulnradar.scanners.csrf import CSRFScanner
import pytest


@pytest.mark.unit
class TestCSRFScanner:
    """Unit tests for CSRF scanner."""
    
    def test_scanner_initialization(self):
        """Test scanner initializes with correct tokens."""
        scanner = CSRFScanner()
        
        assert len(scanner.csrf_token_names) > 0
        assert "csrf_token" in scanner.csrf_token_names
    
    def test_has_csrf_token(self):
        """Test CSRF token detection in forms."""
        scanner = CSRFScanner()
        
        # Form with CSRF token
        form_with_token = {
            "inputs": [
                {"name": "csrf_token", "value": "abc123", "type": "hidden"}
            ]
        }
        assert scanner._has_csrf_token(form_with_token)
        
        # Form without CSRF token
        form_without_token = {
            "inputs": [
                {"name": "username", "value": "", "type": "text"}
            ]
        }
        assert not scanner._has_csrf_token(form_without_token)

