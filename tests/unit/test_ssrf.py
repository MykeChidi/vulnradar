# tests/unit/test_ssrf.py - SSRF scanner test suite

from vulnradar.scanners.ssrf import SSRFScanner
import pytest


@pytest.mark.unit
class TestSSRFScanner:
    """Unit tests for SSRF scanner."""
    
    def test_scanner_initialization(self):
        """Test scanner initializes with payloads."""
        scanner = SSRFScanner()
        
        assert len(scanner.payloads) > 0
        assert len(scanner.vulnerable_params) > 0
        assert len(scanner.indicators) > 0
