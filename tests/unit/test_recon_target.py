# tests/unit/test_recon_target.py - Recon Target test suite

from vulnradar.reconn._target import ReconTarget
import pytest


@pytest.mark.unit
class TestReconTarget:
    """Unit tests for ReconTarget class."""
    
    def test_target_initialization(self):
        """Test target initialization with valid data."""
        target = ReconTarget(
            url="https://example.com",
            hostname="example.com",
            ip="93.184.216.34",
            port=443,
            is_https=True
        )
        
        assert target.url == "https://example.com"
        assert target.hostname == "example.com"
        assert target.ip == "93.184.216.34"
        assert target.port == 443
        assert target.is_https is True
    
    def test_target_default_values(self):
        """Test target initialization with defaults."""
        target = ReconTarget(
            url="http://example.com",
            hostname="example.com"
        )
        
        assert target.port == 80
        assert target.is_https is False
        assert target.ip is None