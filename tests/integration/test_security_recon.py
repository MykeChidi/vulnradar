# tests/integration/test_security_recon.py - Security infrastructure analyzer test suite

from vulnradar.reconn.security import SecurityInfrastructureAnalyzer
import pytest
from aioresponses import aioresponses


@pytest.mark.integration
class TestSecurityInfrastructureAnalyzer:
    """Integration tests for security infrastructure analysis."""
    
    @pytest.mark.asyncio
    async def test_analyzer_initialization(self, mock_target, mock_options):
        """Test analyzer initialization."""
        analyzer = SecurityInfrastructureAnalyzer(mock_target, mock_options)
        
        assert analyzer.target == mock_target
        assert analyzer.options == mock_options
    
    @pytest.mark.asyncio
    async def test_detect_waf(self, mock_target, mock_options):
        """Test WAF detection."""
        analyzer = SecurityInfrastructureAnalyzer(mock_target, mock_options)
        
        with aioresponses() as mocked:
            mocked.get("https://example.com", status=200, headers={"cf-ray": "123456"})
            results = await analyzer._detect_waf()
        
        assert isinstance(results, dict)
    
    @pytest.mark.asyncio
    async def test_analyze_security_headers(self, mock_target, mock_options):
        """Test security headers analysis."""
        analyzer = SecurityInfrastructureAnalyzer(mock_target, mock_options)
        
        with aioresponses() as mocked:
            mocked.get(
                "https://example.com",
                status=200,
                headers={
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff"
                }
            )
            results = await analyzer._analyze_security_headers()
        
        assert isinstance(results, dict)

