# tests/integration/test_webapp.py - Web app analyzer test suite

from vulnradar.reconn.webapp import WebApplicationAnalyzer
import pytest
from aioresponses import aioresponses


@pytest.mark.integration
class TestWebApplicationAnalyzer:
    """Integration tests for web application analysis."""
    
    @pytest.mark.asyncio
    async def test_analyzer_initialization(self, mock_target, mock_options):
        """Test analyzer initialization."""
        analyzer = WebApplicationAnalyzer(mock_target, mock_options)
        
        assert analyzer.target == mock_target
        assert analyzer.options == mock_options
    
    @pytest.mark.asyncio
    async def test_detect_technologies(self, mock_target, mock_options, sample_html):
        """Test technology detection."""
        analyzer = WebApplicationAnalyzer(mock_target, mock_options)
        
        with aioresponses() as mocked:
            mocked.get("https://example.com/", status=200, body=sample_html, headers={"Server": "nginx"})
            results = await analyzer._detect_technologies()
        
        assert results is not None
    
    @pytest.mark.asyncio
    async def test_analyze_robots_txt(self, mock_target, mock_options, sample_robots_txt):
        """Test robots.txt analysis."""
        analyzer = WebApplicationAnalyzer(mock_target, mock_options)
        
        with aioresponses() as mocked:
            mocked.get("https://example.com/robots.txt", status=200, body=sample_robots_txt)
            results = await analyzer._analyze_robots_txt()
        
        assert isinstance(results, dict)
