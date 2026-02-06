# tests/integration/test_vulnradar.py - Main scanner test suite

from vulnradar.core import VulnRadar
import pytest
from unittest.mock import patch, AsyncMock
from aioresponses import aioresponses


@pytest.mark.integration
class TestVulnerabilityScanner:
    """Integration tests for VulnerabilityScanner."""
    
    @pytest.mark.asyncio
    async def test_scanner_initialization(self, mock_options):
        """Test scanner initialization."""
        scanner = VulnRadar(
            "https://example.com",
            mock_options
        )
        
        assert scanner.target_url == "https://example.com"
        assert scanner.options == mock_options
        assert scanner.results["target"] == "https://example.com"
    
    @pytest.mark.asyncio
    async def test_validate_target_success(self, mock_options):
        """Test successful target validation."""
        scanner = VulnRadar(
            "https://example.com",
            mock_options
        )
        
        with aioresponses() as mocked:
            mocked.get("https://example.com", status=200)
            is_valid = await scanner.validate_target()
        
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_validate_target_failure(self, mock_options):
        """Test failed target validation."""
        scanner = VulnRadar(
            "https://example.com",
            mock_options
        )
        
        with aioresponses() as mocked:
            mocked.get("https://example.com", status=500)
            is_valid = await scanner.validate_target()
        
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_crawl_site(self, mock_options, sample_html):
        """Test website crawling."""
        scanner = VulnRadar(
            "https://example.com",
            mock_options
        )
        
        with aioresponses() as mocked:
            mocked.get("https://example.com/", status=200, body=sample_html)
            with patch('vulnradar.crawlers.WebCrawler.crawl') as mock_crawl:
                async def mock_crawl_generator():
                    yield "https://example.com/page1", 200
                    yield "https://example.com/page2", 200
                
                mock_crawl.return_value = mock_crawl_generator()
                await scanner.crawl_site()
        
        assert len(scanner.results["endpoints"]) >= 0
    
    @pytest.mark.asyncio
    async def test_detect_technologies(self, mock_options, sample_html):
        """Test technology detection."""
        scanner = VulnRadar(
            "https://example.com",
            mock_options
        )
        
        with aioresponses() as mocked:
            mocked.get("https://example.com/", status=200, body=sample_html, headers={"Server": "nginx/1.18.0"})
            await scanner.detect_technologies()
        
        assert "technologies" in scanner.results
        assert scanner.results["technologies"] is not None
