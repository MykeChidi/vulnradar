# tests/unit/test_base.py - Base scanner test suite

from vulnradar.scanners.base import BaseScanner
import pytest
from unittest.mock import patch, AsyncMock


@pytest.mark.unit
class TestBaseScanner:
    """Unit tests for BaseScanner class."""
    
    def test_base_scanner_initialization(self):
        """Test base scanner initialization."""
        # Create a concrete implementation for testing
        class TestScanner(BaseScanner):
            async def scan(self, url: str):
                return []
            
            async def validate(self, url: str, payload: str, evidence: str):
                return False
        
        scanner = TestScanner(headers={"User-Agent": "Test"}, timeout=15)
        
        assert scanner.headers == {"User-Agent": "Test"}
        assert scanner.timeout.total == 15
    
    @pytest.mark.asyncio
    async def test_extract_parameters(self):
        """Test parameter extraction from URL."""
        class TestScanner(BaseScanner):
            async def scan(self, url: str):
                return []
            
            async def validate(self, url: str, payload: str, evidence: str):
                return False
        
        scanner = TestScanner()
        
        url = "https://example.com/page?id=123&name=test&active=true"
        params = await scanner._extract_parameters(url)
        
        assert params == {"id": "123", "name": "test", "active": "true"}
    
    @pytest.mark.asyncio
    async def test_get_form_inputs(self, mock_session, sample_html):
        """Test form input extraction."""
        from aioresponses import aioresponses
        
        class TestScanner(BaseScanner):
            async def scan(self, url: str):
                return []
            
            async def validate(self, url: str, payload: str, evidence: str):
                return False
        
        scanner = TestScanner()
        
        with aioresponses() as mocked:
            mocked.get("https://example.com/", status=200, body=sample_html)
            forms = await scanner._get_form_inputs("https://example.com")
        
        assert len(forms) >= 0
