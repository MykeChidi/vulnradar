# tests/integration/test_misc_recon.py - Miscellaneous reconnaissance test suite

from vulnradar.reconn.misc import MiscellaneousAnalyzer
import pytest
from unittest.mock import AsyncMock
from aioresponses import aioresponses


@pytest.mark.integration
class TestMiscellaneousAnalyzer:
    """Integration tests for miscellaneous analysis."""
    
    @pytest.mark.asyncio
    async def test_analyzer_initialization(self, mock_target, mock_options):
        """Test analyzer initialization."""
        analyzer = MiscellaneousAnalyzer(mock_target, mock_options)
        
        assert analyzer.target == mock_target
        assert analyzer.options == mock_options
    
    @pytest.mark.asyncio
    async def test_analyze_error_responses(self, mock_target, mock_options):
        """Test error response analysis."""
        analyzer = MiscellaneousAnalyzer(mock_target, mock_options)
        
        with aioresponses() as mocked:
            mocked.get("https://example.com", status=404, body="<html>404 Not Found</html>")
            results = await analyzer._analyze_error_responses()
        
        assert isinstance(results, dict)

