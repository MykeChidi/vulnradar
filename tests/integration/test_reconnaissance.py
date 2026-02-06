# tests/integration/test_reconnaissance.py - Reconnaissance manager test suite

from vulnradar.recon import ReconManager
import pytest
from unittest.mock import AsyncMock


@pytest.mark.integration
class TestReconManager:
    """Integration tests for reconnaissance."""
    
    @pytest.mark.asyncio
    async def test_recon_manager_initialization(self, mock_options):
        """Test ReconManager initialization."""
        manager = ReconManager("https://example.com", mock_options)
        
        assert manager.target.url == "https://example.com"
        assert manager.target.hostname == "example.com"
        assert manager.network_analyzer is not None
        assert manager.security_analyzer is not None
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_run_reconnaissance(self, mock_options):
        """Test full reconnaissance run."""
        manager = ReconManager("https://example.com", mock_options)
        
        # Mock the analyzers
        mock_network_result = {"dns": {"A": ["93.184.216.34"]}}
        mock_security_result = {"waf": {"detected": False}}
        mock_webapp_result = {"technologies": []}
        mock_infra_result = {"subdomains": []}
        mock_misc_result = {"error_handling": {}}
        
        manager.network_analyzer.analyze = AsyncMock(return_value=mock_network_result)
        manager.security_analyzer.analyze = AsyncMock(return_value=mock_security_result)
        manager.webapp_analyzer.analyze = AsyncMock(return_value=mock_webapp_result)
        manager.infra_mapper.analyze = AsyncMock(return_value=mock_infra_result)
        manager.misc_analyzer.analyze = AsyncMock(return_value=mock_misc_result)
        
        results = await manager.run_reconnaissance()
        
        assert "network" in results
        assert "security" in results
        assert "webapp" in results
        assert "infrastructure" in results
        assert "miscellaneous" in results
