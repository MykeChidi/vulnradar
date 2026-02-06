# tests/integration/test_network_recon.py - Network infrastructure analyzer test suite

from vulnradar.reconn.network import NetworkInfrastructureAnalyzer
import pytest
from unittest.mock import patch


@pytest.mark.integration
class TestNetworkInfrastructureAnalyzer:
    """Integration tests for network infrastructure analysis."""
    
    @pytest.mark.asyncio
    async def test_analyzer_initialization(self, mock_target, mock_options):
        """Test analyzer initialization."""
        analyzer = NetworkInfrastructureAnalyzer(mock_target, mock_options)
        
        assert analyzer.target == mock_target
        assert analyzer.options == mock_options
        assert analyzer.logger is not None
    
    @pytest.mark.asyncio
    async def test_analyze_dns(self, mock_target, mock_options, mock_dns_resolver):
        """Test DNS analysis."""
        analyzer = NetworkInfrastructureAnalyzer(mock_target, mock_options)
        analyzer.dns_resolver = mock_dns_resolver
        
        results = await analyzer._analyze_dns()
        
        assert "A" in results
        assert len(results["A"]) > 0
    
    @pytest.mark.asyncio
    @pytest.mark.requires_root
    async def test_scan_ports(self, mock_target, mock_options, mock_nmap_scanner):
        """Test port scanning."""
        analyzer = NetworkInfrastructureAnalyzer(mock_target, mock_options)
        
        with patch('nmap.PortScanner', return_value=mock_nmap_scanner):
            results = await analyzer._scan_ports()
        
        assert isinstance(results, dict)
        if "error" not in results:
            assert len(results) > 0
