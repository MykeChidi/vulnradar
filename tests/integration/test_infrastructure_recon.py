# tests/integration/test_infrastructure_recon.py - Infrastructure reconnaissance test suite

from vulnradar.reconn.infrastructure import InfrastructureRelationshipMapper
import pytest
from unittest.mock import AsyncMock


@pytest.mark.integration
class TestInfrastructureRelationshipMapper:
    """Integration tests for infrastructure relationship mapping."""
    
    @pytest.mark.asyncio
    async def test_mapper_initialization(self, mock_target, mock_options):
        """Test mapper initialization."""
        mapper = InfrastructureRelationshipMapper(mock_target, mock_options)
        
        assert mapper.target == mock_target
        assert mapper.options == mock_options
    
    @pytest.mark.asyncio
    @pytest.mark.requires_network
    async def test_enumerate_subdomains(self, mock_target, mock_options):
        """Test subdomain enumeration."""
        mapper = InfrastructureRelationshipMapper(mock_target, mock_options)
        
        # Mock the methods
        mapper._check_cert_transparency = AsyncMock(return_value=["sub1.example.com"])
        mapper._dns_bruteforce = AsyncMock(return_value=["www.example.com"])
        mapper._search_engine_discovery = AsyncMock(return_value=[])
        mapper._try_zone_transfer = AsyncMock(return_value=[])
        mapper._verify_subdomains = AsyncMock(return_value=["www.example.com"])
        
        results = await mapper._enumerate_subdomains()
        
        assert "found" in results
        assert "total_count" in results
