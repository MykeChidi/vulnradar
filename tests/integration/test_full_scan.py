# tests/integration/test_full_scan.py - Full scan test suite

from vulnradar.core import VulnRadar
import pytest
from unittest.mock import AsyncMock, Mock


@pytest.mark.integration
@pytest.mark.slow
class TestFullScan:
    """Integration tests for full scanning workflow."""
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self, mock_options, temp_output_dir):
        """Test complete scan workflow."""
        mock_options["output_dir"] = str(temp_output_dir)
        
        scanner = VulnRadar("https://example.com", mock_options)
        
        # Mock all major components
        scanner.validate_target = AsyncMock(return_value=True)
        scanner.reconnaissance = AsyncMock()
        scanner.crawl_site = AsyncMock()
        scanner.detect_technologies = AsyncMock()
        scanner.run_vulnerability_scans = AsyncMock()
        scanner.generate_reports = Mock()
        
        # Mock results
        scanner.results = {
            "target": "https://example.com",
            "scan_time": "2025-01-01 00:00:00",
            "vulnerabilities": [],
            "endpoints": ["https://example.com/"],
            "technologies": {},
            "reconnaissance": {}
        }
        
        results = await scanner.scan()
        
        assert results["target"] == "https://example.com"
        assert "vulnerabilities" in results
        assert "endpoints" in results
    
    @pytest.mark.asyncio
    async def test_scan_with_vulnerabilities(self, mock_options, 
                                            vulnerability_sample, temp_output_dir):
        """Test scan that finds vulnerabilities."""
        mock_options["output_dir"] = str(temp_output_dir)
        
        scanner = VulnRadar("https://example.com", mock_options)
        
        # Mock to return vulnerabilities
        scanner.validate_target = AsyncMock(return_value=True)
        scanner.reconnaissance = AsyncMock()
        scanner.crawl_site = AsyncMock()
        scanner.detect_technologies = AsyncMock()
        scanner.generate_reports = Mock()
        
        async def mock_vuln_scan():
            scanner.results["vulnerabilities"] = [vulnerability_sample]
        
        scanner.run_vulnerability_scans = mock_vuln_scan
        
        results = await scanner.scan()
        
        assert len(results["vulnerabilities"]) > 0
        assert results["vulnerabilities"][0]["type"] == "SQL Injection"
