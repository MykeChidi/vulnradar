# tests/unit/test_path_traversal.py - Path Traversal scanner test suite

from vulnradar.scanners.path_traversal import PathTraversalScanner
import pytest


@pytest.mark.unit
class TestPathTraversalScanner:
    """Unit tests for path traversal scanner."""
    
    def test_scanner_initialization(self):
        """Test scanner initializes with payloads."""
        scanner = PathTraversalScanner()
        
        assert len(scanner.payloads) > 0
        assert len(scanner.detection_patterns) > 0
        assert len(scanner.vulnerable_params) > 0
    
    @pytest.mark.asyncio
    async def test_detect_path_traversal(self):
        """Test path traversal detection."""
        scanner = PathTraversalScanner()
        
        # Test with /etc/passwd content
        response = "root:x:0:0:root:/root:/bin/bash"
        payload = "../../../etc/passwd"
        
        is_vulnerable = await scanner._detect_path_traversal(response, payload)
        assert is_vulnerable is True
        
        # Test with non-vulnerable response
        response = "Welcome to our website"
        is_vulnerable = await scanner._detect_path_traversal(response, payload)
        assert is_vulnerable is False
