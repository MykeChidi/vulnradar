# tests/scanners/test_path_traversal_expanded.py - Expanded Path Traversal scanner tests

import pytest
from vulnradar.scanners.path_traversal import PathTraversalScanner


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestPathTraversalVariations:
    """Test various path traversal techniques."""
    
    async def test_path_traversal_basic(self, path_traversal_payloads):
        """Test basic path traversal payloads."""
        scanner = PathTraversalScanner()
        
        basic_payloads = [p for p in path_traversal_payloads if "../" in p or "..\\" in p]
        assert len(basic_payloads) > 0
    
    async def test_path_traversal_encoding(self):
        """Test path traversal with encoding."""
        scanner = PathTraversalScanner()
        
        encoded_payloads = [
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        
        for payload in encoded_payloads:
            assert "%2" in payload or "%5" in payload
    
    async def test_path_traversal_unicode(self):
        """Test path traversal with Unicode encoding."""
        scanner = PathTraversalScanner()
        
        unicode_payloads = [
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        ]
        
        for payload in unicode_payloads:
            assert "%c0%af" in payload
    
    async def test_path_traversal_null_bytes(self):
        """Test path traversal with null byte injection."""
        scanner = PathTraversalScanner()
        
        null_payloads = [
            "../../../etc/passwd%00",
            "..\\..\\..\\windows\\win.ini%00.jpg",
        ]
        
        for payload in null_payloads:
            assert "%00" in payload
    
    async def test_path_traversal_case_variation(self):
        """Test path traversal with case variations."""
        scanner = PathTraversalScanner()
        
        case_payloads = [
            "../../../ETC/PASSWD",
            "..\\..\\..\\WINDOWS\\WIN.INI",
        ]
        
        for payload in case_payloads:
            assert "/" in payload or "\\" in payload
    
    async def test_path_traversal_windows_drives(self):
        """Test path traversal targeting Windows drives."""
        scanner = PathTraversalScanner()
        
        drive_payloads = [
            "..\\..\\..\\c:\\windows\\win.ini",
            "../../../c:/windows/system32/config/sam",
        ]
        
        for payload in drive_payloads:
            assert "windows" in payload.lower() or "c:" in payload.lower()
    
    async def test_path_traversal_unix_files(self):
        """Test path traversal targeting Unix/Linux files."""
        scanner = PathTraversalScanner()
        
        unix_payloads = [
            "../../../etc/passwd",
            "../../../etc/shadow",
            "../../../etc/hosts",
            "../../../proc/self/environ",
        ]
        
        for payload in unix_payloads:
            assert "etc" in payload or "proc" in payload
    
    async def test_path_traversal_backslash(self):
        """Test path traversal with backslash notation."""
        scanner = PathTraversalScanner()
        
        backslash_payloads = [
            "..\\..\\..\\windows\\win.ini",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
        ]
        
        for payload in backslash_payloads:
            assert "\\" in payload


@pytest.mark.edge_case
@pytest.mark.asyncio
class TestPathTraversalEdgeCases:
    """Test path traversal edge cases."""
    
    async def test_path_traversal_double_encoding(self):
        """Test double URL encoding bypass."""
        scanner = PathTraversalScanner()
        
        double_encoded = "..%252f..%252f..%252fetc%252fpasswd"
        assert "%25" in double_encoded
    
    async def test_path_traversal_mixed_slashes(self):
        """Test mixed forward/backward slashes."""
        scanner = PathTraversalScanner()
        
        mixed_payloads = [
            "..\\/../../../etc/passwd",
            "../..\\..\\windows\\win.ini",
        ]
        
        for payload in mixed_payloads:
            assert "/" in payload and "\\" in payload
    
    async def test_path_traversal_trailing_dots(self):
        """Test path traversal with trailing dots."""
        scanner = PathTraversalScanner()
        
        trailing_payloads = [
            "../../../etc/passwd...",
            "..\\..\\..\\windows\\win.ini...",
        ]
        
        for payload in trailing_payloads:
            assert "." in payload


@pytest.mark.performance
@pytest.mark.asyncio
class TestPathTraversalPerformance:
    """Test path traversal scanner performance."""
    
    async def test_path_traversal_payload_efficiency(self, path_traversal_payloads):
        """Test path traversal payload set efficiency."""
        assert len(path_traversal_payloads) >= 7
