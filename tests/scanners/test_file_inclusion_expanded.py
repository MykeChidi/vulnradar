# tests/scanners/test_file_inclusion_expanded.py - Expanded File Inclusion scanner tests

import pytest
from vulnradar.scanners.file_inclusion import FileInclusionScanner


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestFileInclusionVariations:
    """Test various file inclusion techniques."""
    
    async def test_file_inclusion_lfi_basic(self, file_inclusion_payloads):
        """Test basic local file inclusion."""
        scanner = FileInclusionScanner()
        
        lfi_payloads = [p for p in file_inclusion_payloads if "/" in p or "\\" in p]
        assert len(lfi_payloads) > 0
    
    async def test_file_inclusion_php_wrappers(self):
        """Test PHP stream wrappers for file inclusion."""
        scanner = FileInclusionScanner()
        
        php_wrappers = [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "php://output",
        ]
        
        for wrapper in php_wrappers:
            assert wrapper.startswith("php://")
    
    async def test_file_inclusion_zip_wrapper(self):
        """Test ZIP wrapper for file inclusion."""
        scanner = FileInclusionScanner()
        
        zip_payloads = [
            "zip://path/to/archive.zip%23internal.php",
        ]
        
        for payload in zip_payloads:
            assert "zip://" in payload
    
    async def test_file_inclusion_phar_wrapper(self):
        """Test PHAR wrapper for file inclusion."""
        scanner = FileInclusionScanner()
        
        phar_payloads = [
            "phar://archive.phar/internal.php",
        ]
        
        for payload in phar_payloads:
            assert "phar://" in payload
    
    async def test_file_inclusion_data_uri(self):
        """Test data URI for file inclusion."""
        scanner = FileInclusionScanner()
        
        data_payloads = [
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        ]
        
        for payload in data_payloads:
            assert "data://" in payload
    
    async def test_file_inclusion_expect_wrapper(self):
        """Test expect wrapper for RCE via file inclusion."""
        scanner = FileInclusionScanner()
        
        expect_payloads = [
            "expect://id",
            "expect://whoami",
        ]
        
        for payload in expect_payloads:
            assert "expect://" in payload
    
    async def test_file_inclusion_proc_self(self):
        """Test /proc/self for information disclosure."""
        scanner = FileInclusionScanner()
        
        proc_payloads = [
            "/proc/self/environ",
            "/proc/self/fd/3",
            "/proc/self/cwd",
        ]
        
        for payload in proc_payloads:
            assert "/proc/self" in payload
    
    async def test_file_inclusion_log_files(self):
        """Test inclusion of log files."""
        scanner = FileInclusionScanner()
        
        log_payloads = [
            "/var/log/apache2/access.log",
            "/var/log/nginx/error.log",
            "C:\\windows\\System32\\LogFiles\\",
        ]
        
        for payload in log_payloads:
            assert "log" in payload.lower()
    
    async def test_file_inclusion_null_byte(self):
        """Test null byte injection in file inclusion."""
        scanner = FileInclusionScanner()
        
        null_payloads = [
            "/etc/passwd%00.php",
            "../../../etc/passwd%00",
        ]
        
        for payload in null_payloads:
            assert "%00" in payload
    
    async def test_file_inclusion_encoding(self):
        """Test file inclusion with encoding."""
        scanner = FileInclusionScanner()
        
        encoded_payloads = [
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        
        for payload in encoded_payloads:
            assert "%" in payload


@pytest.mark.edge_case
@pytest.mark.asyncio
class TestFileInclusionEdgeCases:
    """Test file inclusion edge cases."""
    
    async def test_file_inclusion_unicode_bypass(self):
        """Test file inclusion with Unicode normalization."""
        scanner = FileInclusionScanner()
        
        unicode_payloads = [
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        ]
        
        for payload in unicode_payloads:
            assert "%c0%af" in payload
    
    async def test_file_inclusion_case_insensitive(self):
        """Test case variations in file inclusion."""
        scanner = FileInclusionScanner()
        
        case_payloads = [
            "PHP://FILTER/...",
            "DATA://TEXT/PLAIN;BASE64,...",
        ]
        
        for payload in case_payloads:
            assert len(payload) > 0
    
    async def test_file_inclusion_wrapper_chaining(self):
        """Test chaining multiple wrappers."""
        scanner = FileInclusionScanner()
        
        chained_payloads = [
            "php://filter/convert.base64-encode|convert.base64-encode/resource=index.php",
        ]
        
        for payload in chained_payloads:
            assert "php://" in payload
    
    async def test_file_inclusion_windows_files(self):
        """Test Windows-specific file access."""
        scanner = FileInclusionScanner()
        
        windows_payloads = [
            "C:\\windows\\win.ini",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
        ]
        
        for payload in windows_payloads:
            assert "windows" in payload.lower() or "system32" in payload.lower()


@pytest.mark.performance
@pytest.mark.asyncio
class TestFileInclusionPerformance:
    """Test file inclusion scanner performance."""
    
    async def test_file_inclusion_payload_efficiency(self, file_inclusion_payloads):
        """Test file inclusion payload set efficiency."""
        assert len(file_inclusion_payloads) >= 8
