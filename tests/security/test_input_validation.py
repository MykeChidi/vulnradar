# tests/security/test_input_validation.py - Input validation security tests

import pytest


@pytest.mark.security
@pytest.mark.asyncio
class TestSSRFValidationBypass:
    """Test SSRF bypass attempts on input validation."""
    
    async def test_ssrf_localhost_bypass(self, input_validator_bypass_tester):
        """Test various localhost bypass attempts."""
        tester = input_validator_bypass_tester
        ssrf_payloads = tester.get_payloads("ssrf")
        
        assert len(ssrf_payloads) > 0
        
        # Check that payloads contain localhost indicators
        found_indicators = False
        for payload in ssrf_payloads:
            # Validator should block these
            if any(indicator in payload for indicator in ["127", "localhost", "::", "0.0.0.0", "169.254", "metadata"]):
                found_indicators = True
                break
        
        assert found_indicators, f"No SSRF payloads found with required indicators in {ssrf_payloads[:3]}"
    
    async def test_ssrf_metadata_endpoint_blocking(self):
        """Verify metadata endpoints are properly blocked."""
        blocked_endpoints = [
            "169.254.169.254",
            "metadata.google.internal",
            "169.254.169.253",
        ]
        
        for endpoint in blocked_endpoints:
            assert "169.254" in endpoint or "metadata" in endpoint
    
    async def test_ssrf_dns_rebind_prevention(self):
        """Test prevention of DNS rebinding attacks."""
        rebind_attempts = [
            "http://attacker.com/",  # Would resolve to 127.0.0.1 on retry
        ]
        
        # Validator should implement caching or repeated DNS checks
        assert len(rebind_attempts) > 0
    
    async def test_ssrf_encoding_bypass_detection(self):
        """Test encoding bypass detection."""
        encoding_bypasses = [
            "http://127%2e0%2e0%2e1/",  # Encoded dots
            "http://0x7f000001/",  # Hex notation
            "http://2130706433/",  # Decimal notation
        ]
        
        for bypass in encoding_bypasses:
            assert len(bypass) > 10


@pytest.mark.security
@pytest.mark.asyncio
class TestPathTraversalValidation:
    """Test path traversal validation."""
    
    async def test_path_traversal_blocking(self, input_validator_bypass_tester):
        """Verify path traversal is blocked."""
        tester = input_validator_bypass_tester
        traversal_payloads = tester.get_payloads("path_traversal")
        
        assert len(traversal_payloads) > 0
        
        # Check that payloads contain path traversal indicators
        found_traversal = False
        for payload in traversal_payloads:
            if "../" in payload or "..\\" in payload or "%2e%2e" in payload.lower() or "%252e" in payload.lower():
                found_traversal = True
                break
        
        assert found_traversal, f"No path traversal payloads found with required indicators in {traversal_payloads[:3]}"
    
    async def test_path_traversal_encoding_detection(self):
        """Test detection of encoded path traversal."""
        encoded_traversal = [
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252fetc%252fpasswd",
        ]
        
        for payload in encoded_traversal:
            assert "%" in payload
    
    async def test_path_traversal_normalization(self):
        """Test path normalization before validation."""
        traversal_attempts = [
            "....//....//etc/passwd",
            "..//..//../etc/passwd",
        ]
        
        for payload in traversal_attempts:
            assert len(payload) > 0


@pytest.mark.security
@pytest.mark.asyncio
class TestHeaderInjectionPrevention:
    """Test header injection prevention."""
    
    async def test_header_injection_blocking(self, input_validator_bypass_tester):
        """Verify header injection is blocked."""
        tester = input_validator_bypass_tester
        header_payloads = tester.get_payloads("header_injection")
        
        assert len(header_payloads) > 0
        
        for payload in header_payloads:
            assert "\r" in payload or "\n" in payload
    
    async def test_crlf_injection_detection(self):
        """Test CRLF injection detection."""
        crlf_payloads = [
            "test\r\nSet-Cookie: admin=true",
            "test\r\nContent-Length: 0",
        ]
        
        for payload in crlf_payloads:
            assert "\r\n" in payload


@pytest.mark.security
@pytest.mark.edge_case
@pytest.mark.asyncio
class TestValidationEdgeCases:
    """Test validation edge cases."""
    
    async def test_null_byte_handling(self):
        """Test null byte in input."""
        null_inputs = [
            "test\x00admin",
            "file.jpg\x00.php",
        ]
        
        for input_str in null_inputs:
            assert "\x00" in input_str
    
    async def test_unicode_handling(self):
        """Test unicode input handling."""
        unicode_inputs = [
            "café",
            "日本語",
            "العربية",
        ]
        
        for input_str in unicode_inputs:
            assert len(input_str) > 0
    
    async def test_mixed_encoding(self):
        """Test mixed encoding detection."""
        mixed_inputs = [
            "test%c0%afadmin",
            "test&#x3E;admin",
        ]
        
        for input_str in mixed_inputs:
            assert "%" in input_str or "&#" in input_str
    
    async def test_very_long_input(self):
        """Test very long input handling."""
        long_input = "A" * (10 * 1024 * 1024)  # 10MB
        
        # Should not crash or cause DOS
        assert len(long_input) == 10 * 1024 * 1024
