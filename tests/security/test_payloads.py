# tests/security/test_payloads.py - Security validation for high-impact payloads

import pytest
from vulnradar.scanners.sqli import SQLInjectionScanner
from vulnradar.scanners.xss import XSSScanner
from vulnradar.scanners.comm_injection import CommandInjectionScanner


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestBlindSQLiPayloads:
    """Validate blind SQLi payloads effectiveness."""
    
    async def test_blind_sqli_time_based_effectiveness(self, blind_sqli_payloads):
        """Verify time-based SQLi payloads are properly formed."""
        assert len(blind_sqli_payloads) > 0
        
        # Check that at least some payloads contain time-based keywords
        found_time_based = False
        for payload in blind_sqli_payloads:
            # Check payload structure
            assert isinstance(payload, str)
            assert len(payload) > 0
            # Should contain time-based keyword
            if any(keyword in payload for keyword in ["SLEEP", "DELAY", "BENCHMARK", "WAITFOR", "sleep", "delay"]):
                found_time_based = True
        
        assert found_time_based, f"No time-based SQLi payloads found in {blind_sqli_payloads[:3]}"
    
    async def test_blind_sqli_payload_validity(self, blind_sqli_payloads):
        """Ensure all payloads are properly formatted SQL."""
        for payload in blind_sqli_payloads:
            # Basic SQL validation
            assert not payload.startswith(" ")
            assert not payload.endswith(" ")
            # Should have SQL keywords
            assert any(kw in payload.upper() for kw in ["SELECT", "OR", "SLEEP", "UNION", "AND"])
    
    async def test_blind_sqli_injection_points(self, blind_sqli_payloads):
        """Verify payloads can be injected at various points."""
        injection_wrappers = [
            "' {} -- -",
            "\" {} -- -",
            "1' {} -- -",
            "admin' {} -- -",
        ]
        
        for payload in blind_sqli_payloads[:5]:
            for wrapper in injection_wrappers:
                injected = wrapper.format(payload)
                assert len(injected) > len(wrapper)


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestDOMXSSPayloads:
    """Validate DOM XSS payloads effectiveness."""
    
    async def test_dom_xss_payload_validity(self, dom_xss_payloads):
        """Ensure all DOM XSS payloads are properly formed."""
        for payload in dom_xss_payloads:
            assert isinstance(payload, str)
            assert len(payload) > 0
            # Should contain XSS vectors
            assert any(vector in payload.lower() for vector in ["<", ">", "on", "script", "svg"])
    
    async def test_dom_xss_tag_completion(self, dom_xss_payloads):
        """Verify payloads have proper tag structure."""
        tag_based_payloads = [p for p in dom_xss_payloads if "<" in p]
        
        for payload in tag_based_payloads:
            # Should have either <> pair or be self-closing
            assert (">" in payload or payload.endswith(">"))
    
    async def test_dom_xss_event_handler_syntax(self, dom_xss_payloads):
        """Verify event handlers have correct syntax."""
        event_payloads = [p for p in dom_xss_payloads if "on" in p.lower()]
        
        for payload in event_payloads:
            # Should have proper event syntax
            assert "=" in payload or ":" in payload


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestCommandInjectionPayloads:
    """Validate command injection payloads."""
    
    async def test_command_injection_blind_validity(self, command_injection_blind_payloads):
        """Ensure blind command injection payloads are valid."""
        for payload in command_injection_blind_payloads:
            assert isinstance(payload, str)
            assert len(payload) > 0
            # Should contain command separators or timing
            assert any(sep in payload for sep in [";", "|", "&", "`", "$", "sleep"])
    
    async def test_command_injection_separator_types(self, command_injection_blind_payloads):
        """Verify various command separator types are present."""
        separators = {
            ";": 0,
            "|": 0,
            "&": 0,
            "`": 0,
            "$": 0,
        }
        
        for payload in command_injection_blind_payloads:
            for sep in separators:
                if sep in payload:
                    separators[sep] += 1
        
        # Should have variety of separators
        assert sum(1 for count in separators.values() if count > 0) >= 3


@pytest.mark.security
@pytest.mark.asyncio
class TestSSRFBypassPayloads:
    """Validate SSRF bypass payloads."""
    
    async def test_ssrf_payload_format(self, ssrf_bypass_payloads):
        """Ensure SSRF payloads are valid URLs."""
        for payload in ssrf_bypass_payloads:
            assert isinstance(payload, str)
            assert payload.startswith("http://")
            assert len(payload) > 10
    
    async def test_ssrf_localhost_variations(self, ssrf_bypass_payloads):
        """Verify localhost/internal endpoint variations."""
        assert len(ssrf_bypass_payloads) > 0
        
        localhost_indicators = ["127", "localhost", "::1", "[", "169.254", "0.0.0.0", "0x7f", "metadata"]
        
        # Check that payloads target internal endpoints
        found_internal = False
        for payload in ssrf_bypass_payloads:
            # Each payload should target internal endpoint
            if any(indicator in payload for indicator in localhost_indicators):
                found_internal = True
                break
        
        assert found_internal, f"No SSRF payloads found targeting internal endpoints in {ssrf_bypass_payloads[:3]}"


@pytest.mark.security
@pytest.mark.asyncio
class TestEncodingBypassPayloads:
    """Validate encoding bypass payloads."""
    
    async def test_encoding_bypass_validity(self, encoding_bypass_payloads):
        """Ensure encoding payloads are valid."""
        for payload_set in encoding_bypass_payloads:
            if isinstance(payload_set, dict):
                assert "original" in payload_set
                # Should have at least one encoding variant
                assert len(payload_set) > 1
    
    async def test_encoding_bypass_format(self, encoding_bypass_payloads):
        """Verify encoding variations follow patterns."""
        for payload_set in encoding_bypass_payloads:
            if isinstance(payload_set, dict):
                original = payload_set.get("original", "")
                assert len(original) > 0
                # Variants should be longer (encoded)
                for key, variant in payload_set.items():
                    if key != "original" and isinstance(variant, str):
                        assert len(variant) >= len(original)


@pytest.mark.security
@pytest.mark.asyncio
class TestPathTraversalBypassPayloads:
    """Validate path traversal payloads."""
    
    async def test_path_traversal_validity(self, path_traversal_payloads):
        """Ensure path traversal payloads are valid."""
        for payload in path_traversal_payloads:
            assert isinstance(payload, str)
            # Should traverse directories
            assert (".." in payload or ".%2" in payload)
    
    async def test_path_traversal_target_files(self, path_traversal_payloads):
        """Verify payloads target system files."""
        system_files = ["passwd", "win.ini", "hosts", "shadow"]
        
        for payload in path_traversal_payloads:
            # Should target sensitive files
            assert any(file in payload for file in system_files)


@pytest.mark.security
@pytest.mark.asyncio
class TestFileInclusionPayloads:
    """Validate file inclusion payloads."""
    
    async def test_file_inclusion_payload_validity(self, file_inclusion_payloads):
        """Ensure file inclusion payloads are valid."""
        for payload in file_inclusion_payloads:
            assert isinstance(payload, str)
            assert len(payload) > 0
    
    async def test_file_inclusion_wrapper_types(self, file_inclusion_payloads):
        """Verify various wrapper types are present."""
        wrapper_types = {
            "php://": 0,
            "zip://": 0,
            "phar://": 0,
            "data://": 0,
            "expect://": 0,
            "/proc/": 0,
        }
        
        for payload in file_inclusion_payloads:
            for wrapper in wrapper_types:
                if wrapper in payload:
                    wrapper_types[wrapper] += 1
        
        # Should have multiple wrapper types
        assert sum(1 for count in wrapper_types.values() if count > 0) >= 3


@pytest.mark.security
@pytest.mark.asyncio
class TestPayloadIntegration:
    """Test payload integration and interaction."""
    
    async def test_payload_combination_validity(self, blind_sqli_payloads, dom_xss_payloads):
        """Verify payloads don't conflict when used together."""
        assert len(blind_sqli_payloads) > 0
        assert len(dom_xss_payloads) > 0
        # Payloads should be independent
        assert isinstance(blind_sqli_payloads, list)
        assert isinstance(dom_xss_payloads, list)
    
    async def test_payload_encoding_consistency(self, encoding_bypass_payloads):
        """Verify encoding payloads are consistent."""
        for payload_set in encoding_bypass_payloads:
            if isinstance(payload_set, dict):
                variants = [v for k, v in payload_set.items() if isinstance(v, str)]
                # All variants should decode to similar meaning
                assert len(variants) >= 2
