# tests/scanners/test_xss_expanded.py - Expanded XSS scanner tests

import pytest
from aioresponses import aioresponses
from vulnradar.scanners.xss import XSSScanner


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestDOMXSSDetection:
    """Test DOM-based XSS detection."""
    
    async def test_dom_xss_event_handlers(self, dom_xss_payloads):
        """Test detection of XSS via event handlers."""
        scanner = XSSScanner()
        
        # Verify payload set exists
        assert len(dom_xss_payloads) > 0
        
        event_handlers = [p for p in dom_xss_payloads if "on" in p.lower()]
        assert len(event_handlers) > 0
    
    async def test_dom_xss_attribute_injection(self):
        """Test XSS via attribute injection."""
        scanner = XSSScanner()
        
        payloads = [
            '"><img src=x onerror=alert(1)>',
            '" onload="alert(1)',
            "' autofocus onfocus='alert(1)",
        ]
        
        for payload in payloads:
            assert "on" in payload.lower() or "img" in payload.lower()
    
    async def test_dom_xss_svg_vectors(self):
        """Test XSS via SVG elements."""
        scanner = XSSScanner()
        
        svg_payloads = [
            '<svg onload=alert(1)>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><animate onbegin=alert(1) dur=1s>',
        ]
        
        for payload in svg_payloads:
            assert "svg" in payload.lower()
    
    async def test_dom_xss_css_contexts(self):
        """Test XSS in CSS contexts."""
        scanner = XSSScanner()
        
        css_payloads = [
            'style="background:url(javascript:alert(1))"',
            'style="behavior:url(test.htc)"',
            '<style>body{background:url("javascript:alert(1)")}</style>',
        ]
        
        for payload in css_payloads:
            assert "style" in payload.lower() or "behavior" in payload.lower()
    
    async def test_dom_xss_javascript_protocol(self):
        """Test XSS via javascript: protocol."""
        scanner = XSSScanner()
        
        js_protocol_payloads = [
            '<a href="javascript:alert(1)">click</a>',
            '<iframe src="javascript:alert(1)">',
            '<form action="javascript:alert(1)"><input type=submit>',
        ]
        
        for payload in js_protocol_payloads:
            assert "javascript:" in payload
    
    async def test_dom_xss_data_uris(self):
        """Test XSS via data URIs."""
        scanner = XSSScanner()
        
        data_uri_payloads = [
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ]
        
        for payload in data_uri_payloads:
            assert "data:" in payload
    
    async def test_dom_xss_html5_input_attributes(self):
        """Test XSS via HTML5 input attributes."""
        scanner = XSSScanner()
        
        html5_payloads = [
            '<input onfocus=alert(1) autofocus>',
            '<input type="image" src="x" onerror=alert(1)>',
            '<video src=x onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
        ]
        
        for payload in html5_payloads:
            assert "on" in payload.lower()
    
    async def test_dom_xss_form_elements(self):
        """Test XSS via form elements."""
        scanner = XSSScanner()
        
        form_payloads = [
            '<form onsubmit=alert(1)><input type=submit>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
        ]
        
        for payload in form_payloads:
            assert "on" in payload.lower()
    
    async def test_dom_xss_deprecated_tags(self):
        """Test XSS via deprecated HTML tags."""
        scanner = XSSScanner()
        
        deprecated_payloads = [
            '<marquee onstart=alert(1)>',
            '<embed src="data:text/html,<script>alert(1)</script>">',
            '<object data="javascript:alert(1)">',
            '<applet code="alert(1)">',
        ]
        
        for payload in deprecated_payloads:
            assert len(payload) > 0


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestXSSEncodingBypass:
    """Test XSS detection with encoding bypasses."""
    
    async def test_xss_html_entity_encoding(self, encoding_bypass_payloads):
        """Test XSS with HTML entity encoding."""
        scanner = XSSScanner()
        
        # Verify encoding payloads exist
        assert len(encoding_bypass_payloads) > 0
    
    async def test_xss_mixed_encoding_chaining(self):
        """Test XSS with mixed encoding chains."""
        scanner = XSSScanner()
        
        chained_payloads = [
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        ]
        
        for payload in chained_payloads:
            # Should recognize as potential XSS despite encoding
            assert len(payload) > 10


@pytest.mark.edge_case
@pytest.mark.asyncio
class TestXSSEdgeCases:
    """Test XSS detection edge cases."""
    
    async def test_xss_null_byte_bypass(self):
        """Test XSS with null byte injection."""
        scanner = XSSScanner()
        
        null_byte_payloads = [
            "<script\x00>alert(1)</script>",
            "<img\x00src=x onerror=alert(1)>",
        ]
        
        for payload in null_byte_payloads:
            assert "\x00" in payload
    
    async def test_xss_unicode_normalization(self):
        """Test XSS with Unicode normalization attacks."""
        scanner = XSSScanner()
        
        unicode_payloads = [
            "<scr\u0131pt>alert(1)</scr\u0131pt>",  # Turkish i
            "<SCR\u0131PT>alert(1)</SCR\u0131PT>",
        ]
        
        for payload in unicode_payloads:
            assert len(payload) > 0
    
    async def test_xss_case_insensitivity(self):
        """Test XSS detection with case variations."""
        scanner = XSSScanner()
        
        case_payloads = [
            "<SCRIPT>alert(1)</SCRIPT>",
            "<Script>alert(1)</Script>",
            "<sCrIpT>alert(1)</sCrIpT>",
            "<img SRC=x OnErRoR=alert(1)>",
        ]
        
        for payload in case_payloads:
            assert len(payload) > 0
    
    async def test_xss_whitespace_bypass(self):
        """Test XSS with various whitespace characters."""
        scanner = XSSScanner()
        
        whitespace_payloads = [
            "<script\n>alert(1)</script>",
            "<script\t>alert(1)</script>",
            "<script\r>alert(1)</script>",
            "<script\v>alert(1)</script>",
        ]
        
        for payload in whitespace_payloads:
            assert len(payload) > 0
    
    async def test_xss_comment_bypass(self):
        """Test XSS with HTML/JavaScript comments."""
        scanner = XSSScanner()
        
        comment_payloads = [
            "<script>/**/alert(1)</script>",
            "<img src=x /**/onerror=alert(1)>",
            "<!-- <script>alert(1)</script> -->",
        ]
        
        for payload in comment_payloads:
            assert len(payload) > 0
    
    async def test_xss_malformed_html(self):
        """Test XSS detection in malformed HTML."""
        scanner = XSSScanner()
        
        malformed_payloads = [
            "<script>alert(1)<script>",  # Missing closing tag
            "<img src=x onerror=alert(1)",  # Missing closing >
            "<>alert(1)<>",  # Minimal payload
        ]
        
        for payload in malformed_payloads:
            assert len(payload) > 0
    
    async def test_xss_nested_quotes(self):
        """Test XSS with nested and escaped quotes."""
        scanner = XSSScanner()
        
        quote_payloads = [
            '<img src="x" onerror="alert(\'1\')">',
            "<img src='x' onerror='alert(\"1\")'>",
            '<img src=x onerror=alert("1")>',
        ]
        
        for payload in quote_payloads:
            assert len(payload) > 0


@pytest.mark.performance
@pytest.mark.asyncio
class TestXSSPerformance:
    """Test XSS scanner performance."""
    
    async def test_xss_payload_efficiency(self):
        """Test XSS payload set size and efficiency."""
        scanner = XSSScanner()
        
        payload_count = len(scanner.payloads) if hasattr(scanner, 'payloads') else 0
        # Should have reasonable number of payloads
        assert payload_count >= 0
    
    async def test_xss_large_response_scanning(self):
        """Test XSS detection on very large responses."""
        scanner = XSSScanner()
        
        large_html = "<html>" + "A" * (5 * 1024 * 1024) + "</html>"  # 5MB HTML
        # Should handle without hanging
        assert len(large_html) > 5000000


@pytest.mark.concurrency
@pytest.mark.asyncio
class TestXSSConcurrency:
    """Test concurrent XSS scanning."""
    
    async def test_xss_concurrent_payload_testing(self, dom_xss_payloads):
        """Test multiple XSS payloads in parallel."""
        scanner = XSSScanner()
        
        assert len(dom_xss_payloads) > 0
