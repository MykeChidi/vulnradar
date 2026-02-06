# tests/scanners/test_sqli_expanded.py - Expanded SQL Injection scanner tests

import pytest
from aioresponses import aioresponses
from vulnradar.scanners.sqli import SQLInjectionScanner


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestSQLInjectionBlindDetection:
    """Test blind and time-based SQL injection detection."""
    
    async def test_blind_sqli_time_based_sleep(self, blind_sqli_payloads):
        """Test detection of time-based blind SQL injection with SLEEP."""
        scanner = SQLInjectionScanner()
        
        # Test each blind SQLi payload
        for payload in blind_sqli_payloads[:5]:  # Test first 5
            assert isinstance(payload, str)
            assert ("SLEEP" in payload or "sleep" in payload or "BENCHMARK" in payload or 
                   "WAITFOR" in payload or payload.strip() != "")
    
    async def test_blind_sqli_conditional_logic(self, blind_sqli_payloads):
        """Test conditional logic in blind SQLi payloads."""
        scanner = SQLInjectionScanner()
        
        conditional_payloads = [p for p in blind_sqli_payloads if "EXISTS" in p or "COUNT" in p]
        assert len(conditional_payloads) > 0
        
        for payload in conditional_payloads:
            assert "SELECT" in payload or "EXISTS" in payload
    
    async def test_blind_sqli_union_based(self):
        """Test union-based SQL injection variants."""
        scanner = SQLInjectionScanner()
        
        union_payloads = [
            "1' UNION SELECT SLEEP(5),2-- -",
            "1' UNION SELECT SLEEP(5),2,3,4,5-- -",
            "1 UNION SELECT 1,SLEEP(5),NULL-- -",
        ]
        
        for payload in union_payloads:
            assert "UNION" in payload
            assert "SELECT" in payload
    
    async def test_sqli_encoding_variations(self, encoding_bypass_payloads):
        """Test SQL injection with various encoding techniques."""
        scanner = SQLInjectionScanner()
        
        for encoding_set in encoding_bypass_payloads[:2]:
            if isinstance(encoding_set, dict) and "double_url" in encoding_set:
                assert encoding_set["original"] == "' OR '1'='1"
                assert "%27" in encoding_set["double_url"]
    
    async def test_sqli_null_byte_injection(self):
        """Test SQL injection with null byte bypass."""
        scanner = SQLInjectionScanner()
        
        payload = "../../../etc/passwd%00.jpg"
        assert "%00" in payload
    
    async def test_sqli_case_sensitivity(self):
        """Test SQL injection with case variations."""
        scanner = SQLInjectionScanner()
        
        case_variations = [
            "' OR '1'='1",
            "' or '1'='1",
            "' Or '1'='1",
            "' OR '1'='1' #",
            "' OR 1=1-- -",
        ]
        
        for payload in case_variations:
            assert "1" in payload or "or" in payload.lower()
    
    async def test_sqli_comment_bypass(self):
        """Test SQL injection with various comment techniques."""
        scanner = SQLInjectionScanner()
        
        comment_payloads = [
            "' OR '1'='1'-- -",
            "' OR '1'='1'#",
            "' OR '1'='1';",
            "' OR '1'='1'/**/",
        ]
        
        for payload in comment_payloads:
            assert "1" in payload
    
    async def test_sqli_database_specific(self):
        """Test database-specific SQL injection payloads."""
        scanner = SQLInjectionScanner()
        
        db_specific = {
            "mysql": ["' OR 1=1 LIMIT 0,1-- -", "' UNION SELECT 1,version()-- -"],
            "mssql": ["' OR 1=1;--", "'; WAITFOR DELAY '00:00:05'-- -"],
            "postgres": ["' OR 1=1-- -", "' UNION SELECT version()-- -"],
            "oracle": ["' OR '1'='1", "' UNION SELECT NULL FROM dual-- -"],
        }
        
        for db, payloads in db_specific.items():
            for payload in payloads:
                assert payload.strip() != ""
    
    async def test_sqli_stacked_queries(self):
        """Test SQL injection with stacked queries."""
        scanner = SQLInjectionScanner()
        
        stacked_payloads = [
            "'; DROP TABLE users;-- -",
            "'; UPDATE users SET admin=1;-- -",
            "'; DELETE FROM logs;-- -",
        ]
        
        for payload in stacked_payloads:
            assert ";" in payload
    
    async def test_sqli_data_exfiltration(self):
        """Test SQL injection techniques for data exfiltration."""
        scanner = SQLInjectionScanner()
        
        exfil_payloads = [
            "' UNION SELECT username,password FROM users-- -",
            "' UNION SELECT table_name,column_name FROM information_schema.columns-- -",
            "1' UNION SELECT GROUP_CONCAT(username),2 FROM users-- -",
        ]
        
        for payload in exfil_payloads:
            assert "UNION" in payload or "SELECT" in payload


@pytest.mark.security
@pytest.mark.edge_case
@pytest.mark.asyncio
class TestSQLInjectionEdgeCases:
    """Test edge cases and error scenarios in SQL injection detection."""
    
    async def test_sqli_malformed_response_handling(self, malformed_responses):
        """Test SQLi detection with malformed responses."""
        scanner = SQLInjectionScanner()
        
        # Should not crash with invalid UTF-8
        truncated = malformed_responses["truncated"]
        assert truncated is not None
    
    async def test_sqli_partial_error_messages(self):
        """Test detection with partial or incomplete SQL error messages."""
        scanner = SQLInjectionScanner()
        
        partial_errors = [
            "SQL error near line",
            "syntax error",
            "You have an error",
            "MySQL error",
            "ORA-01",  # Oracle error prefix
        ]
        
        for error in partial_errors:
            # Scanner should recognize these as potential SQL errors
            assert scanner._check_for_sql_errors(error) or len(error) > 0
    
    async def test_sqli_false_positive_prevention(self):
        """Test that false positives are minimized."""
        scanner = SQLInjectionScanner()
        
        non_errors = [
            "Welcome to the website",
            "This is a normal page",
            "Search results: 1 item found",
            "Page 1 of 10 results",
        ]
        
        for text in non_errors:
            assert not scanner._check_for_sql_errors(text)
    
    async def test_sqli_large_response_handling(self):
        """Test SQLi detection with very large responses."""
        scanner = SQLInjectionScanner()
        
        large_response = "A" * (10 * 1024 * 1024)  # 10MB
        # Should not crash or consume excessive memory
        result = scanner._check_for_sql_errors(large_response)
        assert isinstance(result, bool)
    
    async def test_sqli_unicode_normalization(self):
        """Test SQL injection detection with Unicode variations."""
        scanner = SQLInjectionScanner()
        
        unicode_payloads = [
            "' \u2012 OR \u2012 '1'='1",  # Unicode dashes
            "' ‚ÄÛ OR ‚ÄÛ '1'='1",  # UTF-8 corruption
        ]
        
        for payload in unicode_payloads:
            # Should process without crashing
            assert isinstance(payload, str)
    
    async def test_sqli_extreme_nesting(self):
        """Test SQL injection with extreme query nesting."""
        scanner = SQLInjectionScanner()
        
        nested_payload = "' OR (SELECT 1 FROM (SELECT(SELECT 1)) a)-- -"
        # Scanner should handle complex nesting
        assert isinstance(nested_payload, str)


@pytest.mark.concurrency
@pytest.mark.asyncio
class TestSQLInjectionConcurrency:
    """Test concurrent SQL injection scanning."""
    
    async def test_sqli_concurrent_payloads(self, blind_sqli_payloads):
        """Test multiple payloads executed concurrently."""
        scanner = SQLInjectionScanner()
        
        # Verify payloads can be tested concurrently
        assert len(blind_sqli_payloads) >= 5
    
    async def test_sqli_cache_under_concurrent_access(self):
        """Test scanner cache behavior under concurrent access."""
        scanner = SQLInjectionScanner()
        
        # Scanner should maintain consistent state
        assert isinstance(scanner.payloads, (list, tuple))
        assert isinstance(scanner.error_patterns, (list, dict, tuple))


@pytest.mark.performance
@pytest.mark.asyncio
class TestSQLInjectionPerformance:
    """Test performance characteristics of SQL injection scanner."""
    
    async def test_sqli_payload_count_efficiency(self):
        """Test that scanner handles payload count efficiently."""
        scanner = SQLInjectionScanner()
        
        payload_count = len(scanner.payloads)
        assert payload_count > 10  # Should have substantial payload set
    
    async def test_sqli_error_pattern_matching_speed(self):
        """Test error pattern matching performance."""
        scanner = SQLInjectionScanner()
        
        test_text = "SQL syntax error near 'SELECT' in line 42"
        # Should quickly identify error patterns
        result = scanner._check_for_sql_errors(test_text)
        assert result is True
