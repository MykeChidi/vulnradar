# tests/unit/test_sqli.py - SQL Injection scanner test suite

from vulnradar.scanners.sqli import SQLInjectionScanner
import pytest


@pytest.mark.unit
class TestSQLInjectionScanner:
    """Unit tests for SQLInjectionScanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner initializes with payloads."""
        scanner = SQLInjectionScanner()
        
        assert len(scanner.payloads) > 0
        assert len(scanner.error_patterns) > 0
    
    def test_check_for_sql_errors(self):
        """Test SQL error detection."""
        scanner = SQLInjectionScanner()
        
        # Should detect SQL errors
        assert scanner._check_for_sql_errors(
            "You have an error in your SQL syntax"
        )
        assert scanner._check_for_sql_errors(
            "mysql_fetch_array() expects parameter 1"
        )
        assert scanner._check_for_sql_errors(
            "ORA-01756: quoted string not properly terminated"
        )
        
        # Should not detect false positives
        assert not scanner._check_for_sql_errors(
            "Welcome to our website"
        )
    
    def test_extract_error_snippet(self):
        """Test error snippet extraction."""
        scanner = SQLInjectionScanner()
        
        response_text = "Some content here. SQL syntax error near 'user'. More content."
        snippet = scanner._extract_error_snippet(response_text)
        
        assert "SQL syntax error" in snippet
        assert len(snippet) <= 201  # 100 before + error + 100 after + 1
