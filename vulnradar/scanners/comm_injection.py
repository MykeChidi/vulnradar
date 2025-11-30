# vulnradar/scanners/comm_injection.py - Command Injection Scanner

import asyncio
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin

import aiohttp

from .base import BaseScanner
from . import payloads


class CommandInjectionScanner(BaseScanner):
    """Scanner for command injection vulnerabilities."""
    
    def __init__(self, headers: Dict = None, timeout: int = 10):
        """Initialize the command injection scanner."""
        super().__init__(headers, timeout)
        
        # Common command injection payloads
        self.payloads = payloads.comm_injection_payloads
        
        # Evidence patterns to look for in responses
        self.evidence_patterns = payloads.comm_injection_evidence_patterns
        
        # Compile regex patterns for better performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.evidence_patterns]
        
        # Parameters commonly vulnerable to command injection
        self.vulnerable_params = payloads.comm_injection_vulnerable_params

    async def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL for command injection vulnerabilities.
        
        Args:
            url: URL to scan
            
        Returns:
            List[Dict]: List of vulnerability findings
        """
        vulnerabilities = []
        
        try:
            # Test GET parameters
            get_vulns = await self._test_get_parameters(url)
            vulnerabilities.extend(get_vulns)
            
            # Test POST forms
            form_vulns = await self._test_forms(url)
            vulnerabilities.extend(form_vulns)
            
            # Test JSON endpoints
            json_vulns = await self._test_json_endpoints(url)
            vulnerabilities.extend(json_vulns)
            
        except Exception as e:
            print(f"Error scanning '{url}' for command injection: {e}")
            
        return vulnerabilities

    async def _test_get_parameters(self, url: str) -> List[Dict]:
        """Test GET parameters for command injection."""
        vulnerabilities = []
        
        # Extract existing parameters
        params = await self._extract_parameters(url)
        
        if not params:
            return vulnerabilities
            
        # Test each parameter
        for param_name, original_value in params.items():
            # Skip if parameter name doesn't look vulnerable
            if not any(vuln_param in param_name.lower() for vuln_param in self.vulnerable_params):
                continue
                
            for payload in self.payloads:
                try:
                    # Create test parameters
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # Build URL with test parameters
                    base_url = url.split('?')[0]
                    param_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{base_url}?{param_string}"
                    
                    # Time the request for time-based detection
                    start_time = time.time()
                    
                    async with aiohttp.ClientSession(headers=self.headers) as session:
                        async with session.get(test_url, timeout=self.timeout) as response:
                            response_time = time.time() - start_time
                            response_text = await response.text()
                            
                            # Check for evidence of command execution
                            evidence = self._check_evidence(response_text, payload)
                            
                            if evidence or self._is_time_based_vulnerable(payload, response_time):
                                vulnerability = {
                                    "type": "Command Injection",
                                    "severity": "High",
                                    "endpoint": url,
                                    "parameter": param_name,
                                    "method": "GET",
                                    "payload": payload,
                                    "evidence": evidence or f"Time delay detected: {response_time:.2f}s",
                                    "description": f"Command injection vulnerability found in GET parameter '{param_name}'",
                                    "remediation": "Implement proper input validation and sanitization. Use parameterized queries or prepared statements. Avoid executing user input as system commands.",
                                }
                                vulnerabilities.append(vulnerability)
                                break  # Found vulnerability, no need to test more payloads for this parameter
                                
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
                    
        return vulnerabilities

    async def _test_forms(self, url: str) -> List[Dict]:
        """Test POST forms for command injection."""
        vulnerabilities = []
        
        # Get forms from the page
        forms = await self._get_form_inputs(url)
        
        if not forms:
            return vulnerabilities
            
        for form in forms:
            action_url = form.get('action', url)
            method = form.get('method', 'post').lower()
            
            # Make sure action URL is absolute
            if not action_url.startswith(('http://', 'https://')):
                action_url = urljoin(url, action_url)
            
            # Test each input in the form
            for input_info in form.get('inputs', []):
                input_name = input_info.get('name', '')
                input_type = input_info.get('type', '')
                
                # Skip certain input types
                if input_type in ['hidden', 'submit', 'button', 'reset', 'image']:
                    continue
                    
                # Focus on parameters that might be vulnerable
                if not any(vuln_param in input_name.lower() for vuln_param in self.vulnerable_params):
                    continue
                
                for payload in self.payloads:
                    try:
                        # Build form data
                        form_data = {}
                        for inp in form.get('inputs', []):
                            if inp.get('name'):
                                if inp.get('name') == input_name:
                                    form_data[inp.get('name')] = payload
                                else:
                                    form_data[inp.get('name')] = inp.get('value', '')
                        
                        # Time the request
                        start_time = time.time()
                        
                        async with aiohttp.ClientSession(headers=self.headers) as session:
                            if method == 'post':
                                async with session.post(action_url, data=form_data, timeout=self.timeout) as response:
                                    response_time = time.time() - start_time
                                    response_text = await response.text()
                            else:
                                # Handle GET forms
                                async with session.get(action_url, params=form_data, timeout=self.timeout) as response:
                                    response_time = time.time() - start_time
                                    response_text = await response.text()
                            
                            # Check for evidence
                            evidence = self._check_evidence(response_text, payload)
                            
                            if evidence or self._is_time_based_vulnerable(payload, response_time):
                                vulnerability = {
                                    "type": "Command Injection",
                                    "severity": "High",
                                    "endpoint": action_url,
                                    "parameter": input_name,
                                    "method": method.upper(),
                                    "payload": payload,
                                    "evidence": evidence or f"Time delay detected: {response_time:.2f}s",
                                    "description": f"Command injection vulnerability found in form parameter '{input_name}'",
                                    "remediation": "Implement proper input validation and sanitization. Use parameterized queries or prepared statements. Avoid executing user input as system commands.",                                
                                }
                                vulnerabilities.append(vulnerability)
                                break  # Found vulnerability, no need to test more payloads
                                
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
                        
        return vulnerabilities

    async def _test_json_endpoints(self, url: str) -> List[Dict]:
        """Test JSON endpoints for command injection."""
        vulnerabilities = []
        
        # Common JSON parameter names that might be vulnerable
        json_test_params = {
            'command': 'test', 'cmd': 'test', 'exec': 'test', 'execute': 'test',
            'system': 'test', 'shell': 'test', 'file': 'test.txt', 'filename': 'test.txt',
            'path': '/tmp/test', 'directory': '/tmp', 'url': 'http://example.com',
            'host': 'example.com', 'ping': 'example.com', 'backup': 'test.zip',
            'restore': 'test.zip', 'input': 'test', 'data': 'test','value': 'test',
            'content': 'test', 'message': 'test',
        }
        
        for param_name, base_value in json_test_params.items():
            for payload in self.payloads[:10]:  # Test fewer payloads for JSON to avoid too many requests
                try:
                    # Create JSON payload
                    json_payload = {param_name: payload}
                    
                    # Time the request
                    start_time = time.time()
                    
                    async with aiohttp.ClientSession(headers=self.headers) as session:
                        headers = self.headers.copy()
                        headers['Content-Type'] = 'application/json'
                        
                        async with session.post(url, json=json_payload, headers=headers, timeout=self.timeout) as response:
                            response_time = time.time() - start_time
                            response_text = await response.text()
                            
                            # Check for evidence
                            evidence = self._check_evidence(response_text, payload)
                            
                            if evidence or self._is_time_based_vulnerable(payload, response_time):
                                vulnerability = {
                                    "type": "Command Injection",
                                    "severity": "High",
                                    "endpoint": url,
                                    "parameter": param_name,
                                    "method": "POST",
                                    "payload": payload,
                                    "evidence": evidence or f"Time delay detected: {response_time:.2f}s",
                                    "description": f"Command injection vulnerability found in JSON parameter '{param_name}'",
                                    "remediation": "Implement proper input validation and sanitization. Use parameterized queries or prepared statements. Avoid executing user input as system commands.",
                                }
                                vulnerabilities.append(vulnerability)
                                break  # Found vulnerability, no need to test more payloads
                                
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
                    
        return vulnerabilities

    def _check_evidence(self, response_text: str, payload: str) -> Optional[str]:
        """
        Check response for evidence of command execution.
        
        Args:
            response_text: HTTP response text
            payload: Payload that was sent
            
        Returns:
            str: Evidence found, or None if no evidence
        """
        # Check against compiled patterns
        for pattern in self.compiled_patterns:
            match = pattern.search(response_text)
            if match:
                return f"Command execution evidence found: {match.group(0)[:100]}"
        
        # Check for specific command outputs based on payload
        if 'whoami' in payload.lower():
            # Look for common usernames in the response
            username_patterns = [
                r'\b(root|administrator|system|daemon|www-data|apache|nginx|mysql|postgres)\b',
                r'\b[a-z][a-z0-9_-]{2,15}\b'  # Common username pattern
            ]
            for pattern in username_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return f"Potential username found in response: {pattern}"
        
        if 'ls' in payload.lower() or 'dir' in payload.lower():
            # Look for directory listing patterns
            dir_patterns = [
                r'\b(bin|etc|usr|var|tmp|home|root|dev|proc|sys|windows|program files|users)\b',
                r'\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}',  # Date/time format
                r'\b\d+\s+bytes?\b'  # File size
            ]
            for pattern in dir_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return f"Directory listing evidence: {pattern}"
        
        if 'cat' in payload.lower() or 'type' in payload.lower():
            # Look for file content patterns
            file_patterns = [
                r'root:x:0:0:',  # /etc/passwd
                r'\[boot loader\]',  # Windows boot.ini
                r'for 16-bit app support'  # Windows system.ini
            ]
            for pattern in file_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return f"File content evidence: {pattern}"
        
        return None

    def _is_time_based_vulnerable(self, payload: str, response_time: float) -> bool:
        """
        Check if response time indicates time-based command injection.
        
        Args:
            payload: Payload that was sent
            response_time: Response time in seconds
            
        Returns:
            bool: True if time-based vulnerability is detected
        """
        # Check if payload contains sleep/delay commands
        if 'sleep' in payload.lower() or 'ping -n' in payload.lower() or 'timeout' in payload.lower():
            # Look for sleep duration in payload
            sleep_match = re.search(r'sleep\s+(\d+)', payload, re.IGNORECASE)
            if sleep_match:
                expected_delay = int(sleep_match.group(1))
                # Allow some tolerance for network latency
                return response_time >= (expected_delay - 1)
        
        # General time-based detection (response took unusually long)
        return response_time > 8.0  # Arbitrary threshold

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate a command injection vulnerability.
        
        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            
        Returns:
            bool: True if vulnerability is confirmed
        """
        try:
            # Re-test with the same payload
            async with aiohttp.ClientSession(headers=self.headers) as session:
                # Try different methods based on original finding
                methods_to_try = ['GET', 'POST']
                
                for method in methods_to_try:
                    try:
                        if method == 'GET':
                            # Test as GET parameter
                            test_url = f"{url}{'&' if '?' in url else '?'}test={payload}"
                            async with session.get(test_url, timeout=self.timeout) as response:
                                response_text = await response.text()
                        else:
                            # Test as POST data
                            async with session.post(url, data={'test': payload}, timeout=self.timeout) as response:
                                response_text = await response.text()
                        
                        # Check if we can reproduce the evidence
                        if self._check_evidence(response_text, payload):
                            return True
                            
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
            
            # If we can't reproduce the exact evidence, try a simple validation payload
            validation_payload = "; echo 'VALIDATION_TEST_12345'"
            
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(f"{url}{'&' if '?' in url else '?'}test={validation_payload}", timeout=self.timeout) as response:
                    response_text = await response.text()
                    
                    # Look for our validation string
                    if 'VALIDATION_TEST_12345' in response_text:
                        return True
                        
        except Exception as e:
            print(f"Error validating command injection at {url}: {e}")
            
        return False