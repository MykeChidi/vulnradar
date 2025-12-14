# vulnradar/scanners/file_inclusion.py - File Inclusion Scanner

import asyncio
import re
import urllib.parse
from typing import Dict, List

import aiohttp

from .base import BaseScanner
from . import payloads


class FileInclusionScanner(BaseScanner):
    """Scanner for Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities."""
    
    def __init__(self, headers: Dict = None, timeout: int = 10):
        super().__init__(headers, timeout)
        
        # Common LFI payloads
        self.lfi_payloads = payloads.file_inclusion_lfi_payloads
        
        # RFI payloads (external URLs)
        self.rfi_payloads = payloads.file_inclusion_rfi_payloads
        
        # LFI detection patterns
        self.lfi_patterns = payloads.file_inclusion_lfi_patterns
        
        # File inclusion parameter names
        self.file_params = payloads.file_inclusion_file_params
      
    async def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL for file inclusion vulnerabilities.
        
        Args:
            url: URL to scan
            
        Returns:
            List[Dict]: List of vulnerability findings
        """
        vulnerabilities = []
        try:
            # Test URL parameters
            url_vulns = await self._test_url_parameters(url)
            vulnerabilities.extend(url_vulns)
            
            # Test form inputs
            form_vulns = await self._test_form_inputs(url)
            vulnerabilities.extend(form_vulns)
        
        except Exception as e:
            self.logger.error(f"Error scanning '{url}' for file inclusion: {e}")
            
        return vulnerabilities
    
    async def _test_url_parameters(self, url: str) -> List[Dict]:
        """Test URL parameters for file inclusion vulnerabilities."""
        vulnerabilities = []
        
        # Extract existing parameters
        params = await self._extract_parameters(url)
        
        # Test each parameter
        for param_name, original_value in params.items():
            if any(keyword in param_name.lower() for keyword in self.file_params):
                # Test LFI
                lfi_vulns = await self._test_lfi_parameter(url, param_name, original_value)
                vulnerabilities.extend(lfi_vulns)
                
                # Test RFI
                rfi_vulns = await self._test_rfi_parameter(url, param_name, original_value)
                vulnerabilities.extend(rfi_vulns)
        
        # If no existing parameters, test common file inclusion parameter names
        if not params:
            for param_name in self.file_params[:8]:  # Test top 8 common parameters
                test_url = f"{url}?{param_name}=index.php"
                
                # Test LFI
                lfi_vulns = await self._test_lfi_parameter(test_url, param_name, "index.php")
                vulnerabilities.extend(lfi_vulns)
                
                # Test RFI
                rfi_vulns = await self._test_rfi_parameter(test_url, param_name, "index.php")
                vulnerabilities.extend(rfi_vulns)
        
        return vulnerabilities
    
    async def _test_form_inputs(self, url: str) -> List[Dict]:
        """Test form inputs for file inclusion vulnerabilities."""
        vulnerabilities = []
        
        forms = await self._get_form_inputs(url)
        
        for form in forms:
            for input_field in form['inputs']:
                if any(keyword in input_field['name'].lower() for keyword in self.file_params):
                    # Test LFI
                    lfi_vulns = await self._test_lfi_form(url, form, input_field)
                    vulnerabilities.extend(lfi_vulns)
                    
                    # Test RFI
                    rfi_vulns = await self._test_rfi_form(url, form, input_field)
                    vulnerabilities.extend(rfi_vulns)
        
        return vulnerabilities
    
    async def _test_lfi_parameter(self, url: str, param_name: str, original_value: str) -> List[Dict]:
        """Test a URL parameter for LFI vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.lfi_payloads:
            try:
                # Replace the parameter value with the payload
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                query_params[param_name] = [payload]
                
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                
                timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                    async with session.get(test_url, timeout=self.timeout) as response:
                        response_text = await response.text()
                        
                        # Check for LFI indicators
                        if await self._detect_lfi(response_text, payload):
                            vulnerabilities.append({
                                "type": "File Inclusion",
                                "subtype": "Local File Inclusion (LFI)",
                                "severity": "High",
                                "endpoint": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": await self._extract_evidence(response_text),
                                "description": f"Local File Inclusion vulnerability found in parameter '{param_name}'. The application includes local files based on user input without proper validation.",
                                "remediation": "Implement proper input validation and sanitization. Use whitelisting for allowed files. Avoid direct file inclusion based on user input. Consider using a secure file access API.",
                            })
                            
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        
        return vulnerabilities
    
    async def _test_rfi_parameter(self, url: str, param_name: str, original_value: str) -> List[Dict]:
        """Test a URL parameter for RFI vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.rfi_payloads:
            try:
                # Replace the parameter value with the payload
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                query_params[param_name] = [payload]
                
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                
                timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                    async with session.get(test_url, timeout=self.timeout) as response:
                        response_text = await response.text()
                        
                        # Check for RFI indicators
                        if await self._detect_rfi(response_text, payload):
                            vulnerabilities.append({
                                "type": "File Inclusion",
                                "subtype": "Remote File Inclusion (RFI)",
                                "severity": "Critical",
                                "endpoint": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": await self._extract_evidence(response_text),
                                "description": f"Remote File Inclusion vulnerability found in parameter '{param_name}'. The application includes remote files based on user input, allowing potential code execution.",
                                "remediation": "Disable remote file inclusion in PHP configuration. Implement strict input validation and whitelisting. Never include files based on user input without proper validation.",
                            })
                            
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        
        return vulnerabilities
    
    async def _test_lfi_form(self, url: str, form: Dict, input_field: Dict) -> List[Dict]:
        """Test a form input for LFI vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.lfi_payloads:
            try:
                # Prepare form data
                form_data = {}
                for field in form['inputs']:
                    if field['name'] == input_field['name']:
                        form_data[field['name']] = payload
                    else:
                        form_data[field['name']] = field['value'] or 'test'
                
                # Submit form
                timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                    if form['method'] == 'post':
                        async with session.post(form['action'], data=form_data, timeout=self.timeout) as response:
                            response_text = await response.text()
                    else:
                        async with session.get(form['action'], params=form_data, timeout=self.timeout) as response:
                            response_text = await response.text()
                    
                    # Check for LFI indicators
                    if await self._detect_lfi(response_text, payload):
                        vulnerabilities.append({
                            "type": "File Inclusion",
                            "subtype": "Local File Inclusion (LFI)",
                            "severity": "High",
                            "endpoint": form['action'],
                            "parameter": input_field['name'],
                            "payload": payload,
                            "evidence": await self._extract_evidence(response_text),
                            "description": f"Local File Inclusion vulnerability found in form field '{input_field['name']}'. The application includes local files based on user input without proper validation.",
                            "remediation": "Implement proper input validation and sanitization. Use whitelisting for allowed files. Avoid direct file inclusion based on user input.",
                        })
                        
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        
        return vulnerabilities
    
    async def _test_rfi_form(self, url: str, form: Dict, input_field: Dict) -> List[Dict]:
        """Test a form input for RFI vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.rfi_payloads:
            try:
                # Prepare form data
                form_data = {}
                for field in form['inputs']:
                    if field['name'] == input_field['name']:
                        form_data[field['name']] = payload
                    else:
                        form_data[field['name']] = field['value'] or 'test'
                
                # Submit form
                timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                    if form['method'] == 'post':
                        async with session.post(form['action'], data=form_data, timeout=self.timeout) as response:
                            response_text = await response.text()
                    else:
                        async with session.get(form['action'], params=form_data, timeout=self.timeout) as response:
                            response_text = await response.text()
                    
                    # Check for RFI indicators
                    if await self._detect_rfi(response_text, payload):
                        vulnerabilities.append({
                            "type": "File Inclusion",
                            "subtype": "Remote File Inclusion (RFI)",
                            "severity": "Critical",
                            "endpoint": form['action'],
                            "parameter": input_field['name'],
                            "payload": payload,
                            "evidence": await self._extract_evidence(response_text),
                            "description": f"Remote File Inclusion vulnerability found in form field '{input_field['name']}'. The application includes remote files based on user input, allowing potential code execution.",
                            "remediation": "Disable remote file inclusion in PHP configuration. Implement strict input validation and whitelisting. Never include files based on user input without proper validation.",
                        })
                        
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        
        return vulnerabilities
    
    async def _detect_lfi(self, response_text: str, payload: str) -> bool:
        """Detect if response contains LFI indicators."""
        # Check for common file content patterns
        for pattern in self.lfi_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for specific payload success indicators
        if "etc/passwd" in payload:
            if re.search(r"root:.*:0:0:", response_text) or re.search(r"daemon:", response_text):
                return True
        
        if "hosts" in payload:
            if re.search(r"127\.0\.0\.1", response_text) or re.search(r"localhost", response_text):
                return True
        
        if "win.ini" in payload or "system.ini" in payload:
            if re.search(r"\[.*\]", response_text):
                return True
        
        # Check for PHP wrapper success
        if "php://filter" in payload:
            if re.search(r"[A-Za-z0-9+/=]{20,}", response_text):  # Base64 encoded content
                return True
        
        # Check for error messages that might indicate file access
        error_patterns = [
            r"failed to open stream",
            r"No such file or directory",
            r"Permission denied",
            r"include\(\): Failed opening",
            r"Warning: include",
            r"Fatal error: require",
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    async def _detect_rfi(self, response_text: str, payload: str) -> bool:
        """Detect if response contains RFI indicators."""
        # Check for successful remote inclusion
        if "evil.com" in payload:
            if "evil.com" in response_text or "shell" in response_text.lower():
                return True
        
        # Check for metadata service responses
        if "169.254.169.254" in payload:
            if re.search(r"ami-\w+", response_text) or "instance-id" in response_text:
                return True
        
        # Check for external content indicators
        external_indicators = [
            r"http://.*\.com",
            r"https://.*\.com",
            r"ftp://.*\.com",
            r"<html>.*</html>",
            r"<!DOCTYPE html>",
        ]
        
        for pattern in external_indicators:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        # Check for connection errors that might indicate RFI attempt
        rfi_error_patterns = [
            r"failed to open stream: HTTP request failed",
            r"allow_url_include",
            r"URL file-access is disabled",
            r"failed to open stream.*HTTP",
        ]
        
        for pattern in rfi_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    async def _extract_evidence(self, response_text: str) -> str:
        """Extract relevant evidence from response."""
        # Truncate response if too long
        if len(response_text) > 1000:
            return response_text[:1000] + "..."
        return response_text
    
    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate a file inclusion vulnerability finding.
        
        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            
        Returns:
            bool: True if vulnerability is confirmed valid, False otherwise
        """
        try:
            # Re-test the specific payload
            timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
            async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                async with session.get(url, timeout=self.timeout) as response:
                    response_text = await response.text()
                    
                    # Check if we still get the same indicators
                    if "etc/passwd" in payload:
                        return await self._detect_lfi(response_text, payload)
                    elif any(rfi in payload for rfi in ["http://", "https://", "ftp://"]):
                        return await self._detect_rfi(response_text, payload)
                    else:
                        return await self._detect_lfi(response_text, payload)
                        
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
        
        return False