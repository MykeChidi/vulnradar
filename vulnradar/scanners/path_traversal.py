# vulnradar/scanners/path_traversal.py - Path Traversal Scanner

import asyncio
import re
import urllib.parse
from typing import Dict, List

import aiohttp

from .base import BaseScanner
from . import payloads

class PathTraversalScanner(BaseScanner):
    """Scanner for Path Traversal vulnerabilities."""
    
    def __init__(self, headers: Dict = None, timeout: int = 10):
        super().__init__(headers, timeout)
        
        # Common path traversal payloads
        self.payloads = payloads.path_traversal_payloads
         
        # Detection patterns for successful path traversal
        self.detection_patterns = payloads.path_traversal_detection_patterns
        
        # Common parameter names that might be vulnerable to path traversal
        self.vulnerable_params = payloads.path_traversal_vulnerable_params

    async def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL for path traversal vulnerabilities.
        
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
            
            # Test common file access patterns
            file_vulns = await self._test_file_access(url)
            vulnerabilities.extend(file_vulns)
        
        except Exception as e:
            print(f"Error scanning {url} for path traversal: {e}")
        
        return vulnerabilities
    
    async def _test_url_parameters(self, url: str) -> List[Dict]:
        """Test URL parameters for path traversal vulnerabilities."""
        vulnerabilities = []
        
        # Extract existing parameters
        params = await self._extract_parameters(url)
        
        # Test each parameter
        for param_name, original_value in params.items():
            if any(keyword in param_name.lower() for keyword in self.vulnerable_params):
                vulns = await self._test_parameter(url, param_name, original_value)
                vulnerabilities.extend(vulns)
        
        # If no existing parameters, test common vulnerable parameter names
        if not params:
            for param_name in self.vulnerable_params[:10]:  # Test top 10 common parameters
                test_url = f"{url}?{param_name}=test.txt"
                vulns = await self._test_parameter(test_url, param_name, "test.txt")
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_form_inputs(self, url: str) -> List[Dict]:
        """Test form inputs for path traversal vulnerabilities."""
        vulnerabilities = []
        
        forms = await self._get_form_inputs(url)
        
        for form in forms:
            for input_field in form['inputs']:
                if any(keyword in input_field['name'].lower() for keyword in self.vulnerable_params):
                    vulns = await self._test_form_field(url, form, input_field)
                    vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_file_access(self, url: str) -> List[Dict]:
        """Test common file access patterns."""
        vulnerabilities = []
        
        # Test direct file access attempts
        base_url = url.rstrip('/')
        
        # Common vulnerable endpoints
        test_endpoints = [
            f"{base_url}/download",
            f"{base_url}/file",
            f"{base_url}/view",
            f"{base_url}/show",
            f"{base_url}/read",
            f"{base_url}/get",
            f"{base_url}/load",
            f"{base_url}/include",
            f"{base_url}/display",
            f"{base_url}/open",
            f"{base_url}/cat",
            f"{base_url}/fetch",
            f"{base_url}/retrieve",
            f"{base_url}/export",
            f"{base_url}/backup",
            f"{base_url}/log",
            f"{base_url}/logs",
            f"{base_url}/config",
            f"{base_url}/settings",
            f"{base_url}/admin/file",
            f"{base_url}/admin/view",
            f"{base_url}/admin/download",
            f"{base_url}/api/file",
            f"{base_url}/api/download",
            f"{base_url}/files",
            f"{base_url}/documents",
            f"{base_url}/uploads",
            f"{base_url}/assets",
            f"{base_url}/resources",
            f"{base_url}/media",
            f"{base_url}/attachments",
        ]
        
        for endpoint in test_endpoints:
            for param_name in ["file", "path", "name", "filename"]:
                test_url = f"{endpoint}?{param_name}=test.txt"
                vulns = await self._test_parameter(test_url, param_name, "test.txt")
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_parameter(self, url: str, param_name: str, original_value: str) -> List[Dict]:
        """Test a specific parameter for path traversal vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.payloads:
            try:
                # Create test payload - combine traversal with target file
                test_payloads = [
                    payload + "etc/passwd",
                    payload + "windows/system32/drivers/etc/hosts",
                    payload + "etc/shadow",
                    payload + "windows/win.ini",
                    payload + "proc/version",
                    payload + "windows/system32/config/sam",
                    payload + original_value if original_value else payload + "index.php",
                ]
                
                for test_payload in test_payloads:
                    # Replace the parameter value with the payload
                    parsed_url = urllib.parse.urlparse(url)
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    query_params[param_name] = [test_payload]
                    
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                        parsed_url.params, new_query, parsed_url.fragment
                    ))
                    
                    async with aiohttp.ClientSession(headers=self.headers) as session:
                        async with session.get(test_url, timeout=self.timeout) as response:
                            response_text = await response.text()
                            
                            # Check for path traversal indicators
                            if await self._detect_path_traversal(response_text, test_payload):
                                vulnerabilities.append({
                                    "type": "Path Traversal",
                                    "severity": "High",
                                    "endpoint": test_url,
                                    "parameter": param_name,
                                    "payload": test_payload,
                                    "evidence": await self._extract_evidence(response_text),
                                    "description": f"Path traversal vulnerability found in parameter '{param_name}'. The application allows access to files outside the intended directory through directory traversal sequences.",
                                    "remediation": "Implement proper input validation and sanitization. Use whitelisting for allowed file paths. Canonicalize file paths and check against allowed directories. Use secure file access APIs that prevent directory traversal.",
                                })
                                break  # Found vulnerability, no need to test more payloads for this parameter
                            
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        
        return vulnerabilities
    
    async def _test_form_field(self, url: str, form: Dict, input_field: Dict) -> List[Dict]:
        """Test a form field for path traversal vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.payloads[:20]:  # Test fewer payloads for forms to avoid excessive requests
            try:
                # Create test payload
                test_payloads = [
                    payload + "etc/passwd",
                    payload + "windows/system32/drivers/etc/hosts",
                    payload + "etc/shadow",
                    payload + "windows/win.ini",
                ]
                
                for test_payload in test_payloads:
                    # Prepare form data
                    form_data = {}
                    for field in form['inputs']:
                        if field['name'] == input_field['name']:
                            form_data[field['name']] = test_payload
                        else:
                            form_data[field['name']] = field['value'] or 'test'
                    
                    # Submit form
                    async with aiohttp.ClientSession(headers=self.headers) as session:
                        if form['method'] == 'post':
                            async with session.post(form['action'], data=form_data, timeout=self.timeout) as response:
                                response_text = await response.text()
                        else:
                            async with session.get(form['action'], params=form_data, timeout=self.timeout) as response:
                                response_text = await response.text()
                        
                        # Check for path traversal indicators
                        if await self._detect_path_traversal(response_text, test_payload):
                            vulnerabilities.append({
                                "type": "Path Traversal",
                                "severity": "High",
                                "endpoint": form['action'],
                                "parameter": input_field['name'],
                                "payload": test_payload,
                                "evidence": await self._extract_evidence(response_text),
                                "description": f"Path traversal vulnerability found in form field '{input_field['name']}'. The application allows access to files outside the intended directory through directory traversal sequences.",
                                "remediation": "Implement proper input validation and sanitization. Use whitelisting for allowed file paths. Canonicalize file paths and check against allowed directories.",
                            })
                            break  # Found vulnerability, no need to test more payloads
                            
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        
        return vulnerabilities
    
    async def _detect_path_traversal(self, response_text: str, payload: str) -> bool:
        """Detect if response contains path traversal indicators."""
        # Check for common file content patterns
        for pattern in self.detection_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                return True
        
        # Check for specific payload success indicators
        if "etc/passwd" in payload:
            # Look for Unix user entries
            if re.search(r"root:.*:0:0:", response_text) or re.search(r"daemon:.*:", response_text):
                return True
        
        if "hosts" in payload:
            # Look for hosts file content
            if re.search(r"127\.0\.0\.1", response_text) or re.search(r"localhost", response_text):
                return True
        
        if "win.ini" in payload or "system.ini" in payload:
            # Look for Windows INI file structure
            if re.search(r"\[.*\]", response_text):
                return True
        
        if "proc/version" in payload:
            # Look for Linux kernel version
            if re.search(r"Linux version", response_text):
                return True
        
        # Check for error messages that might indicate successful file access
        error_patterns = [
            r"No such file or directory",
            r"Permission denied",
            r"Access is denied",
            r"File not found",
            r"Cannot open file",
            r"failed to open stream",
            r"is not readable",
            r"Could not open",
            r"Unable to open",
            r"Invalid file",
            r"Bad file descriptor",
            r"I/O error",
            r"Read error",
            r"File system error",
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # These errors might indicate the path traversal worked but file doesn't exist
                # or permissions are insufficient - still a vulnerability
                return True
        
        # Check for directory listing patterns
        directory_patterns = [
            r"Index of /",
            r"Directory listing for",
            r"<DIR>",
            r"drwxr-xr-x",
            r"-rw-r--r--",
            r"total \d+",
            r"\d{2}:\d{2}\s+<DIR>",
            r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}\s+(AM|PM)",
        ]
        
        for pattern in directory_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                return True
        
        return False
    
    async def _extract_evidence(self, response_text: str) -> str:
        """Extract relevant evidence from response."""
        # Look for the most relevant evidence
        evidence_patterns = [
            r"root:.*:0:0:.*",
            r"daemon:.*:.*:.*",
            r"# Copyright.*Microsoft",
            r"127\.0\.0\.1\s+localhost",
            r"Linux version.*",
            r"Microsoft Windows.*",
            r"\[boot loader\]",
            r"define\s*\(\s*['\"]DB_.*",
            r"mysql_connect\s*\(",
            r"password\s*[:=]\s*['\"].*['\"]",
        ]
        
        for pattern in evidence_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if matches:
                return matches[0][:200]  # Return first 200 characters of evidence
        
        # If no specific evidence found, return truncated response
        if len(response_text) > 500:
            return response_text[:500] + "..."
        return response_text
    
    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate a path traversal vulnerability finding.
        
        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            
        Returns:
            bool: True if vulnerability is confirmed valid, False otherwise
        """
        try:
            # Re-test the specific payload
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, timeout=self.timeout) as response:
                    response_text = await response.text()
                    
                    # Check if we still get the same indicators
                    return await self._detect_path_traversal(response_text, payload)
                        
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
        
        return False