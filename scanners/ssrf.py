# vulnscan/scanners/ssrf.py - SSRF Scanner

import asyncio
from typing import Dict, List
from urllib.parse import urlparse, quote

import aiohttp

from scanners.base import BaseScanner
from scanners import payloads


class SSRFScanner(BaseScanner):
    """Scanner for Server-Side Request Forgery (SSRF) vulnerabilities."""
    
    def __init__(self, headers: Dict = None, timeout: int = 10):
        """Initialize SSRF scanner."""
        super().__init__(headers, timeout)
        
        # SSRF test payloads
        self.payloads = payloads.ssrf_payloads
        
        # Parameters commonly vulnerable to SSRF
        self.vulnerable_params = payloads.ssrf_vulnerable_params
        
        # Response indicators for successful SSRF
        self.indicators = payloads.ssrf_indicators
        
    async def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL for SSRF vulnerabilities.
        
        Args:
            url: URL to scan
            
        Returns:
            List[Dict]: List of SSRF vulnerability findings
        """
        vulnerabilities = []
        
        try:
            # Test URL parameters
            url_params = await self._extract_parameters(url)
            for param_name, param_value in url_params.items():
                if any(keyword in param_name.lower() for keyword in self.vulnerable_params):
                    ssrf_findings = await self._test_ssrf_parameter(url, param_name, param_value)
                    vulnerabilities.extend(ssrf_findings)
            
            # Test form inputs
            forms = await self._get_form_inputs(url)
            for form in forms:
                ssrf_findings = await self._test_ssrf_form(url, form)
                vulnerabilities.extend(ssrf_findings)
                
        except Exception as e:
            print(f"Error scanning '{url}' for SSRF: {e}")
            
        return vulnerabilities
    
    async def _test_ssrf_parameter(self, url: str, param_name: str, original_value: str) -> List[Dict]:
        """
        Test a URL parameter for SSRF vulnerability.
        
        Args:
            url: URL to test
            param_name: Parameter name
            original_value: Original parameter value
            
        Returns:
            List[Dict]: List of SSRF vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Parse the URL
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Test each payload
            for payload in self.payloads:
                # Construct test URL
                test_params = await self._extract_parameters(url)
                test_params[param_name] = payload
                
                query_string = "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                test_url = f"{base_url}?{query_string}"
                
                # Test the payload
                vulnerability = await self._test_ssrf_payload(test_url, payload, param_name, "parameter")
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                    
        except Exception as e:
            print(f"Error testing SSRF parameter {param_name}: {e}")
            
        return vulnerabilities
    
    async def _test_ssrf_form(self, url: str, form: Dict) -> List[Dict]:
        """
        Test form inputs for SSRF vulnerability.
        
        Args:
            url: URL where the form was found
            form: Form information dictionary
            
        Returns:
            List[Dict]: List of SSRF vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Check each form input
            for input_field in form['inputs']:
                input_name = input_field['name']
                
                # Skip if not a potentially vulnerable parameter
                if not any(keyword in input_name.lower() for keyword in self.vulnerable_params):
                    continue
                
                # Test each payload
                for payload in self.payloads:
                    # Prepare form data
                    form_data = {}
                    for field in form['inputs']:
                        if field['name'] == input_name:
                            form_data[field['name']] = payload
                        else:
                            form_data[field['name']] = field['value'] or 'test'
                    
                    # Test the payload
                    vulnerability = await self._test_ssrf_form_payload(
                        form['action'] or url, 
                        form['method'], 
                        form_data, 
                        payload, 
                        input_name
                    )
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            print(f"Error testing SSRF form: {e}")
            
        return vulnerabilities
    
    async def _test_ssrf_payload(self, test_url: str, payload: str, param_name: str, injection_type: str) -> Dict:
        """
        Test a specific SSRF payload.
        
        Args:
            test_url: URL to test
            payload: SSRF payload
            param_name: Parameter name being tested
            injection_type: Type of injection (parameter or form)
            
        Returns:
            Dict: Vulnerability information if found, None otherwise
        """
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                # Set a longer timeout for SSRF tests as they might be slow
                async with session.get(test_url, timeout=self.timeout * 2) as response:
                    response_text = await response.text()
                    
                    # Check for SSRF indicators in response
                    for indicator in self.indicators:
                        if indicator in response_text:
                            return {
                                "type": "SSRF",
                                "severity": "High",
                                "endpoint": test_url,
                                "description": f"Server-Side Request Forgery via {injection_type} '{param_name}'",
                                "evidence": f"Response contains indicator: '{indicator}' when testing payload: {payload}",
                                "payload": payload,
                                "remediation": "Implement proper URL validation and restrict internal network access",
                                "confidence": "High"
                            }
                    
                    # Check for timing-based indicators (unusual response times)
                    if response.status == 200 and len(response_text) > 0:
                        # Check for specific cloud metadata patterns
                        if "169.254.169.254" in payload:
                            if any(keyword in response_text.lower() for keyword in 
                                   ["ami-", "instance", "metadata", "security-group", "iam"]):
                                return {
                                    "type": "SSRF",
                                    "severity": "Critical",
                                    "endpoint": test_url,
                                    "description": f"Cloud metadata access via SSRF in {injection_type} '{param_name}'",
                                    "evidence": f"Successfully accessed cloud metadata service with payload: {payload}",
                                    "payload": payload,
                                    "remediation": "Block access to cloud metadata services and implement strict URL validation",
                                    "confidence": "High"
                                }
                        
                        # Check for internal service responses
                        if "127.0.0.1" in payload or "localhost" in payload:
                            if any(keyword in response_text.lower() for keyword in 
                                   ["server", "apache", "nginx", "iis", "tomcat", "jetty"]):
                                return {
                                    "type": "SSRF",
                                    "severity": "High",
                                    "endpoint": test_url,
                                    "description": f"Internal service access via SSRF in {injection_type} '{param_name}'",
                                    "evidence": f"Successfully accessed internal service with payload: {payload}",
                                    "payload": payload,
                                    "remediation": "Implement network-level restrictions and proper URL validation",
                                    "confidence": "Medium"
                                }
                                
        except asyncio.TimeoutError:
            # Timeout might indicate successful connection to internal service
            if "127.0.0.1" in payload or "localhost" in payload:
                return {
                    "type": "SSRF",
                    "severity": "Medium",
                    "endpoint": test_url,
                    "description": f"Potential SSRF via timeout behavior in {injection_type} '{param_name}'",
                    "evidence": f"Request timed out when testing payload: {payload} (may indicate internal service access)",
                    "payload": payload,
                    "remediation": "Implement proper URL validation and timeout handling",
                    "confidence": "Low"
                }
        except Exception as e:
            # Some exceptions might indicate successful internal access
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ["connection refused", "connection timeout", "network unreachable"]):
                return {
                    "type": "SSRF",
                    "severity": "Medium",
                    "endpoint": test_url,
                    "description": f"Potential SSRF via error response in {injection_type} '{param_name}'",
                    "evidence": f"Error response indicates internal network access attempt: {str(e)}",
                    "payload": payload,
                    "remediation": "Implement proper error handling and URL validation",
                    "confidence": "Low"
                }
            
        return None
    
    async def _test_ssrf_form_payload(self, action_url: str, method: str, form_data: Dict, payload: str, input_name: str) -> Dict:
        """
        Test SSRF payload via form submission.
        
        Args:
            action_url: Form action URL
            method: HTTP method
            form_data: Form data with payload
            payload: SSRF payload
            input_name: Input field name being tested
            
        Returns:
            Dict: Vulnerability information if found, None otherwise
        """
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                if method.lower() == 'post':
                    async with session.post(action_url, data=form_data, timeout=self.timeout * 2) as response:
                        response_text = await response.text()
                        
                        # Check for SSRF indicators
                        for indicator in self.indicators:
                            if indicator in response_text:
                                return {
                                    "type": "SSRF",
                                    "severity": "High",
                                    "endpoint": action_url,
                                    "description": f"Server-Side Request Forgery via form input '{input_name}'",
                                    "evidence": f"Response contains indicator: '{indicator}' when testing payload: {payload}",
                                    "payload": payload,
                                    "remediation": "Implement proper URL validation and restrict internal network access",
                                    "confidence": "High"
                                }
                else:
                    # Handle GET method
                    query_string = "&".join([f"{k}={quote(str(v))}" for k, v in form_data.items()])
                    test_url = f"{action_url}?{query_string}"
                    
                    return await self._test_ssrf_payload(test_url, payload, input_name, "form")
                    
        except asyncio.TimeoutError:
            if "127.0.0.1" in payload or "localhost" in payload:
                return {
                    "type": "SSRF",
                    "severity": "Medium",
                    "endpoint": action_url,
                    "description": f"Potential SSRF via timeout behavior in form input '{input_name}'",
                    "evidence": f"Request timed out when testing payload: {payload}",
                    "payload": payload,
                    "remediation": "Implement proper URL validation and timeout handling",
                    "confidence": "Low"
                }
        except Exception as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ["connection refused", "connection timeout", "network unreachable"]):
                return {
                    "type": "SSRF",
                    "severity": "Medium",
                    "endpoint": action_url,
                    "description": f"Potential SSRF via error response in form input '{input_name}'",
                    "evidence": f"Error response indicates internal network access attempt: {str(e)}",
                    "payload": payload,
                    "remediation": "Implement proper error handling and URL validation",
                    "confidence": "Low"
                }
            
        return None
    
    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate an SSRF vulnerability finding.
        
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
                async with session.get(url, timeout=self.timeout * 2) as response:
                    response_text = await response.text()
                    
                    # Check if the same indicators are still present
                    for indicator in self.indicators:
                        if indicator in evidence and indicator in response_text:
                            return True
                            
                    # Check for cloud metadata access
                    if "169.254.169.254" in payload:
                        return any(keyword in response_text.lower() for keyword in 
                                 ["ami-", "instance", "metadata", "security-group", "iam"])
                                 
                    # Check for internal service access
                    if "127.0.0.1" in payload or "localhost" in payload:
                        return any(keyword in response_text.lower() for keyword in 
                                 ["server", "apache", "nginx", "iis", "tomcat", "jetty"])
                                 
        except asyncio.TimeoutError:
            # Timeout behavior might still indicate vulnerability
            if "127.0.0.1" in payload or "localhost" in payload:
                return True
        except Exception as e:
            # Network errors might indicate successful internal access attempts
            error_msg = str(e).lower()
            return any(keyword in error_msg for keyword in 
                     ["connection refused", "connection timeout", "network unreachable"])
            
        return False