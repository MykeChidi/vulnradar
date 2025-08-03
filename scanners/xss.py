# vulnscan/scanners/xss.py - Cross-Site Scripting Scanner

from typing import Dict, List

import aiohttp
from bs4 import BeautifulSoup
from scanners.base import BaseScanner
from scanners import payloads


class XSSScanner(BaseScanner):
    """Scanner for Cross-Site Scripting (XSS) vulnerabilities."""
    
    def __init__(self, headers: Dict = None, timeout: int = 10):
        """Initialize the XSS scanner."""
        super().__init__(headers, timeout)
        
        # XSS payloads
        self.payloads = payloads.xss_payloads
        
    async def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL for XSS vulnerabilities.
        
        Args:
            url: URL to scan
            
        Returns:
            List[Dict]: List of XSS findings
        """
        vulnerabilities = []
        
        # Check GET parameters
        params = await self._extract_parameters(url)
        if params:
            get_vulns = await self._check_get_params(url, params)
            vulnerabilities.extend(get_vulns)
            
        # Check POST parameters in forms
        forms = await self._get_form_inputs(url)
        for form in forms:
            post_vulns = await self._check_post_params(form)
            vulnerabilities.extend(post_vulns)
            
        return vulnerabilities
        
    async def _check_get_params(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """
        Check GET parameters for XSS vulnerabilities.
        
        Args:
            url: URL to check
            params: Original parameters in the URL
            
        Returns:
            List[Dict]: List of XSS findings
        """
        from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
        
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        # Test each parameter
        for param_name, original_value in params.items():
            for payload in self.payloads:
                # Create a new query string with the injected payload
                query_params = dict(parse_qsl(parsed_url.query))
                query_params[param_name] = payload
                new_query = urlencode(query_params)
                
                # Create the test URL
                test_parts = list(parsed_url)
                test_parts[4] = new_query  # Replace the query component
                test_url = urlunparse(test_parts)
                
                # Make the request
                try:
                    async with aiohttp.ClientSession(headers=self.headers) as session:
                        async with session.get(test_url, timeout=self.timeout) as response:
                            response_text = await response.text()
                            
                            # Check if the payload is reflected in the response
                            if self._check_for_xss_reflection(response_text, payload):
                                vulnerabilities.append({
                                    "type": "XSS",
                                    "endpoint": url,
                                    "parameter": param_name,
                                    "method": "GET",
                                    "payload": payload,
                                    "evidence": self._extract_reflection_snippet(response_text, payload),
                                    "severity": "High",
                                    "description": f"Cross-Site Scripting vulnerability found in GET parameter '{param_name}'",
                                    "remediation": "Implement proper output encoding and input validation. Consider using Content-Security-Policy headers."
                                })
                                
                                # Stop testing this parameter after finding a vulnerability
                                break
                                
                except Exception as e:
                    print(f"Error testing XSS on GET parameter {param_name} at {url}: {e}")
                    
        return vulnerabilities
        
    async def _check_post_params(self, form: Dict) -> List[Dict]:
        """
        Check POST parameters for XSS vulnerabilities.
        
        Args:
            form: Form information including action URL and inputs
            
        Returns:
            List[Dict]: List of XSS findings
        """
        vulnerabilities = []
        
        action_url = form.get("action", "")
        if not action_url:
            return []
            
        # Test each input field
        for input_field in form.get("inputs", []):
            field_name = input_field.get("name", "")
            original_value = input_field.get("value", "")
            
            for payload in self.payloads:
                # Create test form data
                form_data = {}
                for input_item in form.get("inputs", []):
                    if input_item.get("name") == field_name:
                        form_data[input_item.get("name")] = payload
                    else:
                        form_data[input_item.get("name")] = input_item.get("value", "")
                        
                # Make the request
                try:
                    async with aiohttp.ClientSession(headers=self.headers) as session:
                        if form.get("method") == "post":
                            async with session.post(action_url, data=form_data, timeout=self.timeout) as response:
                                response_text = await response.text()
                                
                                # Check if the payload is reflected in the response
                                if self._check_for_xss_reflection(response_text, payload):
                                    vulnerabilities.append({
                                        "type": "XSS",
                                        "endpoint": action_url,
                                        "parameter": field_name,
                                        "method": "POST",
                                        "payload": payload,
                                        "evidence": self._extract_reflection_snippet(response_text, payload),
                                        "severity": "High",
                                        "description": f"Cross-Site Scripting vulnerability found in POST parameter '{field_name}'",
                                        "remediation": "Implement proper output encoding and input validation. Consider using Content-Security-Policy headers."
                                    })
                                    
                                    # Stop testing this parameter after finding a vulnerability
                                    break
                        else:
                            # Handle GET forms
                            async with session.get(action_url, params=form_data, timeout=self.timeout) as response:
                                response_text = await response.text()
                                
                                # Check if the payload is reflected in the response
                                if self._check_for_xss_reflection(response_text, payload):
                                    vulnerabilities.append({
                                        "type": "XSS",
                                        "endpoint": action_url,
                                        "parameter": field_name,
                                        "method": "GET (form)",
                                        "payload": payload,
                                        "evidence": self._extract_reflection_snippet(response_text, payload),
                                        "severity": "High",
                                        "description": f"Cross-Site Scripting vulnerability found in form parameter '{field_name}'",
                                        "remediation": "Implement proper output encoding and input validation. Consider using Content-Security-Policy headers."
                                    })
                                    
                                    # Stop testing this parameter after finding a vulnerability
                                    break
                                    
                except Exception as e:
                    print(f"Error testing XSS on {action_url}: {e}")
        return vulnerabilities
    
    def _check_for_xss_reflection(self, response_text: str, payload: str) -> bool:
        """
        Check if the payload is reflected in the response.
        
        Args:
            response_text: Response text from the server
            payload: Payload to check for
            
        Returns:
            bool: True if the payload is reflected, False otherwise
        """
        # Use a more robust method to check for XSS reflection
        soup = BeautifulSoup(response_text, 'html.parser')
        for script in soup.find_all('script'):
            if payload in script.text:
                return True
        return False
        
    def _extract_reflection_snippet(self, response_text: str, payload: str) -> str:
        """
        Extract a snippet of the response text that reflects the payload.
        
        Args:
            response_text: Response text from the server
            payload: Payload to extract a snippet for
            
        Returns:
            str: Snippet of the response text that reflects the payload
        """
        # Use a more robust method to extract a snippet of the response text
        soup = BeautifulSoup(response_text, 'html.parser')
        for script in soup.find_all('script'):
            if payload in script.text:
                return script.text[:100]  # Return the first 100 characters of the script text
        return ""                      

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate an XSS vulnerability finding.
        
        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            
        Returns:
            bool: True if vulnerability is confirmed valid, False otherwise
        """
        try:
            # Extract parameter name from evidence or use a common parameter name
            param_name = self._extract_param_from_evidence(evidence) or "test"
            
            # Test with the specific payload
            from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
            
            parsed_url = urlparse(url)
            
            # Test GET parameters
            if parsed_url.query:
                query_params = dict(parse_qsl(parsed_url.query))
                query_params[param_name] = payload
                new_query = urlencode(query_params)
                
                test_parts = list(parsed_url)
                test_parts[4] = new_query
                test_url = urlunparse(test_parts)
                
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(test_url, timeout=self.timeout) as response:
                        response_text = await response.text()
                        
                        if self._check_for_xss_reflection(response_text, payload):
                            return True
            
            # Test POST forms if no GET parameters
            forms = await self._get_form_inputs(url)
            for form in forms:
                if form.get("inputs"):
                    form_data = {}
                    for input_field in form.get("inputs", []):
                        if input_field.get("name") == param_name:
                            form_data[input_field.get("name")] = payload
                        else:
                            form_data[input_field.get("name")] = input_field.get("value", "")
                    
                    async with aiohttp.ClientSession(headers=self.headers) as session:
                        if form.get("method") == "post":
                            async with session.post(form.get("action"), data=form_data, timeout=self.timeout) as response:
                                response_text = await response.text()
                                if self._check_for_xss_reflection(response_text, payload):
                                    return True
            
            return False
            
        except Exception as e:
            print(f"Error validating XSS vulnerability: {e}")
            return False