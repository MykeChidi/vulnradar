# vulnscan/scanners/sqli.py - SQL Injection Scanner

import re
from typing import Dict, List

import aiohttp
from scanners.base import BaseScanner
from scanners import payloads


class SQLInjectionScanner(BaseScanner):
    """Scanner for SQL Injection vulnerabilities."""
    
    def __init__(self, headers: Dict = None, timeout: int = 10):
        """Initialize the SQL injection scanner."""
        super().__init__(headers, timeout)
        
        # SQL injection payloads
        self.payloads = payloads.sqli_payloads
        
        # Error patterns indicating SQL injection
        self.error_patterns = payloads.sqli_error_patterns
        
    async def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL for SQL injection vulnerabilities.
        
        Args:
            url: URL to scan
            
        Returns:
            List[Dict]: List of SQL injection findings
        """
        vulnerabilities = []
        try:
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
                
        except Exception as e:
            print(f"Error scanning '{url}' for sqli: {e}")

        return vulnerabilities
        
    async def _check_get_params(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """
        Check GET parameters for SQL injection vulnerabilities.
        
        Args:
            url: URL to check
            params: Original parameters in the URL
            
        Returns:
            List[Dict]: List of SQL injection findings
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
                            
                            # Check for SQL errors in the response
                            if self._check_for_sql_errors(response_text):
                                vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "endpoint": url,
                                    "parameter": param_name,
                                    "method": "GET",
                                    "payload": payload,
                                    "evidence": self._extract_error_snippet(response_text),
                                    "severity": "High",
                                    "description": f"SQL Injection vulnerability found in GET parameter '{param_name}'",
                                    "remediation": "Use parameterized queries or prepared statements to prevent SQL injection. Validate and sanitize all user inputs."
                                })
                                
                                # Stop testing this parameter after finding a vulnerability
                                break
                                
                except Exception as e:
                    print(f"Error testing SQL injection on GET parameter {param_name} at {url}: {e}")
                    
        return vulnerabilities
        
    async def _check_post_params(self, form: Dict) -> List[Dict]:
        """
        Check POST parameters for SQL injection vulnerabilities.
        
        Args:
            form: Form information including action URL and inputs
            
        Returns:
            List[Dict]: List of SQL injection findings
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
                                
                                # Check for SQL errors in the response
                                if self._check_for_sql_errors(response_text):
                                    vulnerabilities.append({
                                        "type": "SQL Injection",
                                        "endpoint": action_url,
                                        "parameter": field_name,
                                        "method": "POST",
                                        "payload": payload,
                                        "evidence": self._extract_error_snippet(response_text),
                                        "severity": "High",
                                        "description": f"SQL Injection vulnerability found in POST parameter '{field_name}'",
                                        "remediation": "Use parameterized queries or prepared statements to prevent SQL injection. Validate and sanitize all user inputs."
                                    })
                                    
                                    # Stop testing this parameter after finding a vulnerability
                                    break
                        else:
                            # Handle GET forms
                            async with session.get(action_url, params=form_data, timeout=self.timeout) as response:
                                response_text = await response.text()
                                
                                # Check for SQL errors in the response
                                if self._check_for_sql_errors(response_text):
                                    vulnerabilities.append({
                                        "type": "SQL Injection",
                                        "endpoint": action_url,
                                        "parameter": field_name,
                                        "method": "GET (form)",
                                        "payload": payload,
                                        "evidence": self._extract_error_snippet(response_text),
                                        "severity": "High",
                                        "description": f"SQL Injection vulnerability found in form parameter '{field_name}'",
                                        "remediation": "Use parameterized queries or prepared statements to prevent SQL injection. Validate and sanitize all user inputs."
                                    })
                                    
                                    # Stop testing this parameter after finding a vulnerability
                                    break
                                    
                except Exception as e:
                    print(f"Error testing SQL injection on field {field_name} at {action_url}: {e}")
                    
        return vulnerabilities
        
    def _check_for_sql_errors(self, response_text: str) -> bool:
        """
        Check if response contains SQL error patterns.
        
        Args:
            response_text: HTTP response text
            
        Returns:
            bool: True if SQL errors are found, False otherwise
        """
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        return False
        
    def _extract_error_snippet(self, response_text: str) -> str:
        """
        Extract a snippet of text surrounding the SQL error.
        
        Args:
            response_text: HTTP response text
            
        Returns:
            str: Error snippet or empty string if no error found
        """
        for pattern in self.error_patterns:
            match = re.search(f"(.{{0,100}}){pattern}(.{{0,100}})", response_text, re.IGNORECASE)
            if match:
                return match.group(0)
                
        return ""
        
    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate a SQL injection finding.
        
        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            
        Returns:
            bool: True if vulnerability is confirmed valid, False otherwise
        """
        from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
        
        try:
            # Extract parameter and value from URL
            parsed_url = urlparse(url)
            params = dict(parse_qsl(parsed_url.query))
            
            # If no parameters, try to guess from payload
            if not params and "=" in url:
                param_name = url.split("=")[0].split("/")[-1]
                
                # Create a different test payload
                test_payload = "' OR '2'='2" if payload != "' OR '2'='2" else "' OR '3'='3"
                
                # Create test URL
                test_params = {param_name: test_payload}
                test_query = urlencode(test_params)
                test_parts = list(parsed_url)
                test_parts[4] = test_query
                test_url = urlunparse(test_parts)
                
                # Make the request
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(test_url, timeout=self.timeout) as response:
                        response_text = await response.text()
                        
                        # Check for SQL errors in the response
                        return self._check_for_sql_errors(response_text)
            else:
                # We have parameters, test with a different payload
                for param_name in params:
                    # Create a different test payload
                    test_payload = "' OR '2'='2" if payload != "' OR '2'='2" else "' OR '3'='3"
                    
                    # Create test URL
                    test_params = dict(params)
                    test_params[param_name] = test_payload
                    test_query = urlencode(test_params)
                    test_parts = list(parsed_url)
                    test_parts[4] = test_query
                    test_url = urlunparse(test_parts)
                    
                    # Make the request
                    async with aiohttp.ClientSession(headers=self.headers) as session:
                        async with session.get(test_url, timeout=self.timeout) as response:
                            response_text = await response.text()
                            
                            # Check for SQL errors in the response
                            if self._check_for_sql_errors(response_text):
                                return True
                                
            return False
            
        except Exception as e:
            print(f"Error validating SQL injection at '{url}': {e}")
            return False
