# vulnradar/scanners/xss.py - Cross-Site Scripting Scanner

from typing import Dict, List, Optional
import html
import re
import aiohttp
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote
from bs4 import BeautifulSoup
from .base import BaseScanner
from . import payloads


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
            
            # Check for DOM-based XSS
            dom_vulns = await self._check_dom_xss(url)
            vulnerabilities.extend(dom_vulns)

        except Exception as e:
            self.logger.error(f"Error scanning '{url}' for XSS: {e}")

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
                    timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                    async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
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
                    self.logger.error(f"Error testing XSS on GET parameter {param_name} at {url}: {e}")
                    
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
                    timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                    async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
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
                    self.logger.error(f"Error testing XSS on {action_url}: {e}")
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
        # Check for direct payload reflection
        if payload in response_text:
            return True
        
        # Check for HTML-encoded payload reflection
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            return True
        
        # Check for URL-encoded payload reflection
        url_encoded_payload = quote(payload)
        if url_encoded_payload in response_text:
            return True
        
        # Check for partial payload reflection (for bypasses)
        # Extract key parts of the payload
        key_parts = self._extract_payload_parts(payload)
        reflection_count = sum(1 for part in key_parts if part in response_text)
        
        # If most key parts are reflected, consider it a potential XSS
        if len(key_parts) > 0 and reflection_count / len(key_parts) >= 0.7:
            return True
        
        # Check for script execution context
        try:
            soup = BeautifulSoup(response_text, 'lxml')
        except:
            soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check if payload appears in dangerous contexts
        dangerous_contexts = [
            'script', 'style', 'svg', 'iframe', 'object', 'embed'
        ]
        
        for context in dangerous_contexts:
            for element in soup.find_all(context):
                if payload in str(element):
                    return True
        
        # Check for payload in event handlers
        for element in soup.find_all():
            for attr_name, attr_value in element.attrs.items():
                if attr_name.startswith('on') and payload in str(attr_value):
                    return True
        
        return False

    def _extract_payload_parts(self, payload: str) -> List[str]:
        """
        Extract key parts from an XSS payload for partial reflection detection.
        
        Args:
            payload: XSS payload to analyze
            
        Returns:
            List[str]: List of key parts from the payload
        """
        key_parts = []
        
        # Extract tag names
        tag_matches = re.findall(r'<(\w+)', payload)
        key_parts.extend(tag_matches)
        
        # Extract function calls
        function_matches = re.findall(r'(\w+)\s*\(', payload)
        key_parts.extend(function_matches)
        
        # Extract attribute names
        attr_matches = re.findall(r'(\w+)=', payload)
        key_parts.extend(attr_matches)
        
        # Extract quoted strings
        string_matches = re.findall(r'["\']([^"\']+)["\']', payload)
        key_parts.extend(string_matches)
        
        return list(set(key_parts))  # Remove duplicates

        
    def _extract_reflection_snippet(self, response_text: str, payload: str) -> str:
        """
        Extract a snippet of the response text that reflects the payload.
        
        Args:
            response_text: Response text from the server
            payload: Payload to extract a snippet for
            
        Returns:
            str: Snippet of the response text that reflects the payload
        """
        # Find the payload in the response
        payload_index = response_text.find(payload)
        
        if payload_index != -1:
            # Extract context around the payload
            start_index = max(0, payload_index - 50)
            end_index = min(len(response_text), payload_index + len(payload) + 50)
            snippet = response_text[start_index:end_index]
            
            # Add markers to highlight the payload
            snippet = snippet.replace(payload, f">>>{payload}<<<")
            return snippet
        
        # If direct payload not found, check for HTML-encoded version
        encoded_payload = html.escape(payload)
        encoded_index = response_text.find(encoded_payload)
        
        if encoded_index != -1:
            start_index = max(0, encoded_index - 50)
            end_index = min(len(response_text), encoded_index + len(encoded_payload) + 50)
            snippet = response_text[start_index:end_index]
            snippet = snippet.replace(encoded_payload, f">>>{encoded_payload}<<<")
            return snippet
        
        # If still not found, look for partial matches
        try:
            soup = BeautifulSoup(response_text, 'lxml')
        except:
            soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check in script tags
        for script in soup.find_all('script'):
            if payload in script.text:
                return f"Script content: {script.text[:100]}..."
        
        # Check in dangerous contexts
        dangerous_contexts = ['style', 'svg', 'iframe', 'object', 'embed']
        for context in dangerous_contexts:
            for element in soup.find_all(context):
                if payload in str(element):
                    return f"{context.upper()} element: {str(element)[:100]}..."
        
        # Check in event handlers
        for element in soup.find_all():
            for attr_name, attr_value in element.attrs.items():
                if attr_name.startswith('on') and payload in str(attr_value):
                    return f"Event handler {attr_name}: {attr_value}"
        
        return "Payload reflection detected but context unclear"

                     
    def _extract_param_from_evidence(self, evidence: str) -> Optional[str]:
        """
        Extract parameter name from evidence string.
        
        Args:
            evidence: Evidence string containing the reflected payload
            
        Returns:
            Optional[str]: Parameter name if found, None otherwise
        """
        # Try to extract parameter name from common patterns
        
        # Look for common parameter patterns
        param_patterns = [
            r'name="([^"]+)"',
            r'parameter[:\s]+([^\s,]+)',
            r'param[:\s]+([^\s,]+)',
            r'field[:\s]+([^\s,]+)'
        ]
        
        for pattern in param_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    async def _check_dom_xss(self, url: str) -> List[Dict]:
        """
        Check for DOM-based XSS vulnerabilities.
        
        Args:
            url: URL to check for DOM XSS
            
        Returns:
            List[Dict]: List of DOM XSS findings
        """
        vulnerabilities = []
        
        # DOM XSS payloads that work with common JavaScript patterns
        dom_payloads = [
            "#<script>alert('DOM-XSS')</script>",
            "#<img src=x onerror=alert('DOM-XSS')>",
            "#javascript:alert('DOM-XSS')",
            "#'><script>alert('DOM-XSS')</script>",
            "#\"><script>alert('DOM-XSS')</script>",
        ]
        
        for payload in dom_payloads:
            test_url = url + payload
            
            try:
                timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                    async with session.get(test_url, timeout=self.timeout) as response:
                        response_text = await response.text()
                        
                        # Check for DOM XSS indicators
                        if self._check_dom_xss_indicators(response_text, payload):
                            vulnerabilities.append({
                                "type": "DOM XSS",
                                "endpoint": url,
                                "parameter": "URL Fragment",
                                "method": "GET",
                                "payload": payload,
                                "evidence": self._extract_dom_xss_evidence(response_text, payload),
                                "severity": "High",
                                "description": "DOM-based Cross-Site Scripting vulnerability found",
                                "remediation": "Avoid using dangerous DOM methods with user input. Validate and sanitize all user input before using in DOM operations."
                            })
                            
            except Exception as e:
                self.logger.error(f"Error testing DOM XSS on {url}: {e}")
        
        return vulnerabilities

    def _check_dom_xss_indicators(self, response_text: str, payload: str) -> bool:
        """
        Check for DOM XSS indicators in the response.
        
        Args:
            response_text: Response text from the server
            payload: Payload to check for
            
        Returns:
            bool: True if DOM XSS indicators are found, False otherwise
        """
        # Look for dangerous JavaScript patterns that could lead to DOM XSS
        dangerous_patterns = [
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'location\.href\s*=',
            r'location\.hash',
            r'location\.search',
            r'window\.location',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\('
        ]
        
        import re
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Check if the payload characters appear near these patterns
                matches = re.finditer(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    start_pos = max(0, match.start() - 100)
                    end_pos = min(len(response_text), match.end() + 100)
                    context = response_text[start_pos:end_pos]
                    
                    # Check if payload elements appear in the context
                    if any(char in context for char in ['<', '>', '"', "'", '(', ')']):
                        return True
        
        return False

    def _extract_dom_xss_evidence(self, response_text: str, payload: str) -> str:
        """
        Extract evidence of DOM XSS from the response.
        
        Args:
            response_text: Response text from the server
            payload: Payload that was tested
            
        Returns:
            str: Evidence string showing the DOM XSS context
        """
        # Look for script tags that might contain vulnerable patterns
        try:
            soup = BeautifulSoup(response_text, 'lxml')
        except:
            soup = BeautifulSoup(response_text, 'html.parser')
        
        for script in soup.find_all('script'):
            script_content = script.text
            
            # Check for dangerous patterns in script content
            dangerous_patterns = [
                'document.write', 'innerHTML', 'location.href', 'location.hash',
                'eval(', 'setTimeout(', 'setInterval('
            ]
            
            for pattern in dangerous_patterns:
                if pattern in script_content:
                    # Extract relevant portion
                    pattern_index = script_content.find(pattern)
                    start_index = max(0, pattern_index - 30)
                    end_index = min(len(script_content), pattern_index + len(pattern) + 30)
                    evidence = script_content[start_index:end_index]
                    return f"Dangerous pattern found: {evidence}"
        
        return "DOM XSS indicators detected in JavaScript code"

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
            parsed_url = urlparse(url)
            
            # Test GET parameters
            if parsed_url.query:
                query_params = dict(parse_qsl(parsed_url.query))
                query_params[param_name] = payload
                new_query = urlencode(query_params)
                
                test_parts = list(parsed_url)
                test_parts[4] = new_query
                test_url = urlunparse(test_parts)
                
                timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
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
                            
                    timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                    async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                        if form.get("method") == "post":
                            async with session.post(form.get("action"), data=form_data, timeout=self.timeout) as response:
                                response_text = await response.text()
                                if self._check_for_xss_reflection(response_text, payload):
                                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error validating XSS vulnerability at '{url}': {e}")
            return False