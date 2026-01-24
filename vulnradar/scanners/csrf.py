# vulnradar/scanners/csrf.py - CSRF Scanner

from typing import Dict, List
import aiohttp
from .base import BaseScanner
from ..utils.error_handler import get_global_error_handler, handle_async_errors, ScanError

# Setup error handler
error_handler = get_global_error_handler()


class CSRFScanner(BaseScanner):
    """Scanner for Cross-Site Request Forgery (CSRF) vulnerabilities."""
    
    def __init__(self, headers: Dict = None, timeout: int = 10):
        """Initialize CSRF scanner."""
        super().__init__(headers, timeout)
        
        # Common CSRF token parameter names
        self.csrf_token_names = [
            'csrf_token', 'csrf', '_token', 'token', 'authenticity_token',
            'csrf_param', '_csrf', 'csrfmiddlewaretoken', 'csrf_protection',
            'xsrf_token', 'xsrf', '_xsrf', 'anti_csrf_token', 'security_token'
        ]
        
        # Headers that might contain CSRF tokens
        self.csrf_headers = [
            'X-CSRF-Token', 'X-CSRFToken', 'X-XSRF-Token', 'X-Requested-With'
        ]
    
    @handle_async_errors(
        error_handler=error_handler,
        user_message="CSRF scan encountered an error",
        return_on_error=[]
    )
    async def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL for CSRF vulnerabilities.
        
        Args:
            url: URL to scan
            
        Returns:
            List[Dict]: List of CSRF vulnerability findings
        """
        vulnerabilities = []
        
        try:
            # Get forms from the page
            forms = await self._get_form_inputs(url)
            
            for form in forms:
                # Skip GET forms as they're not typically vulnerable to CSRF
                if form['method'].lower() == 'get':
                    continue
                    
                csrf_findings = await self._test_csrf_protection(url, form)
                vulnerabilities.extend(csrf_findings)
                
        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Error scanning '{url}' for CSRF: {str(e)}", original_error=e),
                context={"url": url, "scanner": "CSRF"}
            )
            
        return vulnerabilities
    
    async def _test_csrf_protection(self, url: str, form: Dict) -> List[Dict]:
        """
        Test a form for CSRF protection.
        
        Args:
            url: URL where the form was found
            form: Form information dictionary
            
        Returns:
            List[Dict]: List of CSRF vulnerabilities found
        """
        vulnerabilities = []
        
        # Check if form has CSRF token
        has_csrf_token = self._has_csrf_token(form)
        
        # Test 1: Missing CSRF token
        if not has_csrf_token:
            vuln = await self._test_missing_csrf_token(url, form)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Test 2: Test CSRF token validation (if token exists)
        if has_csrf_token:
            vuln = await self._test_csrf_token_validation(url, form)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Test 3: Test referrer header bypass
        vuln = await self._test_referrer_bypass(url, form)
        if vuln:
            vulnerabilities.append(vuln)
            
        return vulnerabilities
    
    def _has_csrf_token(self, form: Dict) -> bool:
        """
        Check if a form has CSRF token protection.
        
        Args:
            form: Form information dictionary
            
        Returns:
            bool: True if form has CSRF token, False otherwise
        """
        for input_field in form['inputs']:
            if input_field['name'].lower() in self.csrf_token_names:
                return True
                
        return False
    
    async def _test_missing_csrf_token(self, url: str, form: Dict) -> Dict:
        """
        Test for missing CSRF token vulnerability.
        
        Args:
            url: URL where the form was found
            form: Form information dictionary
            
        Returns:
            Dict: Vulnerability information if found, None otherwise
        """
        try:
            # Prepare form data
            form_data = {}
            for input_field in form['inputs']:
                if input_field['type'] == 'hidden':
                    form_data[input_field['name']] = input_field['value']
                else:
                    form_data[input_field['name']] = 'csrf_test_value'
            
            # Submit form without CSRF token
            timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
            async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                if form['method'].lower() == 'post':
                    async with session.post(
                        form['action'] or url,
                        data=form_data,
                        timeout=self.timeout,
                        allow_redirects=False
                    ) as response:
                        response_text = await response.text()
                        
                        # Check if request was successful (indicates missing CSRF protection)
                        if response.status in [200, 201, 302, 303]:
                            return {
                                "type": "CSRF",
                                "severity": "Medium",
                                "endpoint": form['action'] or url,
                                "description": "Form lacks CSRF token protection",
                                "evidence": f"Form submitted successfully without CSRF token. Status: {response.status}",
                                "payload": str(form_data),
                                "remediation": "Implement CSRF token validation for all state-changing operations",
                                "confidence": "High"
                            }
                            
        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Error testing missing CSRF token: {str(e)}", original_error=e),
                context={"url": url, "scanner": "CSRF"}
            )
            
        return None
    
    async def _test_csrf_token_validation(self, url: str, form: Dict) -> Dict:
        """
        Test CSRF token validation bypass.
        
        Args:
            url: URL where the form was found
            form: Form information dictionary
            
        Returns:
            Dict: Vulnerability information if found, None otherwise
        """
        try:
            # Get the original form with CSRF token
            original_form_data = {}
            csrf_token_field = None
            
            for input_field in form['inputs']:
                original_form_data[input_field['name']] = input_field['value']
                if input_field['name'].lower() in self.csrf_token_names:
                    csrf_token_field = input_field['name']
            
            if not csrf_token_field:
                return None
            
            # Test 1: Remove CSRF token
            test_data = original_form_data.copy()
            del test_data[csrf_token_field]
            
            vulnerability = await self._submit_csrf_test(url, form, test_data, "CSRF token removed")
            if vulnerability:
                return vulnerability
            
            # Test 2: Invalid CSRF token
            test_data = original_form_data.copy()
            test_data[csrf_token_field] = "invalid_csrf_token_12345"
            
            vulnerability = await self._submit_csrf_test(url, form, test_data, "Invalid CSRF token")
            if vulnerability:
                return vulnerability
            
            # Test 3: Empty CSRF token
            test_data = original_form_data.copy()
            test_data[csrf_token_field] = ""
            
            vulnerability = await self._submit_csrf_test(url, form, test_data, "Empty CSRF token")
            if vulnerability:
                return vulnerability
                
        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Error testing CSRF token validation: {str(e)}", original_error=e),
                context={"url": url, "scanner": "CSRF"}
            )
            
        return None
    
    async def _test_referrer_bypass(self, url: str, form: Dict) -> Dict:
        """
        Test for referrer header bypass vulnerability.
        
        Args:
            url: URL where the form was found
            form: Form information dictionary
            
        Returns:
            Dict: Vulnerability information if found, None otherwise
        """
        try:
            # Prepare form data
            form_data = {}
            for input_field in form['inputs']:
                form_data[input_field['name']] = input_field['value'] or 'test_value'
            
            # Test with different referrer headers
            test_headers = self.headers.copy()
            test_headers['Referer'] = 'https://evil.com'
            
            timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
            async with aiohttp.ClientSession(headers=test_headers, timeout=timeout) as session:
                if form['method'].lower() == 'post':
                    async with session.post(
                        form['action'] or url,
                        data=form_data,
                        timeout=self.timeout,
                        allow_redirects=False
                    ) as response:
                        if response.status in [200, 201, 302, 303]:
                            return {
                                "type": "CSRF",
                                "severity": "Medium",
                                "endpoint": form['action'] or url,
                                "description": "Form accepts requests from external referrers",
                                "evidence": f"Form submitted successfully with external referrer. Status: {response.status}",
                                "payload": f"Referrer: https://evil.com, Data: {form_data}",
                                "remediation": "Implement proper referrer validation or use SameSite cookies",
                                "confidence": "Medium"
                            }
                            
        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Error testing referrer bypass: {str(e)}", original_error=e),
                context={"url": url, "scanner": "CSRF"}
            )
            
        return None
    
    async def _submit_csrf_test(self, url: str, form: Dict, test_data: Dict, test_type: str) -> Dict:
        """
        Submit a CSRF test and check for vulnerability.
        
        Args:
            url: URL where the form was found
            form: Form information dictionary
            test_data: Data to submit
            test_type: Type of test being performed
            
        Returns:
            Dict: Vulnerability information if found, None otherwise
        """
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
            async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                if form['method'].lower() == 'post':
                    async with session.post(
                        form['action'] or url,
                        data=test_data,
                        timeout=self.timeout,
                        allow_redirects=False
                    ) as response:
                        if response.status in [200, 201, 302, 303]:
                            return {
                                "type": "CSRF",
                                "severity": "Medium",
                                "endpoint": form['action'] or url,
                                "description": f"CSRF token validation bypass: {test_type}",
                                "evidence": f"Form submitted successfully with {test_type.lower()}. Status: {response.status}",
                                "payload": str(test_data),
                                "remediation": "Implement proper CSRF token validation",
                                "confidence": "High"
                            }
                            
        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Error submitting CSRF test: {str(e)}", original_error=e),
                context={"url": url, "scanner": "CSRF"}
            )
            
        return None
    
    @handle_async_errors(
        error_handler=error_handler,
        user_message="CSRF validation encountered an error",
        return_on_error=False
    )
    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate a CSRF vulnerability finding.
        
        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            
        Returns:
            bool: True if vulnerability is confirmed valid, False otherwise
        """
        try:
            # Re-test the specific vulnerability
            forms = await self._get_form_inputs(url)
            
            for form in forms:
                if form['action'] == url or (not form['action'] and url == url):
                    # Test if we can still submit without proper CSRF protection
                    test_data = eval(payload) if payload.startswith('{') else {}
                    
                    timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout)
                    async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
                        if form['method'].lower() == 'post':
                            async with session.post(
                                form['action'] or url,
                                data=test_data,
                                timeout=self.timeout,
                                allow_redirects=False
                            ) as response:
                                return response.status in [200, 201, 302, 303]
                                
        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Error validating CSRF vulnerability in '{url}': {str(e)}", original_error=e),
                context={"url": url, "scanner": "CSRF"}
            )
            
        return False