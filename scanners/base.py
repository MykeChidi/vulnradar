# vulnscan/scanners/base.py - Base Scanner class

import abc
from typing import Dict, List

import aiohttp
from bs4 import BeautifulSoup


class BaseScanner(abc.ABC):
    """Base class for vulnerability scanners."""
    
    def __init__(self, headers: Dict = None, timeout: int = 10):
        """
        Initialize the scanner.
        
        Args:
            headers: HTTP headers to use
            timeout: Request timeout in seconds
        """
        self.headers = headers or {}
        self.timeout = timeout
        
    @abc.abstractmethod
    async def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL for vulnerabilities.
        
        Args:
            url: URL to scan
            
        Returns:
            List[Dict]: List of vulnerability findings
        """
        pass
        
    @abc.abstractmethod
    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate a vulnerability finding.
        
        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            
        Returns:
            bool: True if vulnerability is confirmed valid, False otherwise
        """
        pass
        
    async def _get_form_inputs(self, url: str) -> List[Dict]:
        """
        Extract forms and their inputs from a URL.
        
        Args:
            url: URL to extract forms from
            
        Returns:
            List[Dict]: List of forms with their inputs
        """
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status != 200:
                        return []
                        
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    forms = []
                    
                    for form in soup.find_all('form'):
                        form_info = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'get').lower(),
                            'inputs': []
                        }
                        
                        # Handle relative URLs
                        if form_info['action'].startswith('/'):
                            from urllib.parse import urlparse
                            parsed_url = urlparse(url)
                            form_info['action'] = f"{parsed_url.scheme}://{parsed_url.netloc}{form_info['action']}"
                        elif not form_info['action']:
                            form_info['action'] = url
                        
                        # Extract inputs
                        for input_tag in form.find_all(['input', 'textarea', 'select']):
                            input_type = input_tag.get('type', '')
                            input_name = input_tag.get('name', '')
                            
                            # Skip submit, button, reset, etc.
                            if input_type in ['submit', 'button', 'reset', 'image']:
                                continue
                                
                            # Skip inputs without name
                            if not input_name:
                                continue
                                
                            form_info['inputs'].append({
                                'name': input_name,
                                'type': input_type,
                                'value': input_tag.get('value', '')
                            })
                            
                        forms.append(form_info)
                        
                    return forms
                    
        except Exception as e:
            print(f"Error extracting forms from {url}: {e}")
            return []

    async def _extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract parameters from URL query string.
        
        Args:
            url: URL to extract parameters from
            
        Returns:
            Dict[str, str]: Dictionary of parameter names and values
        """
        from urllib.parse import parse_qs, urlparse
        
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # Convert list values to single strings
            return {k: v[0] if v else '' for k, v in query_params.items()}
            
        except Exception as e:
            print(f"Error extracting parameters from {url}: {e}")
            return {}