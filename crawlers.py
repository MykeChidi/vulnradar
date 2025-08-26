# vulnscan/crawlers.py - Web Crawling module

import asyncio
from typing import Dict, Generator, List, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service


class WebCrawler:
    """Crawler for discovering endpoints on a website."""
    
    def __init__(self, base_url: str, headers: Dict = None, max_depth: int = 3, 
                 timeout: int = 10, use_selenium: bool = False, max_pages: int = 1000):
        """
        Initialize the web crawler.
        
        Args:
            base_url: Starting URL for crawling
            headers: HTTP headers to use
            max_depth: Maximum crawl depth
            timeout: Request timeout in seconds
            use_selenium: Whether to use Selenium for JavaScript rendering
            max_pages: Maximum number of pages to crawl
        """
        self.base_url = base_url
        self.headers = headers or {}
        self.max_depth = max_depth
        self.timeout = timeout
        self.use_selenium = use_selenium
        self.max_pages = max_pages
        self.page_count = 0
        self.visited_urls = set()
        self.to_visit = [(base_url, 0)]  # (url, depth)
        self.base_domain = urlparse(base_url).netloc
        
        # Selenium setup if enabled
        self.driver = None
        if use_selenium:
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            service = Service()
            self.driver = webdriver.Chrome(service=service, options=options)
    
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.driver:
            self.driver.quit()
    
    async def crawl(self) -> Generator[Tuple[str, int], None, None]: # type: ignore
        """
        Crawl the website and yield discovered URLs with their status codes.
        
        Yields:
            Tuple[str, int]: URL and status code
        """
        session_timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(headers=self.headers, timeout=session_timeout) as session:
            while self.to_visit and self.page_count < self.max_pages:
                url, depth = self.to_visit.pop(0)
                
                # Skip if we've already visited this URL or if it's beyond max depth
                if url in self.visited_urls or depth > self.max_depth:
                    continue
                
                # Check if maximum pages has been reached
                if self.page_count >= self.max_pages:
                    break

                self.visited_urls.add(url)
                self.page_count += 1

                try:
                    # Fetch the page
                    status_code = 0
                    html_content = ""
                    
                    if self.use_selenium and self._is_html_url(url):
                        # Use Selenium for JavaScript-rendered content
                        self.driver.get(url)
                        await asyncio.sleep(2)  # Wait for JS to render
                        html_content = self.driver.page_source
                        status_code = 200  # Assume success with Selenium
                    else:
                        # Use aiohttp for regular requests
                        async with session.get(url) as response:
                            status_code = response.status
                            if self._is_html_response(response):
                                html_content = await response.text()
                    
                    # Yield the discovered URL and status code
                    yield url, status_code
                    
                    # Parse HTML and extract links if it's HTML content
                    if html_content and depth < self.max_depth:
                        new_urls = self._extract_links(url, html_content)
                        for new_url in new_urls:
                            if new_url not in self.visited_urls:
                                self.to_visit.append((new_url, depth + 1))
                                
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    # Log error but continue crawling
                    print(f"Error crawling {url}: {e}")
                except Exception as e:
                    print(f"Unexpected error crawling {url}: {e}")
                    
            print(f"Crawling finished. Total pages visited: {self.page_count}")

    def _extract_links(self, base_url: str, html_content: str) -> List[str]:
        """
        Extract links from HTML content.
        
        Args:
            base_url: Base URL for resolving relative links
            html_content: HTML content to parse
            
        Returns:
            List[str]: List of absolute URLs
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        
        # Extract links from <a> tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = urljoin(base_url, href)
            
            # Filter URLs to stay on the same domain and exclude fragments
            if self._should_crawl(absolute_url):
                links.append(absolute_url)
                
        # Extract links from <form> tags
        for form in soup.find_all('form', action=True):
            action = form.get('action', '')
            if action:
                absolute_url = urljoin(base_url, action)
                if self._should_crawl(absolute_url):
                    links.append(absolute_url)
        
        return links
    
    def _should_crawl(self, url: str) -> bool:
        """
        Check if a URL should be crawled.
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL should be crawled, False otherwise
        """
        # Parse URL
        parsed = urlparse(url)
        
        # Check if URL is on the same domain
        if parsed.netloc != self.base_domain:
            return False
            
        # Skip fragment URLs (e.g., example.com/#section)
        if not parsed.path and parsed.fragment:
            return False
            
        # Skip certain file types
        skip_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', 
                          '.css', '.js', '.ico', '.zip', '.tar', '.gz']
        if any(parsed.path.endswith(ext) for ext in skip_extensions):
            return False
            
        return True
    
    def _is_html_url(self, url: str) -> bool:
        """Check if a URL is likely to return HTML content."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check if URL ends with an HTML extension or has no extension
        return path.endswith('.html') or path.endswith('.htm') or '.' not in path.split('/')[-1]
    
    def _is_html_response(self, response) -> bool:
        """
        Check if a response contains HTML content.
        
        Args:
            response: aiohttp response object
            
        Returns:
            bool: True if response contains HTML, False otherwise
        """
        content_type = response.headers.get('Content-Type', '').lower()
        return 'text/html' in content_type