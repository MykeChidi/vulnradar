# tests/unit/test_crawlers - Web crawlers test suite

import pytest
from unittest.mock import patch
from vulnradar.crawlers import WebCrawler


@pytest.mark.unit
class TestWebCrawler:
    """Unit tests for WebCrawler class."""
    
    def test_crawler_initialization(self):
        """Test crawler initializes with correct parameters."""
        crawler = WebCrawler(
            base_url="https://example.com",
            max_depth=3,
            timeout=10,
            max_pages=100
        )
        
        assert crawler.base_url == "https://example.com"
        assert crawler.max_depth == 3
        assert crawler.timeout == 10
        assert crawler.max_pages == 100
        assert crawler.page_count == 0
        assert len(crawler.visited_urls) == 0
    
    def test_should_crawl_same_domain(self):
        """Test URL filtering for same domain."""
        crawler = WebCrawler("https://example.com")
        
        # Should crawl same domain URLs
        assert crawler._should_crawl("https://example.com/page1")
        assert crawler._should_crawl("https://example.com/subdir/page2")
        
        # Should not crawl different domains
        assert not crawler._should_crawl("https://other.com/page1")
        assert not crawler._should_crawl("http://subdomain.example.com/page1")
    
    def test_should_crawl_skip_static_files(self):
        """Test that static files are skipped."""
        crawler = WebCrawler("https://example.com")
        
        # Should skip static files
        assert not crawler._should_crawl("https://example.com/style.css")
        assert not crawler._should_crawl("https://example.com/script.js")
        assert not crawler._should_crawl("https://example.com/image.jpg")
        assert not crawler._should_crawl("https://example.com/logo.png")
        assert not crawler._should_crawl("https://example.com/file.pdf")
    
    def test_is_html_url(self):
        """Test HTML URL detection."""
        crawler = WebCrawler("https://example.com")
        
        assert crawler._is_html_url("https://example.com/page.html")
        assert crawler._is_html_url("https://example.com/page.htm")
        assert crawler._is_html_url("https://example.com/page")
        assert not crawler._is_html_url("https://example.com/file.pdf")
        assert not crawler._is_html_url("https://example.com/image.jpg")
    
    def test_extract_links(self, sample_html):
        """Test link extraction from HTML."""
        crawler = WebCrawler("https://example.com")
        links = crawler._extract_links("https://example.com", sample_html)
        
        assert "https://example.com/page1" in links
        assert "https://example.com/page2" in links
        assert "https://example.com/submit" in links  # Form action
    
    def test_prioritize_endpoints(self):
        """Test endpoint prioritization."""
        crawler = WebCrawler("https://example.com")
        
        endpoints = [
            "https://example.com/style.css",
            "https://example.com/admin",
            "https://example.com/api/users?id=1",
            "https://example.com/search?q=test",
            "https://example.com/image.jpg"
        ]
        
        prioritized = crawler.prioritize_endpoints(endpoints)
        
        # High priority endpoints should come first
        assert "api" in prioritized[0] or "search" in prioritized[0]
        # Static files should be last
        assert ".css" in prioritized[-1] or ".jpg" in prioritized[-1]
    
    @pytest.mark.asyncio
    async def test_crawl_respects_max_pages(self, mock_session):
        """Test that crawling respects max_pages limit."""
        crawler = WebCrawler(
            base_url="https://example.com",
            max_pages=2
        )
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            urls_found = []
            async for url, status in crawler.crawl():
                urls_found.append(url)
            
            assert len(urls_found) <= 2
            assert crawler.page_count <= 2
