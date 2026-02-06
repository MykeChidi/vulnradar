# tests/conftest.py - Pytest configuration and fixtures

import pytest
import asyncio
import aiohttp
from pathlib import Path
from unittest.mock import Mock, AsyncMock, MagicMock
import sys
import tempfile
import shutil
from datetime import datetime, timedelta
import sqlite3
from contextlib import contextmanager

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnradar.reconn._target import ReconTarget
from tests.factories import (
    EndpointFactory, ResponseFactory, FindingFactory, TargetFactory,
    ReconDataFactory, generate_endpoints, generate_large_response_set,
    create_malformed_responses, BLIND_SQLI_PAYLOADS, DOM_XSS_PAYLOADS,
    COMMAND_INJECTION_BLIND_PAYLOADS, SSRF_BYPASS_PAYLOADS,
    ENCODING_BYPASS_PAYLOADS, PATH_TRAVERSAL_PAYLOADS,
    FILE_INCLUSION_PAYLOADS, CSRF_TOKEN_PATTERNS
)

@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def mock_target():
    """Create a mock ReconTarget."""
    return ReconTarget(
        url="https://example.com",
        hostname="example.com",
        ip="93.184.216.34",
        port=443,
        is_https=True
    )

@pytest.fixture
def mock_options():
    """Create mock scan options."""
    return {
        "crawl_depth": 3,
        "timeout": 10,
        "max_workers": 5,
        "max_crawl_pages": 100,
        "use_selenium": False,
        "port_scan": False,
        "scan_sqli": True,
        "scan_xss": True,
        "scan_csrf": True,
        "scan_ssrf": True,
        "scan_path_traversal": True,
        "scan_file_inclusion": True,
        "scan_command_injection": True,
        "advanced_recon_only": False,
        "recon_all": False,
        "advanced_port_scan": True,
        "detect_waf": True,
        "detect_load_balancers": True,
        "service_detection": True,
        "os_detection": True,
        "script_scan": False,
        "content_discovery": True,
        "js_analysis": True,
        "dir_enum": False,
        "subdomain_enum": True,
        "cloud_mapping": True,
        "dns_bruteforce": True,
        "ssl_analysis": True,
        "security_headers": True,
        "error_analysis": True,
        "cache_analysis": True,
        "check_debug_mode": True,
        "check_dev_artifacts": True,
        "backend_tests": True,
        "output_dir": "test_results",
        "use_db": False,
        "html_report": True,
        "pdf_report": False,
        "json_report": True,
        "excel_report": False,
        "cache_dir": "test_cache",
        "cache_ttl": 3600,
        "no_cache": False,
        "clear_cache": False
    }

@pytest.fixture
def temp_cache_dir():
    """Create a temporary cache directory."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)

@pytest.fixture
def temp_output_dir():
    """Create a temporary output directory."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)

@pytest.fixture
async def mock_session():
    """Create a mock aiohttp ClientSession."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    response = AsyncMock()
    response.status = 200
    response.text = AsyncMock(return_value="<html><body>Test</body></html>")
    response.read = AsyncMock(return_value=b"Test content")
    response.headers = {"Content-Type": "text/html"}
    
    session.get = AsyncMock(return_value=response)
    session.post = AsyncMock(return_value=response)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    
    yield session

@pytest.fixture
def mock_dns_resolver():
    """Create a mock DNS resolver."""
    resolver = Mock()
    
    # Mock A records
    a_record = Mock()
    a_record.address = "93.184.216.34"
    resolver.resolve = Mock(return_value=[a_record])
    
    return resolver

@pytest.fixture
def mock_nmap_scanner():
    """Create a mock nmap PortScanner."""
    scanner = Mock()
    scanner.all_hosts = Mock(return_value=["93.184.216.34"])
    scanner.scan = Mock()
    
    # Mock scan results
    scanner.__getitem__ = Mock(return_value={
        "tcp": {
            80: {
                "state": "open",
                "name": "http",
                "product": "nginx",
                "version": "1.18.0",
                "extrainfo": "",
                "reason": "syn-ack",
                "cpe": "cpe:/a:nginx:nginx:1.18.0"
            },
            443: {
                "state": "open",
                "name": "https",
                "product": "nginx",
                "version": "1.18.0",
                "extrainfo": "",
                "reason": "syn-ack",
                "cpe": "cpe:/a:nginx:nginx:1.18.0"
            }
        }
    })
    
    return scanner

@pytest.fixture
def sample_html():
    """Sample HTML content for testing."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page</title>
        <meta name="generator" content="WordPress 5.8">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/css/bootstrap.min.css">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    </head>
    <body>
        <h1>Test Page</h1>
        <form action="/submit" method="post">
            <input type="text" name="username" value="">
            <input type="password" name="password" value="">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="submit" value="Login">
        </form>
        <a href="/page1">Page 1</a>
        <a href="/page2">Page 2</a>
        <script>
            var apiKey = "sk-test-1234567890";
            fetch('/api/data');
        </script>
    </body>
    </html>
    """

@pytest.fixture
def sample_robots_txt():
    """Sample robots.txt content."""
    return """
User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /backup/
Allow: /public/
Sitemap: https://example.com/sitemap.xml
    """

@pytest.fixture
def sample_sitemap_xml():
    """Sample sitemap.xml content."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://example.com/</loc>
        <lastmod>2024-01-01</lastmod>
    </url>
    <url>
        <loc>https://example.com/page1</loc>
        <lastmod>2024-01-01</lastmod>
    </url>
    <url>
        <loc>https://example.com/page2</loc>
        <lastmod>2024-01-01</lastmod>
    </url>
</urlset>
    """

@pytest.fixture
def vulnerability_sample():
    """Sample vulnerability finding."""
    return {
        "type": "SQL Injection",
        "severity": "High",
        "endpoint": "https://example.com/login",
        "parameter": "username",
        "method": "POST",
        "payload": "' OR '1'='1",
        "evidence": "SQL syntax error",
        "description": "SQL Injection vulnerability found",
        "remediation": "Use parameterized queries"
    }

@pytest.fixture
def mock_ssl_certificate():
    """Mock SSL certificate for testing."""
    return {
        "subject": {"commonName": "example.com"},
        "issuer": {"commonName": "Let's Encrypt"},
        "version": 3,
        "serialNumber": "123456789",
        "notBefore": "Jan 1 00:00:00 2024 GMT",
        "notAfter": "Jan 1 00:00:00 2025 GMT",
        "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")]
    }

@pytest.fixture
def mock_cache(temp_cache_dir):
    """Mock cache for testing."""
    from ..vulnradar.utils.cache import ScanCache
    return ScanCache(temp_cache_dir, default_ttl=3600)


# ============================================================================
# NEW FIXTURES FOR COMPREHENSIVE TESTING
# ============================================================================

# SESSION-SCOPED DATABASE FIXTURE

@pytest.fixture(scope="session")
def db_session_file():
    """Create a session-scoped temporary database file."""
    db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = Path(db_file.name)
    db_file.close()
    
    yield db_path
    
    # Cleanup
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def db_session(db_session_file):
    """Provide an in-memory database per test with session-level persistence."""
    conn = sqlite3.connect(str(db_session_file))
    cursor = conn.cursor()
    
    # Create minimal schema for testing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            type TEXT,
            severity TEXT,
            endpoint TEXT,
            parameter TEXT,
            method TEXT,
            payload TEXT,
            evidence TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY,
            target TEXT,
            scan_date TEXT,
            total_findings INTEGER
        )
    """)
    conn.commit()
    
    yield conn
    
    # Clear tables between tests
    cursor.execute("DELETE FROM findings")
    cursor.execute("DELETE FROM scan_results")
    conn.commit()
    conn.close()


# FACTORY-BASED TEST DATA FIXTURES

@pytest.fixture
def endpoint_factory():
    """Provide endpoint factory."""
    return EndpointFactory


@pytest.fixture
def response_factory():
    """Provide response factory."""
    return ResponseFactory


@pytest.fixture
def finding_factory():
    """Provide finding factory."""
    return FindingFactory


@pytest.fixture
def target_factory():
    """Provide target factory."""
    return TargetFactory


@pytest.fixture
def recon_data_factory():
    """Provide recon data factory."""
    return ReconDataFactory


@pytest.fixture
def test_endpoints():
    """Generate 100 test endpoints."""
    return generate_endpoints(count=100, seed=42)


@pytest.fixture
def large_test_dataset():
    """Generate large dataset for performance testing (1000 endpoints, 2000+ findings)."""
    return generate_large_response_set(endpoint_count=1000, findings_per_endpoint=2)


@pytest.fixture
def malformed_responses():
    """Provide malformed responses for edge case testing."""
    return create_malformed_responses()


# PAYLOAD FIXTURES (organized by vulnerability type)

@pytest.fixture
def blind_sqli_payloads():
    """Provide blind SQLi payload set."""
    return BLIND_SQLI_PAYLOADS


@pytest.fixture
def dom_xss_payloads():
    """Provide DOM XSS payload set."""
    return DOM_XSS_PAYLOADS


@pytest.fixture
def command_injection_blind_payloads():
    """Provide command injection blind payload set."""
    return COMMAND_INJECTION_BLIND_PAYLOADS


@pytest.fixture
def ssrf_bypass_payloads():
    """Provide SSRF bypass payload set."""
    return SSRF_BYPASS_PAYLOADS


@pytest.fixture
def encoding_bypass_payloads():
    """Provide encoding bypass payload set."""
    return ENCODING_BYPASS_PAYLOADS


@pytest.fixture
def path_traversal_payloads():
    """Provide path traversal payload set."""
    return PATH_TRAVERSAL_PAYLOADS


@pytest.fixture
def file_inclusion_payloads():
    """Provide file inclusion payload set."""
    return FILE_INCLUSION_PAYLOADS


@pytest.fixture
def csrf_token_patterns():
    """Provide CSRF token pattern definitions."""
    return CSRF_TOKEN_PATTERNS


# NETWORK SIMULATION FIXTURES (using aioresponses)

@pytest.fixture
def aioresponses_mock():
    """Provide aioresponses mock for HTTP simulation."""
    from aioresponses import aioresponses
    with aioresponses() as m:
        yield m


@pytest.fixture
def network_failure_responses():
    """Provide network failure simulation helpers."""
    from aioresponses import aioresponses
    import asyncio
    
    @contextmanager
    def timeout_response(url):
        """Simulate timeout on URL."""
        with aioresponses() as m:
            m.get(url, exception=asyncio.TimeoutError())
            yield m
    
    @contextmanager
    def connection_reset_response(url):
        """Simulate connection reset on URL."""
        with aioresponses() as m:
            m.get(url, exception=ConnectionResetError())
            yield m
    
    @contextmanager
    def rate_limit_response(url):
        """Simulate rate limiting (429) on URL."""
        with aioresponses() as m:
            m.get(url, status=429)
            yield m
    
    @contextmanager
    def truncated_response(url, partial_html):
        """Simulate truncated response."""
        with aioresponses() as m:
            m.get(url, payload={"text": partial_html})
            yield m
    
    return {
        "timeout": timeout_response,
        "connection_reset": connection_reset_response,
        "rate_limit": rate_limit_response,
        "truncated": truncated_response,
    }


# CONCURRENCY TEST FIXTURES

@pytest.fixture
def concurrent_access_tracker():
    """Track concurrent access for race condition testing."""
    class ConcurrentTracker:
        def __init__(self):
            self.access_count = 0
            self.max_concurrent = 0
            self.current_concurrent = 0
        
        def enter(self):
            self.current_concurrent += 1
            self.access_count += 1
            self.max_concurrent = max(self.max_concurrent, self.current_concurrent)
        
        def exit(self):
            self.current_concurrent -= 1
    
    return ConcurrentTracker()


@pytest.fixture
def async_failure_injector():
    """Inject failures into async operations."""
    class FailureInjector:
        def __init__(self):
            self.should_fail = False
            self.failure_type = None
            self.failure_after = None
            self.call_count = 0
        
        async def maybe_fail(self):
            self.call_count += 1
            if self.should_fail and (self.failure_after is None or self.call_count >= self.failure_after):
                if self.failure_type == "timeout":
                    raise asyncio.TimeoutError()
                elif self.failure_type == "connection":
                    raise ConnectionError()
                elif self.failure_type == "value":
                    raise ValueError()
                elif self.failure_type == "cancelled":
                    raise asyncio.CancelledError()
    
    return FailureInjector()


# PERFORMANCE TESTING FIXTURES

@pytest.fixture
def performance_timer():
    """Measure performance metrics."""
    class PerfTimer:
        def __init__(self):
            self.timings = {}
            self.start_time = None
        
        def start(self, label):
            if label not in self.timings:
                self.timings[label] = []
            self.start_time = datetime.utcnow()
        
        def stop(self, label):
            if self.start_time:
                elapsed = (datetime.utcnow() - self.start_time).total_seconds()
                self.timings[label].append(elapsed)
                self.start_time = None
                return elapsed
        
        def average(self, label):
            if label in self.timings and self.timings[label]:
                return sum(self.timings[label]) / len(self.timings[label])
            return 0
    
    return PerfTimer()


@pytest.fixture
def memory_tracker():
    """Track memory usage during tests."""
    import tracemalloc
    
    class MemoryTracker:
        def __init__(self):
            self.snapshots = {}
        
        def start(self, label):
            tracemalloc.start()
            self.snapshots[label] = tracemalloc.take_snapshot()
        
        def stop(self, label):
            current = tracemalloc.take_snapshot()
            top_stats = current.compare_to(self.snapshots[label], 'lineno')
            tracemalloc.stop()
            return top_stats
    
    return MemoryTracker()


# MOCKING & VALIDATION FIXTURES

@pytest.fixture
def input_validator_bypass_tester():
    """Test input validation bypass attempts."""
    class BypassTester:
        def __init__(self):
            self.bypass_payloads = {
                "ssrf": [
                    "127.0.0.1",
                    "localhost",
                    "169.254.169.254",
                    "[::1]",
                    "0x7f000001",
                ],
                "path_traversal": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "....//....//etc/passwd",
                    "..%252f..%252fetc%252fpasswd",
                ],
                "header_injection": [
                    "\r\nSet-Cookie: admin=true",
                    "\r\nContent-Length: 0",
                ],
            }
        
        def get_payloads(self, type_name):
            return self.bypass_payloads.get(type_name, [])
    
    return BypassTester()


@pytest.fixture
def xss_report_validator():
    """Validate XSS prevention in reports."""
    class XSSValidator:
        @staticmethod
        def contains_unescaped_html(text):
            """Check if text contains unescaped HTML."""
            dangerous_patterns = ["<script", "<img", "onerror=", "onclick=", "javascript:"]
            return any(pattern in text.lower() for pattern in dangerous_patterns)
        
        @staticmethod
        def is_properly_escaped(text):
            """Check if HTML entities are properly escaped."""
            escaped = ["&lt;", "&gt;", "&quot;", "&#x27;", "&amp;"]
            return any(esc in text for esc in escaped)
    
    return XSSValidator()


# Markers for test categorization
def pytest_configure(config):
    """Configure custom markers."""
    markers = [
        "unit: mark test as a unit test",
        "integration: mark test as an integration test",
        "security: mark test as security-focused",
        "payload: mark test as payload/technique focused",
        "concurrency: mark test as concurrency-focused",
        "performance: mark test as performance-focused",
        "edge_case: mark test as edge case",
        "compatibility: mark test as compatibility check",
        "slow: mark test as slow running",
        "requires_network: mark test as requiring network access",
        "requires_root: mark test as requiring root privileges",
        "asyncio: mark test as async",
    ]
    
    for marker in markers:
        config.addinivalue_line("markers", marker)