# vulnscan/_recon/misc.py - Miscellaneous analysis techniques
import aiohttp
from typing import Dict, List
import re
from pathlib import Path
from utils.logger import setup_logger
from utils.rate_limit import RateLimiter
from utils.cache import ScanCache
from _recon._target import ReconTarget


class MiscellaneousAnalyzer:
    """
    Handles miscellaneous analysis techniques including error analysis,
    cache behavior, and other specialized tests.
    """
    
    def __init__(self, target: ReconTarget, options: Dict):
        self.target = target
        self.options = options
        self.logger = setup_logger("misc_analyzer", scanner_specific=True)
        self.rate_limiter = RateLimiter()
        # Initialize cache
        if not options.get("no_cache", False):
            cache_dir = Path(options.get("cache_dir", "cache")) / "misc"
            self._cache = ScanCache(cache_dir, default_ttl=options.get("cache_ttl", 3600))
        else:
            self._cache = None

    async def analyze(self) -> Dict:
        """
        Perform miscellaneous analysis techniques.
        
        Returns:
            Dict containing all miscellaneous findings
        """
        results = {}
        
        # Analyze error responses
        if self.options.get('error_analysis', True):
            results['error_handling'] = await self._analyze_error_responses()
            
        # Analyze caching behavior
        if self.options.get('cache_analysis', True):
            results['cache_behavior'] = await self._analyze_cache()
            
        # Additional specialized tests
        results['additional_tests'] = await self._run_specialized_tests()
        
        return results
        
    async def _analyze_error_responses(self) -> Dict:
        """
        Analyze application error handling and information disclosure.
        """
        error_results = {
            "error_pages": {},
            "stack_traces": [],
            "information_leaks": [],
            "error_patterns": {}
        }
        
        try:
            # Test common error triggers
            error_triggers = [
                ("404", "/nonexistent_page_12345"),
                ("500", "/internal_error_trigger"),
                ("403", "/admin/"),
                ("400", "/?param=[invalid]")
            ]
            
            async with aiohttp.ClientSession() as session:
                for error_type, path in error_triggers:
                    url = f"{self.target.url}{path}"
                    try:
                        async with session.get(url) as response:
                            content = await response.text()
                            error_results["error_pages"][error_type] = await self._analyze_error_page(
                                content,
                                response.status
                            )
                    except Exception as e:
                        self.logger.debug(f"Error trigger failed for {error_type}: {str(e)}")
                        
            # Analyze for patterns
            error_results["error_patterns"] = await self._identify_error_patterns(
                error_results["error_pages"]
            )
            
            return error_results
            
        except Exception as e:
            self.logger.error(f"Error response analysis failed: {str(e)}")
            return {"error": str(e)}
            
    async def _analyze_error_page(self, content: str, status_code: int) -> Dict:
        """Analyze an error page for sensitive information."""
        result = {
            "status_code": status_code,
            "type": "custom" if len(content) > 100 else "default",
            "information_leaks": [],
            "stack_trace": None,
            "framework_info": None
        }
        
        # Check for stack traces
        stack_trace_patterns = [
            r"(?s)(?:Exception|Error|Stack trace|Stack Track):\s*\n.*?(?:\n\n|\Z)",
            r"(?s)at [\w\.$]+\([^\)]*\)(?:\n|\Z)",
            r"(?s)File \"[^\"]+\", line \d+, in"
        ]
        
        for pattern in stack_trace_patterns:
            matches = re.findall(pattern, content)
            if matches:
                result["stack_trace"] = matches[0]
                result["information_leaks"].append("Stack trace exposed")
                
        # Check for framework information
        framework_patterns = {
            "Django": r"Django Version: [\d\.]+",
            "Rails": r"Rails [\d\.]+",
            "Laravel": r"Laravel v[\d\.]+",
            "ASP.NET": r"ASP\.NET [\d\.]+",
            "PHP": r"PHP Version [\d\.]+"
        }
        
        for framework, pattern in framework_patterns.items():
            match = re.search(pattern, content)
            if match:
                result["framework_info"] = {
                    "name": framework,
                    "version": match.group(0)
                }
                result["information_leaks"].append(f"Framework version exposed: {framework}")
                
        # Check for sensitive information
        sensitive_patterns = {
            "File paths": r"(?:[A-Za-z]:\\|/var/www/|/home/|/usr/local/)",
            "Database errors": r"(?:SQL syntax|mysql_fetch_array|mysqli|pg_query)",
            "IP addresses": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "Email addresses": r"\b[\w\.-]+@[\w\.-]+\.\w+\b"
        }
        
        for info_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                result["information_leaks"].append(f"{info_type} exposed")
                
        return result
        
    async def _identify_error_patterns(self, error_pages: Dict) -> Dict:
        """Identify patterns in error handling across different error types."""
        patterns = {
            "consistent_handling": True,
            "custom_pages": False,
            "information_disclosure": [],
            "recommendations": []
        }
        
        # Check for consistency in error handling
        page_lengths = [len(str(page)) for page in error_pages.values()]
        if max(page_lengths) - min(page_lengths) > 500:
            patterns["consistent_handling"] = False
            patterns["recommendations"].append(
                "Implement consistent error handling across all error types"
            )
            
        # Check for custom error pages
        for error_info in error_pages.values():
            if error_info.get("type") == "custom":
                patterns["custom_pages"] = True
                
        if not patterns["custom_pages"]:
            patterns["recommendations"].append(
                "Implement custom error pages to prevent information disclosure"
            )
            
        # Analyze information disclosure patterns
        all_leaks = set()
        for error_info in error_pages.values():
            all_leaks.update(error_info.get("information_leaks", []))
            
        if all_leaks:
            patterns["information_disclosure"] = list(all_leaks)
            patterns["recommendations"].append(
                "Remove sensitive information from error pages"
            )
            
        return patterns
        
    def _analyze_cache_headers(self, headers: Dict) -> Dict:
        """Analyze cache-related headers."""
        cache_info = {
            "headers": {},
            "directives": [],
            "issues": [],
            "recommendations": []
        }
        
        cache_headers = {
            "Cache-Control",
            "Expires",
            "ETag",
            "Last-Modified",
            "Pragma",
            "Vary"
        }
        
        for header in cache_headers:
            if header in headers:
                cache_info["headers"][header] = headers[header]
                
        # Analyze Cache-Control
        if "Cache-Control" in headers:
            directives = [d.strip() for d in headers["Cache-Control"].split(",")]
            cache_info["directives"] = directives
            
            # Check for security issues
            if "private" not in directives and "public" not in directives:
                cache_info["issues"].append("No cache privacy directive specified")
                cache_info["recommendations"].append(
                    "Add 'private' directive for sensitive content"
                )
                
            if "no-store" not in directives and "no-cache" not in directives:
                cache_info["issues"].append("Content may be cached inappropriately")
                cache_info["recommendations"].append(
                    "Consider adding 'no-store' for sensitive content"
                )
                
        return cache_info
        
    async def _test_cache_behavior(self, session: aiohttp.ClientSession) -> Dict:
        """Test caching behavior with various requests."""
        results = {
            "browser_caching": {},
            "cdn_caching": {},
            "issues": []
        }
        
        # Test browser caching
        async def test_with_headers(headers: Dict) -> Dict:
            async with session.get(self.target.url, headers=headers) as response:
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "cached": "cf-cache-status" in response.headers or
                            "x-cache" in response.headers
                }
                
        # Test with different cache scenarios
        scenarios = {
            "fresh": {},
            "if_modified": {"If-Modified-Since": "Wed, 21 Oct 2015 07:28:00 GMT"},
            "etag": {"If-None-Match": "\"123456789\""},
            "no_cache": {"Cache-Control": "no-cache"}
        }
        
        for scenario, headers in scenarios.items():
            results["browser_caching"][scenario] = await test_with_headers(headers)
            
        return results
        
    async def _check_cache_poisoning(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Check for potential cache poisoning vulnerabilities."""
        vulnerabilities = []
        
        # Test cases for cache poisoning
        test_cases = [
            {
                "name": "Host header manipulation",
                "headers": {"Host": "evil.com"},
                "description": "Cache key based on Host header"
            },
            {
                "name": "X-Forwarded-Host injection",
                "headers": {"X-Forwarded-Host": "evil.com"},
                "description": "Cache key based on X-Forwarded-Host"
            }
        ]
        
        for test in test_cases:
            try:
                async with session.get(self.target.url, headers=test["headers"]) as response:
                    if "X-Cache" in response.headers or "CF-Cache-Status" in response.headers:
                        vulnerabilities.append({
                            "type": test["name"],
                            "description": test["description"],
                            "evidence": dict(response.headers)
                        })
            except Exception as e:
                self.logger.debug(f"Cache poisoning test failed: {str(e)}")
                
        return vulnerabilities
        
    async def _analyze_cdn_caching(self) -> Dict:
        """Analyze CDN caching behavior."""
        cdn_results = {
            "provider": None,
            "caching_enabled": False,
            "cache_times": {},
            "issues": []
        }
        
        # Common CDN cache headers
        cdn_headers = {
            "Cloudflare": ["cf-cache-status", "cf-ray"],
            "Akamai": ["x-cache", "x-check-cacheable"],
            "Fastly": ["fastly-debug-digest", "x-served-by"],
            "CloudFront": ["x-amz-cf-id", "x-cache"]
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target.url) as response:
                    headers = response.headers
                    
                    # Identify CDN
                    for provider, signatures in cdn_headers.items():
                        if any(sig.lower() in headers for sig in signatures):
                            cdn_results["provider"] = provider
                            cdn_results["caching_enabled"] = True
                            break
                            
                    # Analyze cache times
                    if "Cache-Control" in headers:
                        cdn_results["cache_times"]["Cache-Control"] = headers["Cache-Control"]
                    if "Expires" in headers:
                        cdn_results["cache_times"]["Expires"] = headers["Expires"]
                        
                    # Check for issues
                    if cdn_results["caching_enabled"]:
                        if "Vary" not in headers:
                            cdn_results["issues"].append(
                                "No Vary header set for CDN caching"
                            )
                            
        except Exception as e:
            self.logger.error(f"CDN cache analysis failed: {str(e)}")
            
        return cdn_results
        
    async def _detect_debug_mode(self) -> Dict:
        """Detect if application is running in debug mode."""
        debug_info = {
            "debug_mode": False,
            "evidence": [],
            "risk_level": "low"
        }
        
        debug_indicators = {
            "error_detail": [
                r"detailed error message",
                r"debug\s*=\s*true",
                r"stack trace",
                r"line \d+ of"
            ],
            "debug_endpoints": [
                "/debug",
                "/dev",
                "/console",
                "/admin/console"
            ],
            "debug_parameters": [
                "?debug=true",
                "?test=true",
                "?dev=1"
            ]
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Check debug endpoints
                for endpoint in debug_indicators["debug_endpoints"]:
                    url = f"{self.target.url}{endpoint}"
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                content = await response.text()
                                for pattern in debug_indicators["error_detail"]:
                                    if re.search(pattern, content, re.I):
                                        debug_info["debug_mode"] = True
                                        debug_info["evidence"].append(
                                            f"Debug endpoint accessible: {endpoint}"
                                        )
                                        debug_info["risk_level"] = "high"
                    except Exception:
                        continue
                        
                # Check debug parameters
                for param in debug_indicators["debug_parameters"]:
                    url = f"{self.target.url}{param}"
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                content = await response.text()
                                if any(re.search(pattern, content, re.I) 
                                      for pattern in debug_indicators["error_detail"]):
                                    debug_info["debug_mode"] = True
                                    debug_info["evidence"].append(
                                        f"Debug mode enabled via parameter: {param}"
                                    )
                                    debug_info["risk_level"] = "high"
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Debug mode detection failed: {str(e)}")
            
        return debug_info
        
    async def _check_dev_artifacts(self) -> Dict:
        """Check for development artifacts and exposed configuration files."""
        artifacts = {
            "found": [],
            "risk_level": "low",
            "recommendations": []
        }
        
        common_artifacts = [
            ".git/config",
            ".env",
            "config.js",
            "webpack.config.js",
            "package.json",
            "composer.json",
            "Dockerfile",
            ".dockerignore",
            ".gitignore",
            "README.md",
            "phpinfo.php",
            ".htaccess",
            "web.config"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for artifact in common_artifacts:
                    url = f"{self.target.url}/{artifact}"
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                artifacts["found"].append({
                                    "file": artifact,
                                    "url": url,
                                    "size": len(await response.read())
                                })
                                artifacts["risk_level"] = "high"
                                artifacts["recommendations"].append(
                                    f"Remove or protect {artifact}"
                                )
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Development artifact check failed: {str(e)}")
            
        return artifacts
        
    async def _test_backend_behavior(self) -> Dict:
        """Test backend behavior for security issues."""
        results = {
            "issues": [],
            "behaviors": {},
            "recommendations": []
        }
        
        tests = [
            {
                "name": "HTTP method support",
                "method": "OPTIONS",
                "analyze": self._analyze_http_methods
            },
            {
                "name": "Server behavior",
                "method": "GET",
                "headers": {"X-Custom-Test": "test"},
                "analyze": self._analyze_server_behavior
            }
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for test in tests:
                    try:
                        async with session.request(
                            test["method"],
                            self.target.url,
                            headers=test.get("headers", {})
                        ) as response:
                            analysis = await test["analyze"](response)
                            results["behaviors"][test["name"]] = analysis
                            if analysis.get("issues"):
                                results["issues"].extend(analysis["issues"])
                            if analysis.get("recommendations"):
                                results["recommendations"].extend(
                                    analysis["recommendations"]
                                )
                    except Exception as e:
                        self.logger.debug(f"Backend test failed: {str(e)}")
                        
        except Exception as e:
            self.logger.error(f"Backend behavior testing failed: {str(e)}")
            
        return results
        
    async def _analyze_http_methods(self, response: aiohttp.ClientResponse) -> Dict:
        """Analyze supported HTTP methods."""
        analysis = {
            "supported_methods": [],
            "issues": [],
            "recommendations": []
        }
        
        if "Allow" in response.headers:
            methods = response.headers["Allow"].split(",")
            analysis["supported_methods"] = [m.strip() for m in methods]
            
            dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
            for method in dangerous_methods:
                if method in analysis["supported_methods"]:
                    analysis["issues"].append(
                        f"Potentially dangerous HTTP method enabled: {method}"
                    )
                    analysis["recommendations"].append(
                        f"Disable {method} method if not required"
                    )
                    
        return analysis
        
    async def _analyze_server_behavior(self, response: aiohttp.ClientResponse) -> Dict:
        """Analyze server behavior from response."""
        analysis = {
            "server_info": {},
            "issues": [],
            "recommendations": []
        }
        
        # Check server headers
        if "Server" in response.headers:
            analysis["server_info"]["server"] = response.headers["Server"]
            analysis["issues"].append("Server header reveals version information")
            analysis["recommendations"].append("Remove detailed version from Server header")
            
        # Check for other revealing headers
        revealing_headers = ["X-Powered-By", "X-AspNet-Version", "X-Runtime"]
        for header in revealing_headers:
            if header in response.headers:
                analysis["server_info"][header] = response.headers[header]
                analysis["issues"].append(f"{header} header reveals technology information")
                analysis["recommendations"].append(f"Remove {header} header")
                
        return analysis
            
    async def _analyze_cache(self) -> Dict:
        """
        Analyze caching behavior and potential cache-based vulnerabilities.
        """
        cache_results = {
            "headers": {},
            "behavior": {},
            "vulnerabilities": [],
            "cache_control": {}
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Check cache headers
                async with session.get(self.target.url) as response:
                    cache_results["headers"] = self._analyze_cache_headers(response.headers)
                    
                # Test cache behavior
                cache_results["behavior"] = await self._test_cache_behavior(session)
                
                # Check for cache poisoning
                if self.options.get('check_cache_poisoning', False):
                    cache_results["vulnerabilities"] = await self._check_cache_poisoning(session)
                    
                # Analyze CDN caching
                cdn_cache = await self._analyze_cdn_caching()
                if cdn_cache:
                    cache_results["cdn_cache"] = cdn_cache
                    
                return cache_results
                
        except Exception as e:
            self.logger.error(f"Cache analysis failed: {str(e)}")
            return {"error": str(e)}
            
    async def _run_specialized_tests(self) -> Dict:
        """
        Run additional specialized tests based on configuration.
        """
        specialized_results = {}
        
        try:
            # Debug mode detection
            if self.options.get('check_debug_mode', True):
                specialized_results["debug_mode"] = await self._detect_debug_mode()
                
            # Development artifacts
            if self.options.get('check_dev_artifacts', True):
                specialized_results["dev_artifacts"] = await self._check_dev_artifacts()
                
            # Backend technology tests
            if self.options.get('backend_tests', True):
                specialized_results["backend"] = await self._test_backend_behavior()
                
            return specialized_results
            
        except Exception as e:
            self.logger.error(f"Specialized tests failed: {str(e)}")
            return {"error": str(e)}
