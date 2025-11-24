# vulnscan/_recon/webapp.py - Web Application Analysis Module
import asyncio
import aiohttp
from typing import Dict, List, Optional
import re
from pathlib import Path
from bs4 import BeautifulSoup
from utils.logger import setup_logger
from utils.rate_limit import RateLimiter
from utils.cache import ScanCache
from reconn._target import ReconTarget


class WebApplicationAnalyzer:
    """
    Handles web application analysis including technology stack detection,
    content discovery, and JavaScript analysis.
    """
    
    def __init__(self, target: ReconTarget, options: Dict):
        self.target = target
        self.options = options
        self.logger = setup_logger("webapp_recon", scanner_specific=True)
        self.rate_limiter = RateLimiter()
        
        # Initialize cache
        if not options.get("no_cache", False):
            cache_dir = Path(options.get("cache_dir", "cache")) / "webapp"
            self._cache = ScanCache(cache_dir, default_ttl=options.get("cache_ttl", 3600))
        else:
            self._cache = None

    async def analyze(self) -> Dict:
        """
        Perform comprehensive web application analysis.
        
        Returns:
            Dict containing all web application findings
        """
        results = {}
        
        # Detect technology stack
        results['technologies'] = await self._detect_technologies()
        
        # Analyze content
        if self.options.get('content_discovery', True):
            results['content'] = await self._discover_content()
            
        # Analyze JavaScript
        if self.options.get('js_analysis', True):
            results['javascript'] = await self._analyze_javascript()
            
        return results
        
    async def _detect_technologies(self) -> Dict:
        """
        Detect technologies used in the web application.
        """
        tech_results = {
            "frameworks": [],
            "languages": [],
            "databases": [],
            "servers": [],
            "javascript_libs": [],
            "cms": None,
            "cloud_services": []
        }
        
        try:
            await self.rate_limiter.acquire()
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(self.target.url) as response:
                        await self.rate_limiter.report_success()
                        html = await response.text()
                        headers = response.headers
                        
                        # Analyze response headers
                        tech_results.update(await self._analyze_headers(headers))
                        
                        # Analyze HTML content
                        soup = BeautifulSoup(html, 'html.parser')
                        tech_results.update(await self._analyze_html(soup))
                        
                        # Analyze JavaScript
                        tech_results["javascript_libs"] = await self._detect_js_libraries(soup)
                        
                        return tech_results
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    await self.rate_limiter.report_failure() 
                    raise    
        except Exception as e:
            self.logger.error(f"Technology detection failed: {str(e)}")
            return {"error": str(e)}
            
    async def _analyze_headers(self, headers: Dict) -> Dict:
        """
        Analyze response headers to identify technologies.
        """
        tech_info = {
            "servers": [],
            "languages": [],
            "frameworks": []
        }
        
        header_signatures = {
            "Server": {
                "Apache": "servers",
                "nginx": "servers",
                "IIS": "servers",
                "LiteSpeed": "servers"
            },
            "X-Powered-By": {
                "PHP": "languages",
                "ASP.NET": "languages",
                "Express": "frameworks",
                "Django": "frameworks"
            },
            "X-AspNet-Version": {
                "ASP.NET": "frameworks"
            },
            "X-Runtime": {
                "Ruby": "languages"
            }
        }
        
        for header, value in headers.items():
            if header in header_signatures:
                value_lower = value.lower()
                for tech, category in header_signatures[header].items():
                    if tech.lower() in value_lower:
                        if tech not in tech_info[category]:
                            tech_info[category].append({
                                "name": tech,
                                "version": self._extract_version(value),
                                "confidence": "high",
                                "source": f"{header} header"
                            })
                            
        return tech_info
        
    def _extract_version(self, value: str) -> Optional[str]:
        """Extract version information from header value."""
        version_pattern = r"[\d]+(?:\.[\d]+)*(?:-[a-zA-Z0-9_]+)?"
        match = re.search(version_pattern, value)
        return match.group(0) if match else None
        
    async def _analyze_html(self, soup: BeautifulSoup) -> Dict:
        """
        Analyze HTML content to identify technologies.
        """
        tech_info = {
            "frameworks": [],
            "javascript_libs": [],
            "cms": None
        }
        
        # Check meta tags
        meta_signatures = {
            "generator": {
                "WordPress": "cms",
                "Drupal": "cms",
                "Joomla": "cms",
                "Ghost": "cms"
            }
        }
        
        for name, signatures in meta_signatures.items():
            meta = soup.find("meta", attrs={"name": name})
            if meta and "content" in meta.attrs:
                content = meta["content"].lower()
                for tech, category in signatures.items():
                    if tech.lower() in content:
                        if category == "cms":
                            tech_info["cms"] = {
                                "name": tech,
                                "version": self._extract_version(content),
                                "confidence": "high",
                                "source": "meta generator tag"
                            }
                            
        # Check CSS links for common frameworks
        css_signatures = {
            "bootstrap": "Bootstrap",
            "foundation": "Foundation",
            "materialize": "Materialize",
            "bulma": "Bulma"
        }
        
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href", "").lower()
            for sig, name in css_signatures.items():
                if sig in href:
                    tech_info["frameworks"].append({
                        "name": name,
                        "version": self._extract_version(href),
                        "confidence": "high",
                        "source": "stylesheet link"
                    })
                    
        return tech_info
        
    async def _detect_js_libraries(self, soup: BeautifulSoup) -> List[Dict]:
        """
        Detect JavaScript libraries used in the application.
        """
        libraries = []
        
        # Common JavaScript library signatures
        js_signatures = {
            "jquery": "jQuery",
            "angular": "Angular",
            "react": "React",
            "vue": "Vue.js",
            "lodash": "Lodash",
            "moment": "Moment.js",
            "axios": "Axios"
        }
        
        try:
            # Check script sources
            for script in soup.find_all("script", src=True):
                src = script["src"].lower()
                for sig, name in js_signatures.items():
                    if sig in src:
                        libraries.append({
                            "name": name,
                            "version": self._extract_version(src),
                            "confidence": "high",
                            "source": "script src"
                        })
                        
            # Check inline scripts for library declarations
            for script in soup.find_all("script"):
                if script.string:
                    content = script.string.lower()
                    for sig, name in js_signatures.items():
                        if f"require('{sig}')" in content or f'require("{sig}")' in content:
                            libraries.append({
                                "name": name,
                                "confidence": "medium",
                                "source": "inline script"
                            })
                            
        except Exception as e:
            self.logger.error(f"JavaScript library detection failed: {str(e)}")
            
        return libraries
            
    async def _discover_content(self) -> Dict:
        """
        Discover hidden content and resources.
        """
        content_results = {
            "endpoints": [],
            "directories": [],
            "files": [],
            "parameters": [],
            "apis": []
        }
        
        try:
            # Check robots.txt
            content_results["robots"] = await self._analyze_robots_txt()
            
            # Check sitemaps
            content_results["sitemaps"] = await self._analyze_sitemaps()
            
            # Directory enumeration
            if self.options.get('dir_enum', False):
                content_results["directories"] = await self._enumerate_directories()
                
            # API endpoint discovery
            content_results["apis"] = await self._discover_api_endpoints()
            
            return content_results
            
        except Exception as e:
            self.logger.error(f"Content discovery failed: {str(e)}")
            return {"error": str(e)}
            
    async def _analyze_robots_txt(self) -> Dict:
        """
        Analyze robots.txt file for hidden content.
        """
        results = {
            "found": False,
            "entries": [],
            "sitemaps": [],
            "interesting_paths": []
        }
        
        try:
            await self.rate_limiter.acquire()
            async with aiohttp.ClientSession() as session:
                robots_url = f"{self.target.url}/robots.txt"
                try:
                    async with session.get(robots_url) as response:
                        await self.rate_limiter.report_success()
                        if response.status == 200:
                            results["found"] = True
                            content = await response.text()
                            
                            # Parse robots.txt content
                            for line in content.splitlines():
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    if line.lower().startswith('disallow:'):
                                        path = line.split(':', 1)[1].strip()
                                        results["entries"].append({
                                            "type": "disallow",
                                            "path": path
                                        })
                                        if any(k in path.lower() for k in ['admin', 'backup', 'config', 'test']):
                                            results["interesting_paths"].append(path)
                                    elif line.lower().startswith('allow:'):
                                        path = line.split(':', 1)[1].strip()
                                        results["entries"].append({
                                            "type": "allow",
                                            "path": path
                                        })
                                    elif line.lower().startswith('sitemap:'):
                                        sitemap = line.split(':', 1)[1].strip()
                                        results["sitemaps"].append(sitemap)
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    await self.rate_limiter.report_failure()
                    self.logger.error(f"Error during robots.txt analysis {str(e)}")                    
        except Exception as e:
            self.logger.error(f"Robots.txt analysis failed: {str(e)}")
            
        return results
        
    async def _analyze_sitemaps(self) -> Dict:
        """
        Analyze sitemap files for content discovery.
        """
        results = {
            "found": False,
            "urls": [],
            "errors": []
        }
        
        sitemap_locations = [
            "/sitemap.xml",
            "/sitemap_index.xml",
            "/sitemap/",
            "/sitemap/sitemap.xml"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for location in sitemap_locations:
                    try:
                        url = f"{self.target.url}{location}"
                        await self.rate_limiter.acquire()
                        async with session.get(url) as response:
                            await self.rate_limiter.report_success()
                            if response.status == 200:
                                results["found"] = True
                                content = await response.text()
                                
                                # Parse XML content
                                soup = BeautifulSoup(content, 'xml')
                                
                                # Look for URLs in both sitemap index and regular sitemaps
                                urls = soup.find_all(['loc', 'url'])
                                for url in urls:
                                    if url.string:
                                        results["urls"].append({
                                            "url": url.string.strip(),
                                            "source": location
                                        })
                                        
                    except Exception as e:
                        await self.rate_limiter.report_failure()
                        results["errors"].append(f"Error analyzing {location}: {str(e)}")
                        
        except Exception as e:
            self.logger.error(f"Sitemap analysis failed: {str(e)}")
            
        return results
        
    async def _enumerate_directories(self) -> List[Dict]:
        """
        Enumerate directories using common wordlists.
        """
        discovered = []
        common_dirs = [
            "admin", "api", "app", "backup", "conf",
            "css", "data", "docs", "images", "includes",
            "js", "log", "media", "test", "tmp", "upload"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                tasks = []
                for directory in common_dirs:
                    url = f"{self.target.url}/{directory}/"
                    tasks.append(self._check_directory(session, url, directory))
                    
                results = await asyncio.gather(*tasks)
                discovered.extend([r for r in results if r])
                
        except Exception as e:
            self.logger.error(f"Directory enumeration failed: {str(e)}")
            
        return discovered
        
    async def _check_directory(self, 
                             session: aiohttp.ClientSession,
                             url: str,
                             directory: str) -> Optional[Dict]:
        """Check if a directory exists and analyze its response."""
        try:
            await self.rate_limiter.acquire()
            async with session.get(url) as response:
                await self.rate_limiter.report_success()
                if response.status != 404:
                    return {
                        "path": f"/{directory}/",
                        "status": response.status,
                        "size": len(await response.read()),
                        "content_type": response.headers.get("content-type", ""),
                        "interesting": self._is_interesting_response(response)
                    }
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                await self.rate_limiter.report_failure()  
                return None
            
    def _is_interesting_response(self, response: aiohttp.ClientResponse) -> bool:
        """Determine if a response is interesting based on various factors."""
        if response.status == 200:
            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type:
                return True
        return False
        
    async def _discover_api_endpoints(self) -> List[Dict]:
        """
        Discover API endpoints through various techniques.
        """
        endpoints = []
        
        # Common API paths to check
        api_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/docs",
            "/swagger",
            "/swagger.json",
            "/openapi.json",
            "/graphql",
            "/graphiql"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                tasks = []
                for path in api_paths:
                    url = f"{self.target.url}{path}"
                    tasks.append(self._check_api_endpoint(session, url, path))
                    
                results = await asyncio.gather(*tasks)
                endpoints.extend([r for r in results if r])
                
                # Also check for API documentation
                swagger_info = await self._check_swagger_docs(session)
                if swagger_info:
                    endpoints.extend(swagger_info)
                    
        except Exception as e:
            self.logger.error(f"API endpoint discovery failed: {str(e)}")
            
        return endpoints
        
    async def _check_api_endpoint(self,
                                session: aiohttp.ClientSession,
                                url: str,
                                path: str) -> Optional[Dict]:
        """Check if an API endpoint exists and analyze its response."""
        try:
            await self.rate_limiter.acquire()
            async with session.get(url) as response:
                await self.rate_limiter.report_success()
                if response.status != 404:
                    content_type = response.headers.get("content-type", "")
                    return {
                        "path": path,
                        "url": url,
                        "status": response.status,
                        "content_type": content_type,
                        "is_api": "json" in content_type.lower() or
                                "api" in path.lower()
                    }
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                await self.rate_limiter.report_failure() 
                return None
            
    async def _check_swagger_docs(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Check for Swagger/OpenAPI documentation."""
        docs = []
        swagger_paths = [
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/api-docs",
            "/api-docs.json",
            "/openapi.json",
            "/openapi/v3/api-docs"
        ]
        
        for path in swagger_paths:
            try:
                url = f"{self.target.url}{path}"
                await self.rate_limiter.acquire()
                async with session.get(url) as response:
                    await self.rate_limiter.report_success()
                    if response.status == 200:
                        content_type = response.headers.get("content-type", "")
                        if "json" in content_type.lower():
                            try:
                                data = await response.json()
                                if any(k in data for k in ["swagger", "openapi", "paths"]):
                                    docs.append({
                                        "type": "api_documentation",
                                        "format": "swagger/openapi",
                                        "url": url,
                                        "version": data.get("swagger") or 
                                                 data.get("openapi"),
                                        "endpoints": len(data.get("paths", {}))
                                    })
                            except Exception:
                                continue
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                await self.rate_limiter.report_failure()  
                continue
                
        return docs
            
    async def _analyze_javascript(self) -> Dict:
        """
        Analyze JavaScript files for endpoints, secrets, and vulnerabilities.
        """
        js_results = {
            "files": [],
            "endpoints": [],
            "possible_secrets": [],
            "vulnerabilities": [],
            "websocket_endpoints": []
        }
        
        try:
            # Get all JavaScript files
            js_files = await self._get_javascript_files()
            
            for js_file in js_files:
                # Analyze each file
                analysis = await self._analyze_js_file(js_file)
                js_results["files"].append(analysis)
                
                # Update collected data
                js_results["endpoints"].extend(analysis.get("endpoints", []))
                js_results["possible_secrets"].extend(analysis.get("secrets", []))
                js_results["vulnerabilities"].extend(analysis.get("vulnerabilities", []))
                js_results["websocket_endpoints"].extend(analysis.get("websockets", []))
                
            return js_results
            
        except Exception as e:
            self.logger.error(f"JavaScript analysis failed: {str(e)}")
            return {"error": str(e)}
            
    async def _get_javascript_files(self) -> List[Dict]:
        """
        Get all JavaScript files referenced in the application.
        """
        js_files = []
        
        try:
            await self.rate_limiter.acquire()
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(self.target.url) as response:
                        await self.rate_limiter.report_success()
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Find all script tags with src attribute
                        scripts = soup.find_all("script", src=True)
                        
                        for script in scripts:
                            src = script["src"]
                            
                            # Handle relative URLs
                            if not src.startswith(("http://", "https://")):
                                if src.startswith("//"):
                                    src = f"https:{src}"
                                elif src.startswith("/"):
                                    src = f"{self.target.url}{src}"
                                else:
                                    src = f"{self.target.url}/{src}"
                                    
                            try:
                                # Stream analysis instead of loading full content
                                analysis = await self._analyze_js_file(session, src)
                                if analysis:
                                    js_files.append(analysis)
                            except Exception as e:
                                self.logger.debug(f"Failed to analyze {src}: {str(e)}")
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    await self.rate_limiter.report_failure() 
                    self.logger.error(f"Error during js file discovery {str(e)}")   

        except Exception as e:
            self.logger.error(f"JavaScript file discovery failed: {str(e)}")
            
        return js_files
    
    async def _analyze_js_file(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """
        Analyze a JavaScript file by streaming chunks.
        Never loads the entire file into memory.
        """
        analysis = {
            "url": url,
            "size": 0,
            "endpoints": [],
            "secrets": [],
            "vulnerabilities": [],
            "websockets": []
        }
        
        try:
            await self.rate_limiter.acquire()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status != 200:
                    await self.rate_limiter.report_failure()
                    return None
                
                await self.rate_limiter.report_success()
                # Track file size
                content_length = response.headers.get('Content-Length')
                if content_length:
                    analysis["size"] = int(content_length)
                    
                    # Skip very large files
                    if analysis["size"] > 5 * 1024 * 1024:  # 5MB limit
                        self.logger.warning(f"Skipping large file: {url} ({analysis['size']} bytes)")
                        return None
                
                # Process in chunks
                chunk_buffer = ""
                chunk_size = 8192
                
                async for chunk in response.content.iter_chunked(chunk_size):
                    try:
                        chunk_text = chunk.decode('utf-8', errors='ignore')
                        chunk_buffer += chunk_text
                        
                        # Keep a sliding window to catch patterns across chunks
                        if len(chunk_buffer) > chunk_size * 2:
                            # Analyze current buffer
                            await self._analyze_js_chunk(chunk_buffer, analysis)
                            # Keep last 1KB for overlap
                            chunk_buffer = chunk_buffer[-1024:]
                            
                    except UnicodeDecodeError:
                        continue
                
                # Analyze remaining buffer
                if chunk_buffer:
                    await self._analyze_js_chunk(chunk_buffer, analysis)
                
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout analyzing {url}")
            return None
        except Exception as e:
            self.logger.debug(f"Error analyzing {url}: {str(e)}")
            return None
        
        return analysis    
    
    async def _analyze_js_chunk(self, chunk: str, analysis: Dict) -> Dict:
        """
        Analyze a JavaScript file for interesting content in chunks.
        """
       
        try:
            # Find API endpoints
            await self._find_endpoints(chunk, analysis)
            
            # Look for potential secrets
            await self._find_secrets(chunk, analysis)
            
            # Check for common vulnerabilities
            await self._check_js_vulnerabilities(chunk, analysis)
            
            # Find WebSocket endpoints
            await self._find_websockets(chunk, analysis)
            
        except Exception as e:
            self.logger.error(f"JavaScript file analysis failed: {str(e)}")
            
        return analysis
        
    async def _find_endpoints(self, content: str, analysis: Dict):
        """Find API endpoints in JavaScript code."""
        # Patterns for identifying endpoints
        endpoint_patterns = [
            r'(?:"|\')/api/[^"\']+(?:"|\')',  # API endpoints
            r'(?:"|\')https?://[^"\']+(?:"|\')',  # Full URLs
            r'fetch\([^)]+\)',  # fetch calls
            r'axios\.[a-z]+\([^)]+\)',  # axios calls
            r'\$\.(?:get|post|put|delete)\([^)]+\)'  # jQuery AJAX calls
        ]
        
        for pattern in endpoint_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group(0).strip('\'"')
                if endpoint not in [e["url"] for e in analysis["endpoints"]]:
                    analysis["endpoints"].append({
                        "url": endpoint,
                        "type": "api",
                        "method": self._guess_http_method(match.group(0))
                    })
                    
    def _guess_http_method(self, code_snippet: str) -> str:
        """Guess HTTP method from code snippet."""
        if "post" in code_snippet.lower():
            return "POST"
        elif "put" in code_snippet.lower():
            return "PUT"
        elif "delete" in code_snippet.lower():
            return "DELETE"
        else:
            return "GET"
            
    async def _find_secrets(self, content: str, analysis: Dict):
        """Find potential secrets in JavaScript code."""
        secret_patterns = {
            "api_key": r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            "secret": r'(?i)secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            "password": r'(?i)password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            "token": r'(?i)token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            "aws_key": r'(?i)aws[_-]?(?:access[_-]?)?key["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        }
        
        for secret_type, pattern in secret_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                secret_value = match.group(1)
                if self._looks_like_secret(secret_value):
                    analysis["secrets"].append({
                        "type": secret_type,
                        "value": self._mask_secret(secret_value),
                        "line": content.count('\n', 0, match.start()) + 1
                    })
                    
    def _looks_like_secret(self, value: str) -> bool:
        """Check if a value looks like a secret."""
        # Ignore obviously non-secret values
        non_secrets = ['null', 'undefined', '', '0', 'false', 'true']
        if value.lower() in non_secrets:
            return False
            
        # Check for minimum entropy and length
        if len(value) < 8:
            return False
            
        # Check for variety in characters
        char_types = set()
        for char in value:
            if char.isupper():
                char_types.add('upper')
            elif char.islower():
                char_types.add('lower')
            elif char.isdigit():
                char_types.add('digit')
            else:
                char_types.add('special')
                
        return len(char_types) >= 2
        
    def _mask_secret(self, secret: str) -> str:
        """Mask a secret value for safe logging."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
        
    async def _check_js_vulnerabilities(self, content: str, analysis: Dict):
        """Check for common JavaScript vulnerabilities."""
        vulnerability_patterns = {
            "eval_usage": {
                "pattern": r'\beval\s*\(',
                "risk": "high",
                "description": "Use of eval() can lead to code injection"
            },
            "innerHTML": {
                "pattern": r'\.innerHTML\s*=',
                "risk": "medium",
                "description": "Direct innerHTML assignment can lead to XSS"
            },
            "document_write": {
                "pattern": r'document\.write\s*\(',
                "risk": "medium",
                "description": "Use of document.write is dangerous"
            },
            "sql_string": {
                "pattern": r'SELECT\s+\w+\s+FROM',
                "risk": "high",
                "description": "SQL query string found in JavaScript"
            }
        }
        
        for vuln_type, info in vulnerability_patterns.items():
            matches = re.finditer(info["pattern"], content)
            for match in matches:
                analysis["vulnerabilities"].append({
                    "type": vuln_type,
                    "risk": info["risk"],
                    "description": info["description"],
                    "line": content.count('\n', 0, match.start()) + 1,
                    "evidence": content[match.start():match.end()]
                })
                
    async def _find_websockets(self, content: str, analysis: Dict):
        """Find WebSocket endpoints in JavaScript code."""
        websocket_patterns = [
            r'(?:"|\')?wss?://[^"\']+(?:"|\')?',  # WebSocket URLs
            r'new\s+WebSocket\s*\([^)]+\)',  # WebSocket initialization
            r'WebSocket\.connect\s*\([^)]+\)'  # Alternative initialization
        ]
        
        for pattern in websocket_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                ws_url = match.group(0).strip('\'"()')
                if "WebSocket" in ws_url:
                    # Extract URL from WebSocket initialization
                    url_match = re.search(r'(?:"|\')([^"\']+)(?:"|\')', ws_url)
                    if url_match:
                        ws_url = url_match.group(1)
                        
                if ws_url not in [w["url"] for w in analysis["websockets"]]:
                    analysis["websockets"].append({
                        "url": ws_url,
                        "type": "websocket",
                        "protocol": "wss" if ws_url.startswith("wss") else "ws"
                    })

