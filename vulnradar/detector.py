# vulnradar/detector.py - Technology Detection module

import asyncio
import re
from typing import Dict, Optional
from dataclasses import dataclass

import aiohttp
from bs4 import BeautifulSoup
from .utils.error_handler import (get_global_error_handler,
    ParseError, NetworkError, ScanTimeoutError, ScanError)

# Setup error handler
error_handler = get_global_error_handler()


@dataclass
class DetectionResult:
    """Result of technology detection."""
    technologies: Dict[str, int]
    errors: list[str]
    url: str
    response_time: float = 0.0


class TechDetector:
    """Detector for web technologies, frameworks, and servers."""
    
    def __init__(self, timeout: int = 10, max_content_size: int = 5_000_000):
        """
        Initialize the technology detector.
        
        Args:
            timeout: Request timeout in seconds
            max_content_size: Maximum response size to process (bytes)
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_content_size = max_content_size
        self._compiled_patterns = {}
        
        # Technology signatures with compiled regex patterns
        self.signatures = {
            # Web servers
            "Apache": [
                r"Server:\s*Apache",
                r"Apache/[\d\.]+"
            ],
            "Nginx": [
                r"Server:\s*nginx",
                r"nginx/[\d\.]+"
            ],
            "IIS": [
                r"Server:\s*Microsoft-IIS",
                r"X-Powered-By:\s*ASP\.NET"
            ],
            
            # Frameworks
            "WordPress": [
                r"/wp-content/",
                r"/wp-includes/",
                r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress'
            ],
            "Drupal": [
                r"Drupal\.settings",
                r"/sites/default/files/",
                r"jQuery\.extend\(Drupal\.settings"
            ],
            "Joomla": [
                r"/media/jui/",
                r"/media/system/js/",
                r"Joomla!"
            ],
            "Laravel": [
                r"laravel_session",
                r"XSRF-TOKEN"
            ],
            "Django": [
                r"csrfmiddlewaretoken",
                r"__django",
                r"\bdjango\b"
            ],
            "Flask": [
                r"\bWerkzeug\b",
                r"\bFlask\b"
            ],
            "React": [
                r"react-root",
                r"react\.development\.js",
                r"react\.production\.min\.js",
                r"data-reactroot"
            ],
            "Vue": [
                r"vue\.js",
                r"vue\.min\.js",
                r"__vue__",
                r"data-v-[\da-f]+"
            ],
            "Angular": [
                r"ng-app",
                r"ng-controller",
                r"angular\.js",
                r"angular\.min\.js"
            ],
            
            # Databases (from error messages)
            "MySQL": [
                r"\bMySQL\b",
                r"mysql_error"
            ],
            "PostgreSQL": [
                r"\bPostgreSQL\b",
                r"pg_database"
            ],
            "MongoDB": [
                r"\bMongoDB\b",
                r"mongo_err"
            ],
            
            # Programming Languages
            "PHP": [
                r"X-Powered-By:\s*PHP",
                r"\.php\b",
                r"PHPSESSID"
            ],
            "ASP.NET": [
                r"\.aspx\b",
                r"\bASP\.NET\b",
                r"__VIEWSTATE"
            ],
            "Java": [
                r"JavaServer Pages",
                r"\bServlet\b",
                r"JSESSIONID"
            ],
            "Python": [
                r"\bPython/[\d\.]+",
                r"\bwsgi\b",
                r"__pycache__"
            ],
            "Ruby": [
                r"\bRuby\b",
                r"\bRails\b",
                r"_rails_session"
            ],
            
            # JavaScript Libraries
            "jQuery": [
                r"jquery\.js",
                r"jquery\.min\.js",
                r"jQuery\s+v[\d\.]+"
            ],
            "Bootstrap": [
                r"bootstrap\.css",
                r"bootstrap\.min\.css",
                r"bootstrap\.js",
                r"bootstrap\.min\.js"
            ],
            
            # CDNs & Services
            "Cloudflare": [
                r"__cfduid",
                r"cf-ray",
                r"cloudflare"
            ],
            "Google Analytics": [
                r"google-analytics\.com/analytics\.js",
                r"gtag/js",
                r"_ga\b"
            ]
        }
        
        # Compile all patterns
        self._compile_patterns()
        
    def _compile_patterns(self):
        """Pre-compile all regex patterns for better performance."""
        for tech, patterns in self.signatures.items():
            self._compiled_patterns[tech] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
    
    async def detect(
        self, 
        url: str, 
        headers: Optional[Dict] = None,
        session: Optional[aiohttp.ClientSession] = None
    ) -> DetectionResult:
        """
        Detect technologies used by a website.
        
        Args:
            url: URL to scan
            headers: HTTP headers to use
            session: Existing aiohttp session (optional, creates new if not provided)
            
        Returns:
            DetectionResult: Object containing detected technologies and metadata
        """
        headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        detected_techs = {}
        errors = []
        response_time = 0.0
        
        # Determine if we should close the session
        close_session = session is None
        if session is None:
            session = aiohttp.ClientSession(timeout=self.timeout)
        
        try:
            import time
            start_time = time.time()
            
            async with session.get(url, headers=headers, allow_redirects=True) as response:
                response_time = time.time() - start_time
                
                # Check content length
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > self.max_content_size:
                    errors.append(f"Response too large: {content_length} bytes")
                    return DetectionResult(detected_techs, errors, url, response_time)
                
                # Get response data
                resp_headers = dict(response.headers)
                
                # Read content with size limit
                html_content = await response.text()
                if len(html_content) > self.max_content_size:
                    html_content = html_content[:self.max_content_size]
                    errors.append("Content truncated due to size")
                
                # Detect from headers
                detected_techs = self._detect_from_headers(resp_headers)
                
                # Detect from HTML content
                content_detections = self._detect_from_content(html_content)
                self._merge_detections(detected_techs, content_detections)
                
                # Parse HTML for structured detection
                try:
                    try:
                        soup = BeautifulSoup(html_content, 'lxml')
                    except:
                        soup = BeautifulSoup(html_content, 'html.parser')
                    structured_detections = self._detect_from_structure(soup)
                    self._merge_detections(detected_techs, structured_detections)
                except Exception as e:
                    error_handler.handle_error(
                        ParseError(f"HTML parsing error: {str(e)}", original_error=e),
                        context={"url": url}
                    )
                    errors.append(f"HTML parsing error: {str(e)}")
        
        except aiohttp.ClientError as e:
            error_handler.handle_error(
                NetworkError(f"Connection error: {str(e)}", original_error=e),
                context={"url": url}
            )
            errors.append(f"Connection error: {str(e)}")
        except asyncio.TimeoutError as e:
            error_handler.handle_error(
                ScanTimeoutError(f"Request timeout after {self.timeout.total}s", original_error=e),
                context={"url": url, "timeout": self.timeout.total}
            )
            errors.append(f"Request timeout after {self.timeout.total}s")
        except Exception as e:
            error_handler.handle_error(
                ScanError(f"Unexpected error: {type(e).__name__}: {str(e)}", original_error=e),
                context={"url": url}
            )
            errors.append(f"Unexpected error: {type(e).__name__}: {str(e)}")
        finally:
            if close_session:
                await session.close()
        
        return DetectionResult(detected_techs, errors, url, response_time)
    
    def _detect_from_headers(self, headers: Dict[str, str]) -> Dict[str, int]:
        """Detect technologies from HTTP headers."""
        detected = {}
        header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        
        for tech, patterns in self._compiled_patterns.items():
            confidence = 0
            for pattern in patterns:
                if pattern.search(header_text):
                    confidence += 30  # Higher confidence for header matches
            
            if confidence > 0:
                detected[tech] = min(confidence, 100)
        
        return detected
    
    def _detect_from_content(self, content: str) -> Dict[str, int]:
        """Detect technologies from page content."""
        detected = {}
        
        for tech, patterns in self._compiled_patterns.items():
            confidence = 0
            matches = 0
            
            for pattern in patterns:
                if pattern.search(content):
                    matches += 1
                    confidence += 10  # Lower confidence for content matches
            
            if confidence > 0:
                # Bonus for multiple pattern matches
                if matches > 2:
                    confidence += 20
                detected[tech] = min(confidence, 100)
        
        return detected
    
    def _detect_from_structure(self, soup: BeautifulSoup) -> Dict[str, int]:
        """Detect technologies from HTML structure."""
        detected = {}
        
        # Meta generator tag
        meta_generator = soup.find("meta", {"name": "generator"})
        if meta_generator and meta_generator.get("content"):
            generator = meta_generator["content"].lower()
            tech_map = {
                "wordpress": "WordPress",
                "drupal": "Drupal",
                "joomla": "Joomla"
            }
            for key, tech in tech_map.items():
                if key in generator:
                    detected[tech] = 80  # High confidence for generator tag
        
        # Script sources
        for script in soup.find_all("script", src=True):
            src = script["src"].lower()
            tech_indicators = {
                "jquery": "jQuery",
                "bootstrap": "Bootstrap",
                "react": "React",
                "vue": "Vue",
                "angular": "Angular"
            }
            for indicator, tech in tech_indicators.items():
                if indicator in src:
                    detected[tech] = max(detected.get(tech, 0), 70)
        
        # CSS links
        for css in soup.find_all("link", rel="stylesheet", href=True):
            href = css["href"].lower()
            if "bootstrap" in href:
                detected["Bootstrap"] = max(detected.get("Bootstrap", 0), 60)
        
        # Framework-specific attributes
        if soup.find(attrs={"data-reactroot": True}) or soup.find(attrs={"data-react-root": True}):
            detected["React"] = max(detected.get("React", 0), 80)
        
        if soup.find(attrs=lambda x: x and any(k.startswith('data-v-') for k in x.keys() if isinstance(x, dict))):
            detected["Vue"] = max(detected.get("Vue", 0), 80)
        
        if soup.find(attrs={"ng-app": True}):
            detected["Angular"] = max(detected.get("Angular", 0), 80)
        
        return detected
    
    def _merge_detections(self, target: Dict[str, int], source: Dict[str, int]):
        """Merge detection results, keeping highest confidence scores."""
        for tech, confidence in source.items():
            target[tech] = max(target.get(tech, 0), confidence)
    