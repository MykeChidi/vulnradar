# vulnscan/detector.py - Technology Detection module

import re
from typing import Dict

import aiohttp
from bs4 import BeautifulSoup


class TechDetector:
    """Detector for web technologies, frameworks, and servers."""
    
    def __init__(self):
        """Initialize the technology detector."""
        # Technology signatures
        self.signatures = {
            # Web servers
            "Apache": [
                "Server: Apache",
                "Apache/[0-9\.]+"
            ],
            "Nginx": [
                "Server: nginx",
                "nginx/[0-9\.]+"
            ],
            "IIS": [
                "Server: Microsoft-IIS",
                "X-Powered-By: ASP.NET"
            ],
            
            # Frameworks
            "WordPress": [
                "/wp-content/",
                "/wp-includes/",
                "<meta name=\"generator\" content=\"WordPress"
            ],
            "Drupal": [
                "Drupal.settings",
                "/sites/default/files/",
                "jQuery.extend\\(Drupal.settings"
            ],
            "Joomla": [
                "/media/jui/",
                "/media/system/js/",
                "Joomla!"
            ],
            "Laravel": [
                "laravel_session",
                "XSRF-TOKEN"
            ],
            "Django": [
                "csrfmiddlewaretoken",
                "__django",
                "django"
            ],
            "Flask": [
                "Werkzeug",
                "Flask"
            ],
            "React": [
                "react-root",
                "react.development.js",
                "react.production.min.js"
            ],
            "Vue": [
                "vue.js",
                "vue.min.js",
                "__vue__"
            ],
            "Angular": [
                "ng-app",
                "ng-controller",
                "angular.js",
                "angular.min.js"
            ],
            
            # Databases
            "MySQL": [
                "MySQL",
                "mysql_error"
            ],
            "PostgreSQL": [
                "PostgreSQL",
                "pg_database"
            ],
            "MongoDB": [
                "MongoDB",
                "mongo_err"
            ],
            
            # Programming Languages
            "PHP": [
                "X-Powered-By: PHP",
                ".php",
                "PHPSESSID"
            ],
            "ASP.NET": [
                ".aspx",
                "ASP.NET",
                "__VIEWSTATE"
            ],
            "Java": [
                "JavaServer Pages",
                "Servlet",
                "JSESSIONID"
            ],
            "Python": [
                "Python",
                "wsgi",
                "__pycache__"
            ],
            "Ruby": [
                "Ruby",
                "Rails",
                "_rails_session"
            ],
            
            # JavaScript Libraries
            "jQuery": [
                "jquery.js",
                "jquery.min.js",
                "jQuery v[0-9]"
            ],
            "Bootstrap": [
                "bootstrap.css",
                "bootstrap.min.css",
                "bootstrap.js",
                "bootstrap.min.js"
            ]
        }
        
    async def detect(self, url: str, headers: Dict = None) -> Dict:
        """
        Detect technologies used by a website.
        
        Args:
            url: URL to scan
            headers: HTTP headers to use
            
        Returns:
            Dict: Dictionary of detected technologies with confidence scores
        """
        headers = headers or {}
        detected_techs = {}
        
        try:
            # Fetch the page
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url) as response:
                    # Check headers
                    resp_headers = dict(response.headers)
                    html_content = await response.text()
                    
                    # Check for technologies in headers
                    for tech, patterns in self.signatures.items():
                        confidence = 0
                        
                        # Check in headers
                        for header, value in resp_headers.items():
                            for pattern in patterns:
                                if re.search(pattern, f"{header}: {value}", re.IGNORECASE):
                                    confidence += 30  # Higher confidence for header matches
                        
                        # Check in HTML content
                        for pattern in patterns:
                            if re.search(pattern, html_content, re.IGNORECASE):
                                confidence += 10  # Lower confidence for content matches
                                
                        # Add technology if confidence is above threshold
                        if confidence > 0:
                            detected_techs[tech] = min(confidence, 100)  # Cap at 100
            
            # Check for specific elements in HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Meta generator tag
            meta_generator = soup.find("meta", {"name": "generator"})
            if meta_generator and meta_generator.get("content"):
                generator = meta_generator["content"].lower()
                if "wordpress" in generator:
                    detected_techs["WordPress"] = min(detected_techs.get("WordPress", 0) + 50, 100)
                elif "drupal" in generator:
                    detected_techs["Drupal"] = min(detected_techs.get("Drupal", 0) + 50, 100)
                elif "joomla" in generator:
                    detected_techs["Joomla"] = min(detected_techs.get("Joomla", 0) + 50, 100)
            
            # Script sources
            for script in soup.find_all("script", src=True):
                src = script["src"].lower()
                if "jquery" in src:
                    detected_techs["jQuery"] = min(detected_techs.get("jQuery", 0) + 40, 100)
                elif "bootstrap" in src:
                    detected_techs["Bootstrap"] = min(detected_techs.get("Bootstrap", 0) + 40, 100)
                elif "react" in src:
                    detected_techs["React"] = min(detected_techs.get("React", 0) + 40, 100)
                elif "vue" in src:
                    detected_techs["Vue"] = min(detected_techs.get("Vue", 0) + 40, 100)
                elif "angular" in src:
                    detected_techs["Angular"] = min(detected_techs.get("Angular", 0) + 40, 100)
            
            # CSS links
            for css in soup.find_all("link", rel="stylesheet", href=True):
                href = css["href"].lower()
                if "bootstrap" in href:
                    detected_techs["Bootstrap"] = min(detected_techs.get("Bootstrap", 0) + 30, 100)
                    
            return detected_techs
                    
        except Exception as e:
            print(f"Error detecting technologies: {e}")
            return {}