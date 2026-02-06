# tests/unit/test_detector.py - Tech Detector test suite

from vulnradar.detector import TechDetector
import pytest


@pytest.mark.unit
class TestTechDetector:
    """Unit tests for TechDetector class."""
    
    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        detector = TechDetector(timeout=15)
        
        assert detector.timeout.total == 15
        assert len(detector.signatures) > 0
        assert len(detector._compiled_patterns) > 0
    
    def test_detect_from_headers(self):
        """Test technology detection from headers."""
        detector = TechDetector()
        
        headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.0"
        }
        
        detected = detector._detect_from_headers(headers)
        
        assert "Nginx" in detected
        assert "PHP" in detected
        assert detected["Nginx"] > 0
        assert detected["PHP"] > 0
    
    def test_detect_from_content(self, sample_html):
        """Test technology detection from HTML content."""
        detector = TechDetector()
        
        detected = detector._detect_from_content(sample_html)
        
        assert "WordPress" in detected
        assert detected["WordPress"] > 0
        assert "Bootstrap" in detected
    
    def test_detect_from_structure(self, sample_html):
        """Test technology detection from HTML structure."""
        from bs4 import BeautifulSoup
        detector = TechDetector()
        
        soup = BeautifulSoup(sample_html, 'html.parser')
        detected = detector._detect_from_structure(soup)
        
        assert "WordPress" in detected
        assert "jQuery" in detected
        assert "Bootstrap" in detected
    
    def test_merge_detections(self):
        """Test detection merging."""
        detector = TechDetector()
        
        target = {"Apache": 50, "PHP": 30}
        source = {"Apache": 70, "MySQL": 40}
        
        detector._merge_detections(target, source)
        
        assert target["Apache"] == 70  # Higher confidence
        assert target["PHP"] == 30  # Unchanged
        assert target["MySQL"] == 40  # New entry
