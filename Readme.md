# VulnScan - A Web Vulnerability Scanner

A comprehensive, asynchronous web vulnerability scanner designed to identify common security flaws in web applications. VulnScan performs automated reconnaissance, crawling, technology detection, and vulnerability testing with detailed reporting capabilities.

## Features

### 🔍 Reconnaissance
- DNS lookup (A, MX, NS, TXT records)
- Port scanning (top 1000 ports)
- Web Application Firewall (WAF) detection
- Technology stack identification

### 🕷️ Web Crawling
- Intelligent web crawling with configurable depth
- JavaScript rendering support via Selenium
- Endpoint discovery and mapping
- Progress tracking with visual indicators

### 🛡️ Vulnerability Detection
- **SQL Injection** - Detects database injection vulnerabilities
- **Cross-Site Scripting (XSS)** - Identifies reflected, stored, and DOM-based XSS
- **Cross-Site Request Forgery (CSRF)** - Checks for CSRF protection mechanisms
- **Server-Side Request Forgery (SSRF)** - Tests for SSRF vulnerabilities
- **Path Traversal** - Directory traversal and file access vulnerabilities
- **File Inclusion** - Local and remote file inclusion vulnerabilities
- **Command Injection** - OS command injection testing

### 📊 Reporting
- **HTML Reports** - Interactive web-based reports
- **PDF Reports** - Professional documentation format
- **JSON Reports** - Machine-readable format for integration
- **Excel Reports** - Spreadsheet format for analysis
- **SQLite Database** - Persistent storage for scan results

### ⚡ Performance
- Asynchronous scanning for improved performance
- Configurable concurrency limits
- Request timeout management
- Progress tracking and logging

## Installation

### Prerequisites
- Python 3.10+
- pip package manager

### Required Dependencies
Install the required Python packages:

```bash
pip install aiohttp colorama dnspython python-nmap tqdm wafw00f selenium beautifulsoup4 requests reportlab sqlalchemy pandas jinja2
```

### Optional Dependencies
For JavaScript rendering support:
```bash
# Install ChromeDriver for Selenium
# Ubuntu/Debian:
sudo apt-get install chromium-chromedriver

# macOS:
brew install chromedriver

# Windows:
# Download from https://chromedriver.chromium.org/
```

### Command Line Arguments

#### Target Options
- `url` - Target URL to scan (required)
- `--cookies` - Cookies to include with HTTP requests
- `--user-agent` - Custom User-Agent string (default: VulnScan/1.0)

#### Scan Configuration
- `--crawl-depth` - Maximum crawl depth (default: 3)
- `--timeout` - Request timeout in seconds (default: 10)
- `--max-workers` - Maximum concurrent workers (default: 5)
- `--use-selenium` - Enable JavaScript rendering with Selenium
- `--port-scan` - Perform port scanning during reconnaissance

#### Vulnerability Scanning Toggles
- `--no-sqli` - Skip SQL injection scanning
- `--no-xss` - Skip XSS scanning
- `--no-csrf` - Skip CSRF scanning
- `--no-ssrf` - Skip SSRF scanning
- `--no-path-traversal` - Skip path traversal scanning
- `--no-file-inclusion` - Skip file inclusion scanning
- `--no-command-injection` - Skip command injection scanning

#### Output Options
- `--output-dir` - Output directory for reports (default: scan_results)
- `--no-html` - Skip HTML report generation
- `--no-pdf` - Skip PDF report generation
- `--no-json` - Skip JSON report generation
- `--excel` - Generate Excel report

#### Database Options
- `--use-db` - Store results in SQLite database
- `--db-path` - Path to SQLite database (default: vulnscan.db)

## Usage

### Basic Usage
```bash
python vulnscan.py https://example.com
```

### Advanced Options
```bash
python vulnscan.py https://example.com \
    --crawl-depth 5 \
    --timeout 15 \
    --max-workers 10 \
    --port-scan \
    --use-selenium \
    --cookies "session=abc123; auth=token456" \
    --output-dir ./my_scan_results
```
### Authenticated Scanning
```bash
python vulnscan.py https://app.example.com \
    --cookies "PHPSESSID=abc123; user_token=xyz789" \
    --crawl-depth 3 \
    --output-dir ./authenticated_scan
```

### Targeted Vulnerability Scanning
```bash
python vulnscan.py https://example.com \
    --no-csrf \
    --no-ssrf \
    --no-path-traversal \
    --timeout 30
```

## Output Structure

VulnScan generates comprehensive reports in the specified output directory:

```
scan_results/
├── vulnerability_report.html    # Interactive HTML report
├── vulnerability_report.pdf     # PDF documentation
├── vulnerability_report.json    # Machine-readable results
├── vulnerability_report.xlsx    # Excel spreadsheet (if --excel)
└── vulnscan.db                  # SQLite database (if --use-db)
```

### Report Contents
- **Executive Summary** - High-level findings overview
- **Reconnaissance Results** - DNS, ports, WAF detection
- **Technology Stack** - Identified frameworks and libraries
- **Endpoint Discovery** - All discovered URLs and paths
- **Vulnerability Details** - Comprehensive vulnerability information including:
  - Vulnerability type and severity
  - Affected endpoints
  - Proof of concept evidence
  - Remediation recommendations
  - Technical details and payloads

## Configuration

### Custom Headers
Modify the default headers in the `VulnerabilityScanner` class:

```python
self.headers = {
    "User-Agent": "Custom-Scanner",
    "Accept": "text/html,application/xhtml+xml",
    "Custom-Header": "Custom-Value"
}
```

### Timeout and Concurrency
Adjust performance settings based on target responsiveness:

```bash
# For slow targets
python vulnscan.py https://slow-site.com --timeout 30 --max-workers 2

# For fast targets
python vulnscan.py https://fast-site.com --timeout 5 --max-workers 15
```

## Best Practices

### Ethical Usage
- Only scan applications you own or have explicit permission to test
- Respect rate limits and avoid overwhelming target servers
- Follow responsible disclosure practices for discovered vulnerabilities

### Performance Optimization
- Use appropriate `--max-workers` based on target capacity
- Adjust `--timeout` values for target responsiveness
- Consider `--crawl-depth` impact on scan duration

### Authentication
- Use `--cookies` parameter for authenticated scanning
- Ensure session tokens remain valid throughout scan duration
- Test both authenticated and unauthenticated attack surfaces

## Troubleshooting

### Common Issues

#### "Invalid target URL" Error
- Ensure URL includes protocol (http:// or https://)
- Verify target is accessible and responding
- Check network connectivity and DNS resolution

#### Selenium/ChromeDriver Issues
```bash
# Install ChromeDriver
sudo apt-get install chromium-chromedriver

# Or download manually and add to PATH
export PATH=$PATH:/path/to/chromedriver
```

#### Memory Usage with Large Sites
- Reduce `--max-workers` for memory-constrained environments
- Decrease `--crawl-depth` for sites with many pages
- Monitor system resources during scanning

#### Database Permissions
```bash
# Ensure write permissions for database directory
chmod 755 ./scan_results/
```

## Contributing

Contributions are welcome! Areas for improvement:
- Additional vulnerability scanners
- Enhanced reporting formats
- Performance optimizations
- False positive reduction
- New reconnaissance techniques

## Security Considerations

- VulnScan generates network traffic that may trigger security monitoring
- Some vulnerability tests may cause temporary service disruption
- Always obtain proper authorization before scanning
- Review and understand payloads before deployment

## Disclaimer

This scanner is provided for educational and authorized testing purposes only. The author(s) is/are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before scanning any systems.