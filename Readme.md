# `VulnScan` - A Web Vulnerability Scanner

A comprehensive, asynchronous web vulnerability scanner designed to identify common security flaws in web applications. VulnScan performs automated reconnaissance, crawling, technology detection, and vulnerability testing with detailed reporting capabilities.

## Features

### 🖥️ User Interface
- **Command-line interface** - Full-featured CLI with extensive options
- **Graphical interface** - User-friendly GUI for easier operation

### 🔍 Reconnaissance
- **Basic Reconnaissance**
  - DNS lookup (A, MX, NS, TXT records)
  - Port scanning (top 1000 ports)
  - Web Application Firewall (WAF) detection
  - Technology stack identification

- **Advanced Reconnaissance Modules**
  - Network Infrastructure Analysis
  - Security Infrastructure Analysis
  - Web Application Analysis
  - Infrastructure Relationship Mapping
  - Miscellaneous Analysis

### 🕷️ Web Crawling
- Intelligent web crawling with configurable depth
- JavaScript rendering support via Selenium
- Endpoint discovery and mapping
- Progress tracking with visual indicators
- Configurable page limits to prevent memory overflow

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
- Result caching for faster repeated scans
- Batch processing for large endpoint sets

## Installation

### Prerequisites
- Python 3.10+
- pip package manager

### Required Dependencies
Install the required Python packages:

```bash
pip install -r requirements.txt
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

## Usage

### GUI Mode

Launch the graphical interface:
```bash
python vulnscan.py --gui
```

Or launch with pre-filled target URL:
```bash
python vulnscan.py https://example.com --gui
```

### Command Line Mode

#### Basic Usage
```bash
python vulnscan.py https://example.com
```

#### View Usage Examples
Run without arguments to see comprehensive usage examples:
```bash
python vulnscan.py
```

### Command Line Arguments

#### Target Options
- `url` - Target URL to scan (required for CLI mode)
- `--cookies` - Cookies to include with HTTP requests
- `--user-agent` - Custom User-Agent string (default: VulnScan/1.0)
- `--gui` - Launch graphical user interface

#### Scan Configuration
- `--crawl-depth` - Maximum crawl depth (default: 3)
- `--max-crawl-pages` - Maximum number of pages to crawl (default: 1000)
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

#### Advanced Reconnaissance Options
- `--advanced-recon-only` - Perform reconnaissance only, skip vulnerability scanning
- `--recon-network` - Enable network infrastructure analysis
- `--recon-security` - Enable security infrastructure analysis
- `--recon-webapp` - Enable web application analysis
- `--recon-infrastructure` - Enable infrastructure relationship mapping
- `--recon-misc` - Enable miscellaneous analysis
- `--recon-all` - Enable all reconnaissance modules

#### Fine-Grained Reconnaissance Control

**Network Analysis:**
- `--no-advanced-port-scan` - Skip port scanning during advanced recon
- `--no-waf-detect` - Skip firewall detection
- `--no-detect-load-balancers` - Skip load balancer detection
- `--no-service-detection` - Skip service detection on open ports
- `--no-os-detection` - Skip target OS detection
- `--no-script-scan` - Skip nmap script scan

**Web Application Analysis:**
- `--no-content-discovery` - Skip content discovery
- `--no-js-analysis` - Skip JavaScript content analysis
- `--dir-enum` - Enable directory enumeration

**Infrastructure Mapping:**
- `--no-subdomain-enum` - Skip subdomain enumeration
- `--no-cloud-mapping` - Skip cloud infrastructure mapping
- `--no-dns-bruteforce` - Skip DNS brute-force

**Security Analysis:**
- `--no-ssl-analysis` - Skip SSL security configuration analysis
- `--no-security-headers` - Skip security header configuration analysis

**Miscellaneous:**
- `--no-error-analysis` - Skip error code analysis
- `--no-cache-analysis` - Skip cache configuration analysis
- `--no-debug-mode-check` - Skip debug mode detection
- `--no-check-dev-artifacts` - Skip development artifact detection
- `--no-backend-tests` - Skip backend tests

#### Cache Options
- `--cache-dir` - Directory for caching results (default: cache)
- `--cache-ttl` - Cache time-to-live in seconds (default: 3600)
- `--no-cache` - Disable result caching
- `--clear-cache` - Clear cache before scanning

#### Output Options
- `--output-dir` - Output directory for reports (default: scan_results)
- `--no-html` - Skip HTML report generation
- `--no-pdf` - Skip PDF report generation
- `--no-json` - Skip JSON report generation
- `--excel` - Generate Excel report

#### Database Options
- `--use-db` - Store results in SQLite database
- `--db-path` - Path to SQLite database (default: vulnscan.db)

## Advanced Usage Examples

### Quick Scan
```bash
python vulnscan.py https://example.com
```

### Authenticated Scanning
```bash
python vulnscan.py https://app.example.com \
    --cookies "PHPSESSID=abc123; user_token=xyz789" \
    --crawl-depth 3 \
    --output-dir ./authenticated_scan
```

### Comprehensive Security Assessment
```bash
python vulnscan.py https://example.com \
    --crawl-depth 5 \
    --port-scan \
    --use-selenium \
    --timeout 20 \
    --max-workers 10 \
    --use-db \
    --db-path ./scans.db \
    --excel
```

### Targeted Vulnerability Scanning
```bash
python vulnscan.py https://example.com \
    --no-csrf \
    --no-ssrf \
    --no-path-traversal \
    --timeout 30
```

### Advanced Reconnaissance Only
```bash
# Interactive module selection
python vulnscan.py https://example.com --advanced-recon-only

# Specific modules
python vulnscan.py https://example.com \
    --advanced-recon-only \
    --recon-network \
    --recon-security

# All modules
python vulnscan.py https://example.com \
    --advanced-recon-only \
    --recon-all
```

### Fine-Tuned Reconnaissance
```bash
python vulnscan.py https://example.com \
    --advanced-recon-only \
    --recon-network \
    --no-os-detection \
    --no-script-scan \
    --cache-dir ./recon_cache
```

### Performance Optimization

For slow targets:
```bash
python vulnscan.py https://slow-site.com --timeout 30 --max-workers 2
```

For fast targets:
```bash
python vulnscan.py https://fast-site.com --timeout 5 --max-workers 15
```

### Cache Management
```bash
# Clear cache before scan (but use cache during scan)
python vulnscan.py https://example.com --clear-cache

# Disable caching completely
python vulnscan.py https://example.com --no-cache

# Custom cache settings
python vulnscan.py https://example.com \
    --cache-dir ./my_cache \
    --cache-ttl 7200
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
- **Reconnaissance Results** - DNS, ports, WAF detection, advanced recon findings
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
- Consider `--crawl-depth` and `--max-crawl-pages` impact on scan duration
- Enable caching for faster repeated scans
- Clear cache periodically to avoid stale results

### Authentication
- Use `--cookies` parameter for authenticated scanning
- Ensure session tokens remain valid throughout scan duration
- Test both authenticated and unauthenticated attack surfaces

### Reconnaissance Strategy
- Start with `--advanced-recon-only` to understand the target
- Use specific recon modules to focus on areas of interest
- Disable unnecessary checks with fine-grained flags to speed up scans
- Save recon results to database for future reference

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
- Decrease `--crawl-depth` and `--max-crawl-pages` for sites with many pages
- Monitor system resources during scanning
- Enable `--no-cache` if cache size becomes too large

#### Database Permissions
```bash
# Ensure write permissions for database directory
chmod 755 ./scan_results/
```

#### GUI Launch Issues
- Ensure tkinter is installed: `sudo apt-get install python3-tk` (Linux)
- On macOS, tkinter comes with Python
- On Windows, tkinter is included in the standard Python installation

## Contributing

Contributions are welcome! Areas for improvement:
- Additional vulnerability scanners
- Enhanced reporting formats
- Performance optimizations
- False positive reduction
- New reconnaissance techniques
- Improved scanning techniques
- GUI enhancements

## Security Considerations

- VulnScan generates network traffic that may trigger security monitoring
- Some vulnerability tests may cause temporary service disruption
- Always obtain proper authorization before scanning
- Review and understand payloads before deployment
- Cache files may contain sensitive information - secure the cache directory

## Legal Disclaimer

This tool is intended for authorized security testing only. Users are required to:
- Obtain proper written authorization before scanning any systems
- Comply with all applicable laws and regulations
- Use responsibly and ethically
- Understand that unauthorized scanning may be illegal in your jurisdiction