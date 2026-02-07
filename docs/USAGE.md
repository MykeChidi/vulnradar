# Usage Guide

Complete reference for all VulnRadar command-line options and usage patterns.

## Basic Syntax

```bash
python -m vulnradar <URL> [OPTIONS]
```

## Quick Examples

### Simple Scan
```bash
python -m vulnradar https://example.com
```

### GUI Mode
```bash
python -m vulnradar --gui
```

### With Cookies (Authenticated Scan)
```bash
python -m vulnradar https://app.example.com --cookies "session=abc123"
```

### Comprehensive Assessment
```bash
python -m vulnradar https://example.com \
    --crawl-depth 4 \
    --port-scan \
    --use-selenium \
    --timeout 20 \
    --max-workers 8 \
    --use-db \
    --db-path ./scans.db \
    --excel
```

## Target Options

### URL Target (Required)
```bash
python -m vulnradar https://example.com
```
- Only required positional argument
- Must be a valid URL (http or https)
- Will be validated before scanning

### Cookies (`--cookies`)
```bash
python -m vulnradar https://example.com --cookies "session=abc123;user=john"
```
- Include authentication cookies
- Format: `key1=value1;key2=value2`
- Useful for authenticated scanning

### User-Agent (`--user-agent`)
```bash
python -m vulnradar https://example.com --user-agent "Mozilla/5.0..."
```
- Default: `VulnRadar/1.0`
- Customize to avoid detection or match browser

### GUI Mode (`--gui`)
```bash
python -m vulnradar --gui
```
- Launch graphical user interface
- No URL required with this flag
- Recommended for beginners

## Scan Options

### Crawl Depth (`--crawl-depth`)
```bash
python -m vulnradar https://example.com --crawl-depth 4
```
- Default: `3`
- Range: `1-10` (recommended)
- Higher values = more thorough but slower
- Controls how many levels deep to follow links

### Request Timeout (`--timeout`)
```bash
python -m vulnradar https://example.com --timeout 30
```
- Default: `10` seconds
- For slow sites: `30` or higher
- For fast sites: `5` or lower

### Max Workers (`--max-workers`)
```bash
python -m vulnradar https://example.com --max-workers 8
```
- Default: `5`
- Higher values = faster but use more resources
- For slow sites: `2-3`
- For fast sites: `10-15`

### Use Selenium (`--use-selenium`)
```bash
python -m vulnradar https://example.com --use-selenium
```
- Enables JavaScript rendering
- More accurate but slower
- Requires Chrome/Chromium browser
- Useful for modern JavaScript applications

### Port Scanning (`--port-scan`)
```bash
python -m vulnradar https://example.com --port-scan
```
- Enables port scanning on target
- Scans top 1000 ports by default
- Requires Nmap to be installed

### Max Crawl Pages (`--max-crawl-pages`)
```bash
python -m vulnradar https://example.com --max-crawl-pages 500
```
- Default: `1000`
- Prevents memory issues on large sites
- Stops crawling after reaching this limit

## Vulnerability Scanning Options

### Disable Specific Scanners

```bash
# Disable SQL Injection scanning
python -m vulnradar https://example.com --no-sqli

# Disable XSS scanning
python -m vulnradar https://example.com --no-xss

# Disable CSRF scanning
python -m vulnradar https://example.com --no-csrf

# Disable SSRF scanning
python -m vulnradar https://example.com --no-ssrf

# Disable Path Traversal scanning
python -m vulnradar https://example.com --no-path-traversal

# Disable File Inclusion scanning
python -m vulnradar https://example.com --no-file-inclusion

# Disable Command Injection scanning
python -m vulnradar https://example.com --no-command-injection
```

### Scan Only Specific Vulnerabilities

```bash
# Only SQL Injection and XSS
python -m vulnradar https://example.com \
    --no-csrf --no-ssrf --no-path-traversal \
    --no-file-inclusion --no-command-injection
```

## Reconnaissance Options

### Recon Only Mode (`--recon-only`)
```bash
python -m vulnradar https://example.com --recon-only
```
- Skip vulnerability scanning
- Only perform reconnaissance
- Useful for discovery phase

### Enable All Reconnaissance (`--recon-all`)
```bash
python -m vulnradar https://example.com --recon-only --recon-all
```
- Enables all reconnaissance modules
- Equivalent to enabling all `--recon-*` flags

### Individual Reconnaissance Modules

#### Network Reconnaissance (`--recon-network`)
```bash
python -m vulnradar https://example.com --recon-only --recon-network
```
- DNS enumeration
- Port scanning
- WAF detection
- Load balancer detection
- Service detection
- OS detection

**Sub-options:**
```bash
--no-advanced-port-scan    # Skip port scanning
--no-waf-detect            # Skip WAF detection
--no-detect-load-balancers # Skip load balancer detection
--no-service-detection     # Skip service detection
--no-os-detection          # Skip OS detection
--no-script-scan           # Skip nmap script scans
--port-range "1-10000"     # Specify port range
```

#### Security Reconnaissance (`--recon-security`)
```bash
python -m vulnradar https://example.com --recon-only --recon-security
```
- SSL/TLS configuration analysis
- Security headers detection
- Certificate information

**Sub-options:**
```bash
--no-ssl-analysis       # Skip SSL analysis
--no-security-headers   # Skip security headers check
```

#### Web Application Reconnaissance (`--recon-webapp`)
```bash
python -m vulnradar https://example.com --recon-only --recon-webapp
```
- Content discovery
- JavaScript analysis
- Directory enumeration

**Sub-options:**
```bash
--no-content-discovery  # Skip content discovery
--no-js-analysis        # Skip JavaScript analysis
--dir-enum              # Enable directory enumeration
```

#### Infrastructure Reconnaissance (`--recon-infrastructure`)
```bash
python -m vulnradar https://example.com --recon-only --recon-infrastructure
```
- Subdomain enumeration
- Cloud infrastructure mapping
- DNS bruteforce

**Sub-options:**
```bash
--no-subdomain-enum     # Skip subdomain enumeration
--no-cloud-mapping      # Skip cloud mapping
--no-dns-bruteforce     # Skip DNS bruteforce
```

#### Miscellaneous Reconnaissance (`--recon-misc`)
```bash
python -m vulnradar https://example.com --recon-only --recon-misc
```
- Error code analysis
- Cache configuration analysis
- Debug mode detection
- Development artifacts detection
- Backend service detection

**Sub-options:**
```bash
--no-error-analysis        # Skip error analysis
--no-cache-analysis        # Skip cache analysis
--no-debug-mode-check      # Skip debug mode detection
--no-check-dev-artifacts   # Skip dev artifacts check
--no-backend-tests         # Skip backend tests
```

## Output Options

### Output Directory (`--output-dir`)
```bash
python -m vulnradar https://example.com --output-dir ./my_results
```
- Default: `scan_results`
- Where reports are saved
- Created automatically if doesn't exist

### Report Formats

#### HTML Report (`--no-html`)
```bash
# Disable HTML (default is enabled)
python -m vulnradar https://example.com --no-html
```
- Default: Enabled
- Interactive, detailed findings
- Best for viewing in browser

#### PDF Report (`--no-pdf`)
```bash
# Disable PDF (default is enabled)
python -m vulnradar https://example.com --no-pdf
```
- Default: Enabled
- Professional, printable format
- Good for sharing with stakeholders

#### JSON Report (`--no-json`)
```bash
# Disable JSON (default is enabled)
python -m vulnradar https://example.com --no-json
```
- Default: Enabled
- Machine-readable format
- Good for automation and integration

#### Excel Report (`--excel`)
```bash
python -m vulnradar https://example.com --excel
```
- Default: Disabled
- Spreadsheet format
- Good for data analysis

## Database Options

### Use Database (`--use-db`)
```bash
python -m vulnradar https://example.com --use-db
```
- Store results in SQLite database
- Useful for multiple scans and analysis

### Database Path (`--db-path`)
```bash
python -m vulnradar https://example.com --use-db --db-path ./scans.db
```
- Default: `vulnradar.db` in current directory
- Path to SQLite database file
- Can be absolute or relative path

## Cache Options

### Cache Directory (`--cache-dir`)
```bash
python -m vulnradar https://example.com --cache-dir ./my_cache
```
- Default: `cache`
- Where cached results are stored
- Improves performance for repeated scans

### Cache TTL (`--cache-ttl`)
```bash
python -m vulnradar https://example.com --cache-ttl 7200
```
- Default: `3600` (1 hour)
- Time-to-live in seconds
- Cached data older than TTL is discarded

### Clear Cache (`--clear-cache`)
```bash
python -m vulnradar https://example.com --clear-cache
```
- Delete cache before scanning
- Ensures fresh results
- Scan still caches new results for future use

### Disable Cache (`--no-cache`)
```bash
python -m vulnradar https://example.com --no-cache
```
- Don't use or save cache
- Every scan is completely fresh
- Slower but ensures accuracy

## Common Use Cases

### 1. Quick Security Check
```bash
python -m vulnradar https://example.com
```

### 2. Authenticated Application Testing
```bash
python -m vulnradar https://app.example.com \
    --cookies "PHPSESSID=xyz123" \
    --crawl-depth 4 \
    --max-workers 5
```

### 3. Slow Server (High Latency)
```bash
python -m vulnradar https://slow-server.example.com \
    --timeout 30 \
    --max-workers 2 \
    --crawl-depth 2
```

### 4. Fast Server (Optimize Speed)
```bash
python -m vulnradar https://fast-server.example.com \
    --timeout 5 \
    --max-workers 15 \
    --max-crawl-pages 2000
```

### 5. JavaScript-Heavy Application
```bash
python -m vulnradar https://react-app.example.com \
    --use-selenium \
    --crawl-depth 3 \
    --timeout 20 \
    --max-workers 3
```

### 6. Reconnaissance Only
```bash
python -m vulnradar https://example.com \
    --recon-only --recon-all \
    --port-scan
```

### 7. Vulnerability Focus (No Recon)
```bash
python -m vulnradar https://example.com \
    --crawl-depth 3 \
    --max-workers 10 \
    --output-dir ./vulns
```

### 8. Specific Vulnerability Testing
```bash
python -m vulnradar https://example.com \
    --no-csrf --no-xss --no-file-inclusion \
    --no-command-injection --no-ssrf
# Only tests: SQLi and Path Traversal
```

### 9. Full Scan with Database Storage
```bash
python -m vulnradar https://example.com \
    --crawl-depth 5 \
    --port-scan \
    --use-selenium \
    --use-db --db-path ./company_scans.db \
    --output-dir ./results \
    --excel \
    --max-workers 8
```

## Performance Tuning

### Memory-Limited Environment
```bash
python -m vulnradar https://example.com \
    --max-workers 2 \
    --max-crawl-pages 500 \
    --crawl-depth 2 \
    --no-cache
```

### Time-Limited Environment (Fast Scan)
```bash
python -m vulnradar https://example.com \
    --timeout 5 \
    --max-workers 15 \
    --crawl-depth 2 \
    --max-crawl-pages 1000
```

### Accuracy Priority (Slow Scan)
```bash
python -m vulnradar https://example.com \
    --timeout 20 \
    --max-workers 3 \
    --crawl-depth 5 \
    --use-selenium
```


## Multi-Target Scanning

### Generate Configuration Template

```bash
python -m vulnradar --show-multi-config
```
- Creates a `multi_target_config.yaml` with examples and comments
- Modify the file to add your targets
- See [Multi-Target Scanning Guide](MULTI_TARGET.md) for detailed format

### Run Multi-Target Scan (Concurrent)

```bash
python -m vulnradar --targets-file multi_target_config.yaml
```
- Scans multiple targets concurrently
- Default: 3 concurrent scans at a time
- Outputs summary and per-target results

### Run Sequential Multi-Target Scan

```bash
python -m vulnradar --targets-file multi_target_config.yaml --sequential
```
- Scans targets one at a time
- Useful for rate-limited or fragile targets
- More stable but slower

### Adjust Concurrency Level

```bash
python -m vulnradar --targets-file multi_target_config.yaml --max-concurrent 5
```
- Default: 3 concurrent scans
- Increase for faster scanning (if resources allow)
- Decrease for stability or rate limiting

### Multi-Target Configuration Example

```yaml
targets:
  - url: "https://example.com"
    name: "Example Site"
    timeout: 120
    retries: 2
    options:
      crawl_depth: 3
      timeout: 10
      max_workers: 5

  - url: "https://api.example.com"
    name: "Example API"
    timeout: 180
    retries: 1
    options:
      crawl_depth: 2
      max_workers: 3
```

Each target can have:
- `url` (required): Target URL to scan
- `name` (optional): Display name for reports
- `timeout` (optional): Timeout per target in seconds
- `retries` (optional): Auto-retry on failure
- `options` (optional): Target-specific scan options

For detailed multi-target documentation, see [Multi-Target Scanning Guide](MULTI_TARGET.md).

## Help 

### Show Help
```bash
python -m vulnradar --help
```
- Display all available options
- Shows default values

---

**Next Steps**: See [Configuration Guide](CONFIGURATION.md) for advanced configuration or [Getting Started](GETTING_STARTED.md) for your first scan.
