# Configuration Guide

Complete reference for configuring VulnRadar through CLI arguments and other methods.

## Configuration Methods

VulnRadar can be configured through:
1. **Command-line arguments** (primary method)
2. **Environment variables** (optional)
3. **Defaults** (built-in values)

## CLI Arguments Reference

### Target Configuration

```bash
# Target URL (required)
python -m vulnradar https://example.com

# With cookies
python -m vulnradar https://example.com --cookies "session=abc;user=john"

# Custom User-Agent
python -m vulnradar https://example.com --user-agent "Mozilla/5.0 (Windows NT 10.0)"

# GUI Interface
python -m vulnradar --gui
```

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `url` | string | Required | Target URL to scan |
| `--cookies` | string | None | HTTP cookies for authentication |
| `--user-agent` | string | VulnRadar/1.0 | Custom User-Agent header |
| `--gui` | flag | False | Launch GUI interface |

### Scan Performance Configuration

```bash
# Crawl depth
python -m vulnradar https://example.com --crawl-depth 4

# Request timeout
python -m vulnradar https://example.com --timeout 20

# Concurrent workers
python -m vulnradar https://example.com --max-workers 8

# Enable JavaScript rendering
python -m vulnradar https://example.com --use-selenium

# Maximum pages to crawl
python -m vulnradar https://example.com --max-crawl-pages 500

# Enable port scanning
python -m vulnradar https://example.com --port-scan
```

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--crawl-depth` | int | 3 | How deep to crawl site (1-10) |
| `--timeout` | int | 10 | Request timeout in seconds |
| `--max-workers` | int | 5 | Concurrent request threads |
| `--use-selenium` | flag | False | Enable JavaScript rendering |
| `--max-crawl-pages` | int | 1000 | Maximum pages to crawl |
| `--port-scan` | flag | False | Enable port scanning |

### Vulnerability Scanner Configuration

Disable specific vulnerability scanners:

```bash
# Disable individual scanners
python -m vulnradar https://example.com \
    --no-sqli \
    --no-xss \
    --no-csrf \
    --no-ssrf \
    --no-path-traversal \
    --no-file-inclusion \
    --no-command-injection
```

| Argument | Description |
|----------|-------------|
| `--no-sqli` | Disable SQL injection testing |
| `--no-xss` | Disable XSS testing |
| `--no-csrf` | Disable CSRF testing |
| `--no-ssrf` | Disable SSRF testing |
| `--no-path-traversal` | Disable path traversal testing |
| `--no-file-inclusion` | Disable file inclusion testing |
| `--no-command-injection` | Disable command injection testing |

### Reconnaissance Configuration

```bash
# Reconnaissance only (no vulnerability scanning)
python -m vulnradar https://example.com --recon-only

# Enable all recon modules
python -m vulnradar https://example.com --recon-all

# Specific modules
python -m vulnradar https://example.com \
    --recon-network \
    --recon-security \
    --recon-webapp
```

| Argument | Description |
|----------|-------------|
| `--recon-only` | Skip vulnerability scanning |
| `--recon-all` | Enable all reconnaissance |
| `--recon-network` | Network infrastructure analysis |
| `--recon-security` | Security infrastructure analysis |
| `--recon-webapp` | Web application analysis |
| `--recon-infrastructure` | Infrastructure mapping |
| `--recon-misc` | Miscellaneous analysis |

#### Network Reconnaissance Options

```bash
# Fine-tune network recon
python -m vulnradar https://example.com --recon-network \
    --port-range "1-10000" \
    --no-advanced-port-scan \
    --no-waf-detect
```

| Argument | Description |
|----------|-------------|
| `--port-range` | Ports to scan (e.g., "1-10000") |
| `--no-advanced-port-scan` | Skip port scanning |
| `--no-waf-detect` | Skip WAF detection |
| `--no-detect-load-balancers` | Skip load balancer detection |
| `--no-service-detection` | Skip service detection |
| `--no-os-detection` | Skip OS detection |
| `--no-script-scan` | Skip nmap script scans |

#### Web Application Recon Options

```bash
# Fine-tune webapp recon
python -m vulnradar https://example.com --recon-webapp \
    --dir-enum \
    --no-content-discovery
```

| Argument | Description |
|----------|-------------|
| `--no-content-discovery` | Skip content discovery |
| `--no-js-analysis` | Skip JavaScript analysis |
| `--dir-enum` | Enable directory enumeration |

#### Infrastructure Recon Options

```bash
# Fine-tune infrastructure recon
python -m vulnradar https://example.com --recon-infrastructure \
    --no-subdomain-enum
```

| Argument | Description |
|----------|-------------|
| `--no-subdomain-enum` | Skip subdomain enumeration |
| `--no-cloud-mapping` | Skip cloud infrastructure mapping |
| `--no-dns-bruteforce` | Skip DNS bruteforce |

#### Security Recon Options

```bash
# Fine-tune security recon
python -m vulnradar https://example.com --recon-security \
    --no-ssl-analysis
```

| Argument | Description |
|----------|-------------|
| `--no-ssl-analysis` | Skip SSL/TLS analysis |
| `--no-security-headers` | Skip security headers check |

#### Miscellaneous Recon Options

```bash
# Fine-tune misc recon
python -m vulnradar https://example.com --recon-misc \
    --no-error-analysis
```

| Argument | Description |
|----------|-------------|
| `--no-error-analysis` | Skip error code analysis |
| `--no-cache-analysis` | Skip cache analysis |
| `--no-debug-mode-check` | Skip debug mode detection |
| `--no-check-dev-artifacts` | Skip dev artifacts check |
| `--no-backend-tests` | Skip backend tests |

### Output Configuration

```bash
# Output directory
python -m vulnradar https://example.com --output-dir ./my_results

# Report formats
python -m vulnradar https://example.com \
    --no-html \
    --no-pdf \
    --no-json \
    --excel
```

| Argument | Description | Default |
|----------|-------------|---------|
| `--output-dir` | Output directory for reports | scan_results |
| `--no-html` | Skip HTML report generation | Enabled |
| `--no-pdf` | Skip PDF report generation | Enabled |
| `--no-json` | Skip JSON report generation | Enabled |
| `--excel` | Generate Excel report | Disabled |

### Database Configuration

```bash
# Use database storage
python -m vulnradar https://example.com \
    --use-db \
    --db-path ./scans.db
```

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--use-db` | flag | False | Store results in SQLite database |
| `--db-path` | string | vulnradar.db | Path to database file |

### Cache Configuration

```bash
# Cache control
python -m vulnradar https://example.com \
    --cache-dir ./my_cache \
    --cache-ttl 7200 \
    --clear-cache \
    --no-cache
```

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--cache-dir` | string | cache | Cache directory path |
| `--cache-ttl` | int | 3600 | Cache time-to-live (seconds) |
| `--clear-cache` | flag | False | Clear cache before scanning |
| `--no-cache` | flag | False | Disable caching entirely |

## Configuration Examples

### Lightweight Scan (Quick & Fast)
```bash
python -m vulnradar https://example.com \
    --crawl-depth 2 \
    --max-workers 10 \
    --timeout 5 \
    --max-crawl-pages 500 \
    --no-cache
```

### Comprehensive Scan (Thorough)
```bash
python -m vulnradar https://example.com \
    --crawl-depth 5 \
    --max-workers 3 \
    --timeout 20 \
    --use-selenium \
    --port-scan \
    --use-db \
    --cache-ttl 7200
```

### Authenticated Scan
```bash
python -m vulnradar https://app.example.com \
    --cookies "session=abc123;auth=xyz" \
    --crawl-depth 4 \
    --max-workers 5
```

### Reconnaissance Only
```bash
python -m vulnradar https://example.com \
    --recon-only \
    --recon-all \
    --output-dir ./recon_results
```

### Specific Vulnerability Testing
```bash
python -m vulnradar https://example.com \
    --no-csrf \
    --no-xss \
    --no-ssrf \
    --no-path-traversal \
    --no-file-inclusion \
    --no-command-injection
# Only tests SQL injection
```

### Performance-Limited System
```bash
python -m vulnradar https://example.com \
    --max-workers 2 \
    --max-crawl-pages 300 \
    --crawl-depth 2 \
    --no-cache
```

### CI/CD Pipeline
```bash
python -m vulnradar https://staging.example.com \
    --no-cache \
    --clear-cache \
    --output-dir ./ci_results \
    --json \
    --no-html \
    --no-pdf \
    --timeout 10 \
    --max-workers 5
```

### Enterprise Scan with Storage
```bash
python -m vulnradar https://example.com \
    --crawl-depth 4 \
    --max-workers 8 \
    --use-selenium \
    --port-scan \
    --use-db \
    --db-path ./enterprise_scans.db \
    --output-dir ./reports \
    --excel \
    --cache-ttl 86400
```

## Performance Tuning

### For Slow/Unreliable Networks
```bash
--timeout 30        # Increase timeout
--max-workers 2     # Reduce concurrency
--crawl-depth 2     # Reduce depth
```

### For Fast/Reliable Networks
```bash
--timeout 5         # Decrease timeout
--max-workers 15    # Increase concurrency
--crawl-depth 5     # Increase depth
```

### For Memory-Limited Systems
```bash
--max-workers 2
--max-crawl-pages 500
--crawl-depth 2
--no-cache
```

### For JavaScript-Heavy Sites
```bash
--use-selenium              # Render JavaScript
--max-workers 3             # Lower concurrency (slower)
--timeout 20                # Longer timeout
--crawl-depth 3
```

## Default Values Summary

| Option | Default | Category |
|--------|---------|----------|
| Crawl Depth | 3 | Scanning |
| Timeout | 10 seconds | Scanning |
| Max Workers | 5 | Scanning |
| Max Crawl Pages | 1000 | Scanning |
| Output Dir | scan_results | Output |
| Cache Dir | cache | Cache |
| Cache TTL | 3600 seconds (1 hour) | Cache |
| Database Path | vulnradar.db | Database |
| User-Agent | VulnRadar/1.0 | Target |

## Help and Version

```bash
# Show all options
python -m vulnradar --help

# Show version
python -m vulnradar --version
```

---

**Need more help?** See [Usage Guide](USAGE.md) for examples or [Troubleshooting](TROUBLESHOOTING.md) for common issues.
