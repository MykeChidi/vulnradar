# Getting Started

Welcome to VulnRadar! This guide will help you set up and run your first security scan in minutes.

## Prerequisites

Before you start, make sure you have:
- Python 3.10 or higher installed
- pip package manager
- Internet connection for downloading dependencies
- A target website or application to scan (with proper authorization!)

**Don't have Python?** See [Installation Guide](INSTALLATION.md) for setup instructions.

## 5-Minute Quick Start

### Step 1: Install VulnRadar

```bash
# Clone the repository
git clone https://github.com/MykeChidi/vulnradar.git
cd vulnradar

# Create virtual environment
python -m venv venv

# Activate it
source venv/bin/activate          # macOS/Linux
# OR
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt
```

**Time: 2-3 minutes**

### Step 2: Verify Installation

```bash
python -m vulnradar --help
```

You should see the help menu. If you see an error, check [Troubleshooting](TROUBLESHOOTING.md).

### Step 3: Run Your First Scan

```bash
python -m vulnradar https://example.com
```

That's it! The scanner will:
1. Crawl the website
2. Test for vulnerabilities
3. Generate reports in `scan_results/` directory

**Time: 1-2 minutes (depending on site size)**

### Step 4: View Results

Open the generated report:
```bash
# Open HTML report in browser
open scan_results/report.html              # macOS
start scan_results/report.html             # Windows
xdg-open scan_results/report.html          # Linux
```

## Understanding Your First Scan

### What VulnRadar Does

1. **Crawls** - Discovers pages and endpoints on the target
2. **Scans** - Tests each page for vulnerabilities
3. **Reports** - Creates detailed findings report
4. **Saves** - Stores results in multiple formats

### What Vulnerabilities It Tests

- **SQL Injection** - Database injection attacks
- **XSS** - Cross-site scripting attacks
- **CSRF** - Cross-site request forgery
- **SSRF** - Server-side request forgery
- **Path Traversal** - Directory traversal attacks
- **File Inclusion** - LFI/RFI vulnerabilities
- **Command Injection** - OS command injection

### Report Formats Generated

By default, you get:
- **HTML Report** - Beautiful, interactive findings
- **JSON File** - Machine-readable for automation
- **PDF Report** - Printable professional format

## Next-Level Examples

### Authenticated Scan

```bash
python -m vulnradar https://app.example.com \
    --cookies "session_id=abc123;user=john"
```

You need the cookie value from your browser:
1. Login to the website
2. Open browser DevTools (F12)
3. Go to Application tab
4. Copy cookie values
5. Pass them to VulnRadar

### Deeper Crawl

```bash
python -m vulnradar https://example.com --crawl-depth 4
```

Default depth is 3. Higher values = more thorough but slower:
- `--crawl-depth 2` - Quick scan
- `--crawl-depth 3` - Balanced (default)
- `--crawl-depth 4` - Thorough
- `--crawl-depth 5+` - Very thorough (slow)

### Faster Scanning

```bash
python -m vulnradar https://example.com \
    --max-workers 10 \
    --timeout 5
```

For faster sites:
- Increase `--max-workers` (default 5, try 10-15)
- Decrease `--timeout` (default 10, try 5)

### Focus on Specific Vulnerabilities

```bash
# Only SQL Injection and XSS
python -m vulnradar https://example.com \
    --no-csrf --no-ssrf --no-path-traversal \
    --no-file-inclusion --no-command-injection
```

### Save to Database

```bash
python -m vulnradar https://example.com \
    --use-db --db-path ./scans.db
```

This stores results for comparison across multiple scans.

### With JavaScript Support

```bash
python -m vulnradar https://example.com --use-selenium
```

Requires Chrome browser. Use for modern JavaScript applications.

### Get Reconnaissance Data Only

```bash
python -m vulnradar https://example.com \
    --recon-only --recon-all
```

Only gathers information without testing vulnerabilities:
- DNS records
- Open ports
- Technology stack
- WAF detection

## Report Interpretation

### HTML Report Structure

1. **Summary** - Overview of findings
2. **Vulnerabilities** - Detailed list of issues found
3. **Statistics** - Charts and metrics
4. **Endpoints** - All discovered URLs

### Reading Findings

Each vulnerability shows:
- **Severity** - High, Medium, Low
- **Type** - Vulnerability category
- **Location** - URL/parameter affected
- **Description** - What the issue is
- **Proof** - Evidence it exists
- **Recommendation** - How to fix it

### Severity Levels

- 🔴 **High** - Critical, fix immediately
- 🟠 **Medium** - Important, fix soon
- 🟡 **Low** - Minor, fix when possible
- 🔵 **Info** - Informational only

## Common Issues

### "No vulnerabilities found"
This is good! It means the site either has proper defenses or doesn't have common vulnerabilities. VulnRadar tests for common issues, not all possible vulnerabilities.

### Slow scanning
If scanning is slow:
```bash
# Reduce crawl depth
python -m vulnradar https://example.com --crawl-depth 2

# Or reduce workers
python -m vulnradar https://example.com --max-workers 2
```

### Timeout errors
If you see timeout errors:
```bash
# Increase timeout
python -m vulnradar https://example.com --timeout 30
```

See [Troubleshooting Guide](TROUBLESHOOTING.md) for more issues.

## Important Reminders

### ⚠️ Authorization Required
- Only scan websites/apps you own or have written permission to test
- Unauthorized scanning is illegal in most jurisdictions
- Always get written approval before scanning production systems

### Best Practices
1. **Test first** on a non-production environment
2. **Inform admins** that scanning will occur
3. **Run during** off-peak hours if possible
4. **Keep results** confidential and secure

## Next Steps

1. **Run more scans** with different options
2. **Read [Usage Guide](USAGE.md)** for all available options
3. **Check [Configuration Guide](CONFIGURATION.md)** for advanced setup
4. **Review [Security Guide](SECURITY.md)** for legal considerations

## Common Commands Reference

```bash
# Quick scan
python -m vulnradar https://example.com

# GUI mode
python -m vulnradar --gui

# Deeper scan
python -m vulnradar https://example.com --crawl-depth 4

# Fast scan
python -m vulnradar https://example.com --max-workers 15 --timeout 5

# Authenticated
python -m vulnradar https://example.com --cookies "session=abc"

# Database storage
python -m vulnradar https://example.com --use-db

# Reconnaissance only
python -m vulnradar https://example.com --recon-only --recon-all

# Custom output directory
python -m vulnradar https://example.com --output-dir ./my_results

# Excel report
python -m vulnradar https://example.com --excel

# Specific vulnerabilities only
python -m vulnradar https://example.com --no-xss --no-csrf

# Generate multi-target config template
python -m vulnradar --show-multi-config

# Scan multiple targets
python -m vulnradar --targets-file multi_target_config.yaml

# Sequential multi-target scan
python -m vulnradar --targets-file multi_target_config.yaml --sequential

# Custom concurrency limit
python -m vulnradar --targets-file multi_target_config.yaml --max-concurrent 5
```

## Getting Help

- **Questions?** Check [Troubleshooting Guide](TROUBLESHOOTING.md)
- **Need details?** Read [Usage Guide](USAGE.md)
- **Configuration help?** See [Configuration Guide](CONFIGURATION.md)
- **Multi-target scanning?** See [Multi-Target Scanning Guide](MULTI_TARGET.md)
- **Stuck?** Create an issue on GitHub or check existing issues

---

**Ready to go deeper?** Explore the [Usage Guide](USAGE.md) to master all VulnRadar options or check [Multi-Target Scanning](MULTI_TARGET.md) to scan multiple targets at once!
