# Troubleshooting Guide

Solutions for common VulnRadar issues and problems.

## Installation Issues

### Python Not Found

**Error**: `python: command not found` or `'python' is not recognized as an internal or external command`

**Causes**: Python not installed or not in PATH

**Solutions**:
1. Check if Python is installed:
   ```bash
   python --version
   python3 --version
   ```

2. Install Python:
   - Windows: Download from [python.org](https://www.python.org/downloads/), check "Add Python to PATH"
   - macOS: `brew install python3`
   - Linux: `sudo apt install python3`

3. Use full path to Python:
   ```bash
   /usr/bin/python3 -m vulnradar https://example.com  # macOS/Linux
   "C:\Program Files\Python310\python.exe" -m vulnradar ...  # Windows
   ```

### pip Not Found

**Error**: `pip: command not found` or `'pip' is not recognized`

**Solutions**:
1. Use Python's built-in pip:
   ```bash
   python -m pip --version
   python -m pip install -r requirements.txt
   ```

2. Reinstall pip:
   ```bash
   python -m ensurepip --upgrade
   ```

3. On Linux, install pip package:
   ```bash
   sudo apt install python3-pip
   ```

### Virtual Environment Issues

**Error**: `No module named 'virtualenv'` or virtual environment won't activate

**Solutions**:
1. Create new virtual environment:
   ```bash
   python -m venv venv_new
   source venv_new/bin/activate  # macOS/Linux
   venv_new\Scripts\activate     # Windows
   ```

2. Check if activated (should show `(venv)` in prompt):
   ```bash
   # If not activated, try full path
   source /full/path/to/venv/bin/activate
   ```

3. Manually add to PATH:
   ```bash
   export PATH="/path/to/venv/bin:$PATH"  # macOS/Linux
   ```

### Dependency Installation Fails

**Error**: `Could not find a version that satisfies the requirement` or `ERROR: No matching distribution`

**Causes**: Network issues, incompatible Python version, outdated pip

**Solutions**:
1. Upgrade pip:
   ```bash
   pip install --upgrade pip
   ```

2. Try installing packages individually:
   ```bash
   pip install aiohttp
   pip install beautifulsoup4
   # ... etc
   ```

3. Install from requirements with verbose output:
   ```bash
   pip install -r requirements.txt -v
   ```

4. Check Python version compatibility:
   ```bash
   python --version
   # Should be 3.10 or higher
   ```

5. Clear pip cache:
   ```bash
   pip cache purge
   pip install -r requirements.txt
   ```

### Permission Denied

**Error**: `Permission denied` when installing or running

**Solutions**:
1. Use virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Use `--user` flag:
   ```bash
   pip install --user -r requirements.txt
   ```

3. Use `sudo` (not recommended):
   ```bash
   sudo pip install -r requirements.txt
   ```

## Selenium/JavaScript Issues

### ChromeDriver Not Found

**Error**: `ChromeDriver not found` or `SessionNotCreatedException`

**Causes**: Chrome/Chromium not installed or ChromeDriver not in PATH

**Solutions**:
1. Check Chrome version:
   ```bash
   google-chrome --version  # Linux
   # macOS: /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version
   ```

2. Download matching ChromeDriver from https://chromedriver.chromium.org/

3. Add to PATH:
   ```bash
   # macOS/Linux
   export PATH=$PATH:/path/to/chromedriver
   
   # Windows
   set PATH=%PATH%;C:\path\to\chromedriver
   ```

4. Or run with explicit path:
   ```bash
   # Modify cli.py to include path, or use env variable
   export CHROMEDRIVER_PATH=/path/to/chromedriver
   ```

### Selenium Timeout

**Error**: `TimeoutException` or `Timeout waiting for page load`

**Solutions**:
1. Increase timeout:
   ```bash
   python -m vulnradar https://example.com --timeout 30 --use-selenium
   ```

2. Reduce max workers (less concurrent load):
   ```bash
   python -m vulnradar https://example.com --use-selenium --max-workers 2
   ```

3. Don't use Selenium for this target:
   ```bash
   python -m vulnradar https://example.com
   # Remove --use-selenium flag
   ```

### Selenium Memory Error

**Error**: `MemoryError` when using Selenium

**Causes**: Too many concurrent browser instances

**Solutions**:
1. Reduce max workers:
   ```bash
   python -m vulnradar https://example.com --use-selenium --max-workers 1
   ```

2. Reduce crawl depth:
   ```bash
   python -m vulnradar https://example.com --use-selenium --crawl-depth 2
   ```

3. Disable Selenium:
   ```bash
   python -m vulnradar https://example.com
   # Don't use --use-selenium
   ```

## Nmap/Port Scanning Issues

### Nmap Not Found

**Error**: `nmap: command not found` when using `--port-scan`

**Solutions**:
1. Install Nmap:
   ```bash
   # Windows (Chocolatey)
   choco install nmap
   
   # macOS (Homebrew)
   brew install nmap
   
   # Linux (Debian/Ubuntu)
   sudo apt install nmap
   
   # Linux (Fedora/RHEL)
   sudo dnf install nmap
   ```

2. Add to PATH if needed:
   ```bash
   export PATH=$PATH:/usr/bin/nmap  # Linux/macOS
   set PATH=%PATH%;C:\Program Files\Nmap  # Windows
   ```

3. Don't use port scanning:
   ```bash
   python -m vulnradar https://example.com
   # Remove --port-scan flag
   ```

### Port Scanning Permission Denied

**Error**: `Permission denied` when using port scanning

**Causes**: Port scanning requires elevated privileges

**Solutions**:
1. Run with sudo:
   ```bash
   sudo python -m vulnradar https://example.com --port-scan
   ```

2. Configure Nmap to run without sudo:
   ```bash
   # Linux: Make nmap setuid
   sudo chmod u+s /usr/bin/nmap
   ```

3. Skip port scanning:
   ```bash
   python -m vulnradar https://example.com
   # Remove --port-scan flag
   ```

## Scanning Issues

### URL Invalid / Won't Connect

**Error**: `Invalid URL`, `Connection refused`, or `No such host`

**Solutions**:
1. Check URL format:
   ```bash
   # Include protocol
   python -m vulnradar https://example.com  # ✅ Correct
   python -m vulnradar example.com  # ❌ Wrong
   ```

2. Check target is accessible:
   ```bash
   ping example.com
   curl https://example.com
   ```

3. Check for firewall/network issues:
   ```bash
   # Try with longer timeout
   python -m vulnradar https://example.com --timeout 30
   ```

4. Try with proxy if needed:
   ```bash
   # Set environment variable
   export HTTP_PROXY=http://proxy:port
   export HTTPS_PROXY=http://proxy:port
   python -m vulnradar https://example.com
   ```

### SSL Certificate Errors

**Error**: `SSL: CERTIFICATE_VERIFY_FAILED` or `certificate verify failed`

**Solutions**:
1. For self-signed certificates (test environments only):
   ```bash
   # This is a workaround - not recommended for production
   # Would need to modify the code
   ```

2. Check certificate validity:
   ```bash
   openssl s_client -connect example.com:443
   ```

3. Update certifi:
   ```bash
   pip install --upgrade certifi
   ```

4. On macOS, install SSL certificates:
   ```bash
   /Applications/Python\ 3.x/Install\ Certificates.command
   ```

### Timeout Errors

**Error**: `Timeout` or `Connection timeout`

**Solutions**:
1. Increase timeout:
   ```bash
   python -m vulnradar https://example.com --timeout 30
   ```

2. Reduce concurrency:
   ```bash
   python -m vulnradar https://example.com --max-workers 2
   ```

3. Reduce crawl depth:
   ```bash
   python -m vulnradar https://example.com --crawl-depth 2
   ```

4. Check your network:
   - Ping the target
   - Check internet connection
   - Check for network restrictions

### Rate Limiting / 429 Errors

**Error**: `HTTP 429 Too Many Requests`

**Causes**: Scanner making requests too fast

**Solutions**:
1. Reduce max workers:
   ```bash
   python -m vulnradar https://example.com --max-workers 2
   ```

2. Increase timeout (adds natural delay):
   ```bash
   python -m vulnradar https://example.com --timeout 20 --max-workers 2
   ```

3. Reduce crawl depth:
   ```bash
   python -m vulnradar https://example.com --crawl-depth 2
   ```

4. Contact target administrator for approval to scan at faster rate

### Authentication Failures

**Error**: `401 Unauthorized` or `403 Forbidden`

**Solutions**:
1. Verify cookies are correct:
   ```bash
   # Check in browser DevTools (F12) > Application > Cookies
   python -m vulnradar https://example.com --cookies "session=CORRECT_VALUE"
   ```

2. Update User-Agent:
   ```bash
   python -m vulnradar https://example.com \
       --cookies "session=abc123" \
       --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
   ```

3. Try adding more headers (would need code modification):
   - Check what headers the browser sends
   - Compare with what VulnRadar sends

4. Use Selenium for cookie handling:
   ```bash
   python -m vulnradar https://example.com \
       --use-selenium \
       --cookies "session=abc123"
   ```

## Performance Issues

### Slow Scanning

**Causes**: Network issues, too many workers, high crawl depth, large site

**Solutions**:
1. Check what's slow:
   ```bash
   # Less deep crawl
   python -m vulnradar https://example.com --crawl-depth 2
   
   # Fewer workers
   python -m vulnradar https://example.com --max-workers 2
   
   # Skip JavaScript
   python -m vulnradar https://example.com
   # Don't use --use-selenium
   ```

2. Limit pages crawled:
   ```bash
   python -m vulnradar https://example.com --max-crawl-pages 500
   ```

3. Check network:
   ```bash
   ping example.com
   # Should be <100ms. If >200ms, network is slow
   ```

### High Memory Usage

**Error**: `MemoryError` or system becomes unresponsive

**Solutions**:
1. Reduce concurrency:
   ```bash
   python -m vulnradar https://example.com --max-workers 2
   ```

2. Limit pages:
   ```bash
   python -m vulnradar https://example.com --max-crawl-pages 300
   ```

3. Don't use Selenium:
   ```bash
   python -m vulnradar https://example.com
   # Remove --use-selenium flag
   ```

4. Reduce crawl depth:
   ```bash
   python -m vulnradar https://example.com --crawl-depth 2
   ```

### High CPU Usage

**Error**: Process is using 100% CPU

**Solutions**:
1. Usually not a problem - just very efficient scanning
2. If system unresponsive, reduce workers:
   ```bash
   python -m vulnradar https://example.com --max-workers 2
   ```

## Report Generation Issues

### No Report Generated

**Error**: Scanning completes but no report files created

**Solutions**:
1. Check output directory:
   ```bash
   ls scan_results/  # Linux/macOS
   dir scan_results  # Windows
   ```

2. Specify output directory explicitly:
   ```bash
   python -m vulnradar https://example.com --output-dir ./my_results
   ```

3. Check file permissions:
   ```bash
   # Ensure directory is writable
   chmod 755 scan_results  # Linux/macOS
   ```

4. Don't disable all formats:
   ```bash
   python -m vulnradar https://example.com
   # Don't use --no-html --no-pdf --no-json together
   ```

### PDF Generation Error

**Error**: PDF report won't generate or is corrupted

**Solutions**:
1. Disable PDF generation:
   ```bash
   python -m vulnradar https://example.com --no-pdf
   ```

2. Check if ReportLab is installed:
   ```bash
   pip install --upgrade reportlab
   ```

3. Try HTML or JSON instead:
   ```bash
   python -m vulnradar https://example.com --no-pdf 
   ```

## GUI Issues

### GUI Won't Start

**Error**: `tkinter` import error or GUI window doesn't open

**Solutions**:
1. Install tkinter:
   ```bash
   # Linux
   sudo apt install python3-tk
   
   # macOS
   brew install python-tk
   
   # Windows (included with Python)
   ```

2. Use CLI instead:
   ```bash
   python -m vulnradar https://example.com
   ```

### GUI Unresponsive

**Error**: GUI freezes during scan

**Solutions**:
1. Give it more time (scanning may be running)
2. Check terminal for errors
3. Reduce scan intensity:
   ```bash
   python -m vulnradar --gui
   # In GUI: set Max Workers to 2, Timeout to 5
   ```

## Database Issues

### Database File Corruption

**Error**: Database error or scan won't start with `--use-db`

**Solutions**:
1. Delete corrupted database:
   ```bash
   rm vulnradar.db
   # Or specify new path
   python -m vulnradar https://example.com --use-db --db-path ./new_scans.db
   ```

2. Use SQLite tools to check:
   ```bash
   sqlite3 vulnradar.db ".tables"
   ```

## Cache Issues

### Cache-Related Problems

**Error**: Old results appearing or cache issues

**Solutions**:
1. Clear cache:
   ```bash
   python -m vulnradar https://example.com --clear-cache
   ```

2. Disable caching:
   ```bash
   python -m vulnradar https://example.com --no-cache
   ```

3. Reduce cache TTL:
   ```bash
   python -m vulnradar https://example.com --cache-ttl 300
   # Cache expires after 5 minutes
   ```

## Getting Help

### If Issue Not Listed Here

1. **Check existing issues**: https://github.com/MykeChidi/vulnradar/issues
2. **Create detailed bug report** with:
   - Exact command you ran
   - Full error message
   - Python version (`python --version`)
   - OS and version
   - Steps to reproduce

3. **Check documentation**:
   - [Installation Guide](INSTALLATION.md)
   - [Usage Guide](USAGE.md)
   - [Configuration Guide](CONFIGURATION.md)

4. **Debug tips**:
   - Try simpler command first
   - Add `--help` to see all options
   - Check all prerequisites are installed
   - Try target with `curl` or browser first

---

**Still need help?** Create an issue on GitHub with your error details and command used.
