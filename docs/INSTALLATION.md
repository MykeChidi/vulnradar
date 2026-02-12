# Installation Guide

This guide covers installing VulnRadar on various platforms.

## System Requirements

### Minimum Requirements
- **Python**: 3.10 or higher
- **Memory**: 512 MB RAM
- **Disk Space**: 300 MB
- **OS**: Windows, macOS, or Linux

### Recommended Requirements
- **Python**: 3.10+
- **Memory**: 2+ GB RAM (for large site scans)
- **Disk Space**: 500 MB
- **Network**: High-speed internet connection

## Prerequisites

### Check Python Version

```bash
python --version
# or
python3 --version
```

Required: Python 3.10 or higher. If you don't have Python installed, download it from [python.org](https://www.python.org/downloads/).

### Check pip Installation

```bash
pip --version
# or
pip3 --version
```

If pip is not installed, install it following the [pip installation guide](https://pip.pypa.io/en/latest/installation/).

## Installation Steps

### 1. Clone or Download the Repository

**Using Git (Recommended):**
```bash
git clone https://github.com/MykeChidi/vulnradar.git
cd vulnradar
```

### 2. Create Virtual Environment

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

Your command prompt should now show `(venv)` prefix.

### 3. Upgrade pip (Optional but Recommended)

```bash
pip install --upgrade pip
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs all required packages:
- aiohttp - Async HTTP client
- beautifulsoup4 - HTML parsing
- selenium - Browser automation
- nmap (python-nmap) - Port scanning
- dnspython - DNS queries
- pandas - Data processing
- requests - HTTP requests
- sqlalchemy - Database ORM
- And more...

**Expected installation time**: 2-5 minutes

### 5. Verify Installation

```bash
python -m vulnradar --help
```

You should see the help output with available options. If you see an error, check the [Troubleshooting](#troubleshooting) section.

## Platform-Specific Instructions

### Windows Installation

1. **Download Python**: Get Python 3.10+ from [python.org](https://www.python.org/downloads/)
2. **Install Python**: 
   - Run the installer
   - ✅ Check "Add Python to PATH"
   - Choose "Install Now"
3. **Open Command Prompt** and follow steps 2-5 above

**Windows-Specific Notes:**
- Use `python` instead of `python3`
- Use `venv\Scripts\activate` to activate virtual environment
- Use backslash `\` for paths (or forward slash `/` works too)

### macOS Installation

1. **Check Python**:
   ```bash
   python3 --version
   ```

2. **Install Homebrew** (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

3. **Install Python** (via Homebrew):
   ```bash
   brew install python3
   ```

4. **Install Xcode Command Line Tools**:
   ```bash
   xcode-select --install
   ```

5. **Follow steps 2-5** from the main installation

### Linux Installation

#### Ubuntu/Debian:
```bash
# Update package manager
sudo apt update
sudo apt upgrade

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Install system dependencies (optional)
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# Follow steps 2-5 from main installation
```

#### Fedora/RHEL/CentOS:
```bash
# Update package manager
sudo dnf update

# Install Python and pip
sudo dnf install python3 python3-pip

# Install development tools
sudo dnf install gcc python3-devel openssl-devel

# Follow steps 2-5 from main installation
```

#### Arch:
```bash
sudo pacman -S python pip

# Follow steps 2-5 from main installation
```

## Optional Dependencies

### Selenium (for JavaScript Rendering)

Selenium enables rendering JavaScript-heavy pages for more thorough scanning:

```bash
pip install selenium
```

You'll also need ChromeDriver:

**Windows:**
```bash
# Download from https://chromedriver.chromium.org/
# Or use package manager
choco install chromedriver
```

**macOS:**
```bash
brew install chromedriver
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install chromium-chromedriver
```

### Nmap (for Advanced Port Scanning)

```bash
# Python package (required)
pip install python-nmap

# System package:
# Windows: choco install nmap
# macOS: brew install nmap
# Linux: sudo apt install nmap
```

## Development Installation

If you're contributing or modifying code:

```bash
# Install development dependencies
pip install -r requirements_dev.txt

# Install in editable mode
pip install -e .

# Setup pre-commit hooks (optional)
pre-commit install
```

## Troubleshooting Installation

### Python Not Found

**Error**: `python: command not found` or `python is not recognized`

**Solution**:
1. Check if Python is installed: `python --version`
2. On Windows, reinstall Python and check "Add Python to PATH"
3. On macOS/Linux, use `python3` instead of `python`

### pip Not Found

**Error**: `pip: command not found`

**Solution**:
```bash
# Try:
python -m pip --version

# Or install pip:
python -m ensurepip --upgrade
```

### Permission Denied

**Error**: `Permission denied` when installing packages

**Solution**:
```bash
# Use virtual environment (recommended):
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Then install normally:
pip install -r requirements.txt
```

### SSL Certificate Error

**Error**: `SSL: CERTIFICATE_VERIFY_FAILED`

**Solution**:
```bash
# On macOS, install SSL certificates:
/Applications/Python\ 3.x/Install\ Certificates.command

# Or upgrade certifi:
pip install --upgrade certifi
```

### Selenium ChromeDriver Error

**Error**: `ChromeDriver not found` or `Session not created`

**Solution**:
1. Download ChromeDriver matching your Chrome version: https://chromedriver.chromium.org/
2. Add to PATH or specify path:
   ```bash
   export PATH=$PATH:/path/to/chromedriver  # Linux/macOS
   set PATH=%PATH%;C:\path\to\chromedriver  # Windows
   ```
3. Or use this when running:
   ```bash
   python -m vulnradar https://example.com --use-selenium
   ```

### Nmap Not Found

**Error**: `nmap: command not found`

**Solution**:
```bash
# Windows:
choco install nmap

# macOS:
brew install nmap

# Linux (Debian/Ubuntu):
sudo apt install nmap

# Linux (Fedora/RHEL):
sudo dnf install nmap
```

### Memory Issues

**Error**: `MemoryError` or `Killed`

**Solution**:
- Reduce concurrency: `--max-workers 2`
- Reduce crawl depth: `--crawl-depth 2`
- Disable JavaScript rendering: Don't use `--use-selenium`

### Module Import Errors

**Error**: `ModuleNotFoundError: No module named 'X'`

**Solution**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Reinstall requirements
pip install --upgrade -r requirements.txt
```

## Verify Installation

After installation, run these commands to verify everything works:

```bash
# Check Python version
python --version

# Check pip installation
pip list

# Check VulnRadar
python -m vulnradar --help

# Run basic scan (with test target)
python -m vulnradar https://example.com
```

You should see help output and no errors.

## Next Steps

1. Read [Getting Started Guide](GETTING_STARTED.md) for your first scan
2. Review [Usage Guide](USAGE.md) for all available options
3. Check [Configuration Guide](CONFIGURATION.md) for advanced setup
4. See [Troubleshooting Guide](TROUBLESHOOTING.md) if you encounter issues

## Uninstall

To remove VulnRadar:

```bash
# Remove virtual environment
rm -rf venv  # Linux/macOS
rmdir /s venv  # Windows

# Or just delete the project folder entirely
cd ..
rm -rf vulnradar  # Linux/macOS
rmdir /s vulnradar  # Windows
```

---

**Need help?** See [Troubleshooting Guide](TROUBLESHOOTING.md) or check [Support Options](README.md#support--issues).
