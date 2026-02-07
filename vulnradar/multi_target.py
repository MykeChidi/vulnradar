# vulnradar/multi_target.py - Multi-Target Scanning Module

import asyncio
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style
from tqdm import tqdm

from .core import VulnRadar
from .utils.logger import setup_logger

logger = setup_logger("multi_target")


@dataclass
class TargetConfig:
    """Configuration for a single target."""
    url: str
    name: Optional[str] = None
    options: Optional[Dict] = None
    timeout: Optional[int] = 300  # Default 5 minutes
    retries: int = 0
    
    def __post_init__(self):
        if self.name is None:
            self.name = self.url
        if self.options is None:
            self.options = {}
        
        # Validate URL format
        if not self._validate_url():
            raise ValueError(f"Invalid URL format: {self.url}")
        
        # Validate timeout
        if self.timeout is not None and self.timeout <= 0:
            raise ValueError(f"Timeout must be positive, got: {self.timeout}")
        
        if self.retries < 0:
            raise ValueError(f"Retries must be >= 0, got: {self.retries}")
    
    def _validate_url(self) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(self.url)
            # URL must have scheme and netloc
            return bool(result.scheme and result.netloc)
        except Exception:
            return False


class MultiTargetScanner:
    """Scanner for multiple targets with individual configurations."""
    
    def __init__(self, config_file: Path, default_options: Optional[Dict] = None, 
                 concurrent: bool = True, max_concurrent: int = 3,
                 rate_limit: float = 1.0, ):
        """
        Initialize multi-target scanner.
        
        Args:
            config_file: Path to configuration file 
            default_options: Default options to apply to all targets
            concurrent: Whether to run scans concurrently
            max_concurrent: Maximum number of concurrent scans
            rate_limit: Delay between target scans in seconds (0 = no limit)
            state_file: Optional file to save/restore scan state
        """
        self.config_file = Path(config_file)
        self.default_options = default_options or {}
        self.concurrent = concurrent
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.targets: List[TargetConfig] = []
        self.results: List[Dict] = []
        self.scan_started: Optional[datetime] = None
        self.scan_ended: Optional[datetime] = None
        
        # Validate config file exists
        if not self.config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
        
        # Load targets
        self._load_targets()
    
    def _load_targets(self):
        """Load targets from configuration file."""
        file_ext = self.config_file.suffix.lower()
        
        try:
            if file_ext in ['.yaml', '.yml']:
                self._parse_targets(self._load_yaml())
            else:
                raise ValueError(f"Unsupported file format: {file_ext}. Use JSON or YAML.")
                
            logger.info(f"Loaded {len(self.targets)} targets from {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to load targets: {str(e)}")
            raise
    
    def _parse_targets(self, data: any) -> None:
        """Parse targets from loaded data (JSON/YAML)."""
        if isinstance(data, list):
            # Array of targets
            for item in data:
                self._add_target_from_item(item)
        elif isinstance(data, dict):
            if 'targets' in data:
                # Object with explicit targets key
                if not isinstance(data['targets'], list):
                    raise ValueError("'targets' key must contain a list")
                for item in data['targets']:
                    self._add_target_from_item(item)
            else:
                # Object with URLs as keys
                for name, config in data.items():
                    if isinstance(config, str):
                        self._add_target(url=config, name=name)
                    elif isinstance(config, dict):
                        self._add_target(
                            url=config.get('url', name),
                            name=name,
                            options=config.get('options'),
                            timeout=config.get('timeout'),
                            retries=config.get('retries', 0)
                        )
    
    def _add_target_from_item(self, item: any) -> None:
        """Add single target from parsed item."""
        if isinstance(item, str):
            self._add_target(url=item)
        elif isinstance(item, dict):
            self._add_target(
                url=item.get('url'),
                name=item.get('name'),
                options=item.get('options'),
                timeout=item.get('timeout'),
                retries=item.get('retries', 0)
            )
    
    def _add_target(self, url: str, name: Optional[str] = None,
                    options: Optional[Dict] = None, timeout: Optional[int] = None,
                    retries: int = 0) -> None:
        """Add a single target with validation."""
        if not url:
            logger.warning("Skipping target with missing URL")
            return
        
        try:
            target = TargetConfig(
                url=url,
                name=name,
                options=options,
                timeout=timeout,
                retries=retries
            )
            self.targets.append(target)
        except ValueError as e:
            logger.warning(f"Skipping invalid target: {e}")
    
    def _load_yaml(self) -> any:
        """Load and parse YAML file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return data if data is not None else {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {self.config_file}: {str(e)}")
    
    def _merge_options(self, target_options: Dict) -> Dict:
        """Merge target-specific options with defaults."""
        merged = self.default_options.copy()
        merged.update(target_options)
        return merged
    
    async def scan_target(self, target: TargetConfig, attempt: int = 1) -> Dict:
        """
        Scan a single target with retry logic.
        
        Args:
            target: Target configuration
            attempt: Current retry attempt
            
        Returns:
            Dict: Scan results
        """
        logger.info(f"{Fore.CYAN}Starting scan for: {target.name}{Style.RESET_ALL}")
        
        try:
            # Merge options with target-specific timeout
            options = self._merge_options(target.options)
            if target.timeout:
                options['timeout'] = target.timeout
            
            # Create scanner
            scanner = VulnRadar(target.url, options)
            
            # Run scan with timeout
            try:
                results = await asyncio.wait_for(
                    scanner.scan(),
                    timeout=target.timeout
                )
            except asyncio.TimeoutError:
                raise TimeoutError(f"Scan exceeded timeout of {target.timeout}s")
            
            # Add metadata
            results['target_name'] = target.name
            results['target_url'] = target.url
            results['scan_completed'] = True
            results['scan_timestamp'] = datetime.now().isoformat()
            results['attempt'] = attempt
            
            logger.info(f"{Fore.GREEN}Completed scan for: {target.name}{Style.RESET_ALL}")
            
            return results
            
        except Exception as e:
            logger.error(f"{Fore.RED}Scan failed for {target.name} (attempt {attempt}): {str(e)}{Style.RESET_ALL}")
            
            # Retry if attempts remain
            if attempt <= target.retries:
                logger.info(f"Retrying {target.name}... ({attempt}/{target.retries})")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                return await self.scan_target(target, attempt + 1)
            
            return {
                'target': target.url,
                'target_name': target.name,
                'target_url': target.url,
                'scan_completed': False,
                'error': str(e),
                'scan_timestamp': datetime.now().isoformat(),
                'attempt': attempt
            }
    
    async def scan_sequential(self) -> None:
        """Run scans sequentially."""
        logger.info(f"{Fore.YELLOW}Running sequential scans...{Style.RESET_ALL}")
        
        with tqdm(total=len(self.targets), desc="Scanning targets", unit="target") as pbar:
            for target in self.targets:
                result = await self.scan_target(target)
                self.results.append(result)
                pbar.update(1)
                pbar.set_postfix(current=target.name)
                
                # Rate limiting
                if self.rate_limit > 0:
                    await asyncio.sleep(self.rate_limit)
    
    async def scan_concurrent(self) -> None:
        """Run scans concurrently with limit."""
        logger.info(f"{Fore.YELLOW}Running concurrent scans (max {self.max_concurrent})...{Style.RESET_ALL}")
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def limited_scan(target):
            async with semaphore:
                result = await self.scan_target(target)
                if self.rate_limit > 0:
                    await asyncio.sleep(self.rate_limit)
                return result
        
        # Create tasks
        tasks = [limited_scan(target) for target in self.targets]
        
        # Run with progress bar
        with tqdm(total=len(self.targets), desc="Scanning targets", unit="target") as pbar:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                self.results.append(result)
                pbar.update(1)
    
    async def scan_all(self) -> List[Dict]:
        """
        Scan all targets.
        
        Returns:
            List[Dict]: Results for all targets
        """
        if not self.targets:
            logger.warning("No targets to scan")
            return []
        
        self.scan_started = datetime.now()
        logger.info(f"Scanning {len(self.targets)} targets...")
        
        try:
            if self.concurrent:
                await self.scan_concurrent()
            else:
                await self.scan_sequential()
        finally:
            self.scan_ended = datetime.now()
        
        return self.results
    
    def generate_summary(self) -> Dict:
        """Generate summary of all scan results."""
        summary = {
            'total_targets': len(self.targets),
            'successful_scans': 0,
            'failed_scans': 0,
            'total_vulnerabilities': 0,
            'total_endpoints': 0,
            'vulnerabilities_by_severity': {'High': 0, 'Medium': 0, 'Low': 0},
            'vulnerabilities_by_type': {},
            'targets': []
        }
        
        for result in self.results:
            target_summary = {
                'name': result.get('target_name', result.get('target')),
                'url': result.get('target'),
                'status': 'success' if result.get('scan_completed') else 'failed'
            }
            
            if result.get('scan_completed'):
                summary['successful_scans'] += 1
                
                # Count vulnerabilities
                vulns = result.get('vulnerabilities', [])
                target_summary['vulnerabilities'] = len(vulns)
                summary['total_vulnerabilities'] += len(vulns)
                
                # Count endpoints
                endpoints = result.get('endpoints', [])
                target_summary['endpoints'] = len(endpoints)
                summary['total_endpoints'] += len(endpoints)
                
                # Categorize vulnerabilities
                for vuln in vulns:
                    severity = vuln.get('severity', 'Unknown')
                    if severity in summary['vulnerabilities_by_severity']:
                        summary['vulnerabilities_by_severity'][severity] += 1
                    
                    vuln_type = vuln.get('type', 'Unknown')
                    summary['vulnerabilities_by_type'][vuln_type] = \
                        summary['vulnerabilities_by_type'].get(vuln_type, 0) + 1
            else:
                summary['failed_scans'] += 1
                target_summary['error'] = result.get('error', 'Unknown error')
            
            summary['targets'].append(target_summary)
        
        return summary
    
    def print_summary(self):
        """Print formatted summary to console."""
        summary = self.generate_summary()
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}MULTI-TARGET SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        
        print(f"Total Targets: {summary['total_targets']}")
        print(f"Successful Scans: {Fore.GREEN}{summary['successful_scans']}{Style.RESET_ALL}")
        print(f"Failed Scans: {Fore.RED}{summary['failed_scans']}{Style.RESET_ALL}")
        print(f"\nTotal Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"Total Endpoints: {summary['total_endpoints']}")
        
        print(f"\n{Fore.YELLOW}Vulnerabilities by Severity:{Style.RESET_ALL}")
        for severity, count in summary['vulnerabilities_by_severity'].items():
            color = Fore.RED if severity == 'High' else \
                   Fore.YELLOW if severity == 'Medium' else Fore.BLUE
            print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
        
        if summary['vulnerabilities_by_type']:
            print(f"\n{Fore.YELLOW}Vulnerabilities by Type:{Style.RESET_ALL}")
            for vuln_type, count in sorted(summary['vulnerabilities_by_type'].items(), 
                                          key=lambda x: x[1], reverse=True):
                print(f"  {vuln_type}: {count}")
        
        print(f"\n{Fore.YELLOW}Target Details:{Style.RESET_ALL}")
        for target in summary['targets']:
            status_color = Fore.GREEN if target['status'] == 'success' else Fore.RED
            print(f"\n  {Fore.CYAN}{target['name']}{Style.RESET_ALL}")
            print(f"    URL: {target['url']}")
            print(f"    Status: {status_color}{target['status']}{Style.RESET_ALL}")
            
            if target['status'] == 'success':
                print(f"    Vulnerabilities: {target['vulnerabilities']}")
                print(f"    Endpoints: {target['endpoints']}")
            else:
                print(f"    Error: {target.get('error', 'Unknown')}")
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    def save_summary(self, output_file: Path) -> None:
        """Save detailed summary to JSON file."""
        summary = self.generate_summary()
        
        # Add metadata
        summary['scan_metadata'] = {
            'total_targets': len(self.targets),
            'scan_started': self.scan_started.isoformat() if self.scan_started else None,
            'scan_ended': self.scan_ended.isoformat() if self.scan_ended else None,
            'scan_duration_seconds': (
                (self.scan_ended - self.scan_started).total_seconds()
                if self.scan_started and self.scan_ended else None
            ),
            'concurrent_mode': self.concurrent,
            'max_concurrent': self.max_concurrent
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, default=str)
            logger.info(f"Summary saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save summary: {e}")
    
    def save_detailed_results(self, output_dir: Path) -> None:
        """Save individual results to separate JSON files."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for result in self.results:
            filename = f"{result.get('target_name', 'unknown').replace('/', '_')}_result.json"
            filepath = output_dir / filename
            
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, default=str)
            except Exception as e:
                logger.error(f"Failed to save result for {result.get('target_name')}: {e}")
        
        logger.info(f"Results saved to: {output_dir}")
    
    @staticmethod
    def generate_config_template(format: str = 'yaml') -> str:
        """
        Generate a template configuration file for multi-target scanning with detailed guided comments.
        
        Args:
            format: Configuration format (yaml)
            
        Returns:
            Configuration template as string
            
        Raises:
            ValueError: If format is not 'yaml'
        """
        if format.lower() not in ['yaml', 'yml']:
            raise ValueError("Format must be 'yaml'")
        
        content = MultiTargetScanner._generate_template()
        filename = "multi_target_config.yaml"
        
        output_path = Path.cwd() / filename
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Configuration template saved to: {output_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration template: {e}")
            raise
        
        return content
    
    @staticmethod
    def _generate_template() -> str:
        """Generate YAML config template with detailed comments."""
        yaml_content = """# VulnRadar Multi-Target Configuration Template
# ============================================
# QUICK START:
#   1. Edit this file and add your target URLs
#   2. Customize options as needed
#   3. Run: python -m vulnradar --targets-file multi_target_config.yaml

targets:
  # ========== TARGET 1: Basic Web Application ==========
  - url: "https://example.com"
    name: "Example Web Application"  # Display name for reports
    timeout: 120                       # Max seconds (default: 300 = 5 mins)
    retries: 2                         # Auto-retry on failure (default: 0)
    
    options:
      # ========== CRAWLING OPTIONS ==========
      # crawl_depth: Levels to crawl (recommended: 2-4)
      #   - 1-2: Fast (large/complex sites)
      #   - 3-4: Balanced (most websites)
      #   - 5+: Deep (small/simple sites)
      crawl_depth: 3
      
      # timeout: request timeout in seconds 
      timeout: 10
      # max_workers: Concurrent requests (recommended: 3-8)
      #   - 1-2: Slow targets / rate-limiting
      #   - 3-8: Standard (most sites)
      #   - 9+: Fast/high-capacity targets
      max_workers: 5
      
      # use_selenium: Enable JavaScript rendering
      #   - true: Slower but finds JS-based vulns
      #   - false: Faster standard HTTP
      use_selenium: false
      
      # max_crawl_pages: Limit crawled pages (prevents infinite crawling)
      max_crawl_pages: 1000
      
      # port_scan: Scan for open ports
      port_scan: false
      
      # ========== VULNERABILITY SCANNING ==========
      # Set to true to enable, false to skip
      scan_sqli: true              # SQL Injection
      scan_xss: true               # Cross-Site Scripting
      scan_csrf: true              # CSRF
      scan_ssrf: true              # Server-Side Request Forgery
      scan_path_traversal: true    # Path Traversal
      scan_file_inclusion: true    # File Inclusion
      scan_command_injection: true # Command Injection
      
      # ========== AUTHENTICATION OPTIONS ==========
      # cookies: Session cookies for authenticated scanning
      #   Format: "cookie1=value1; cookie2=value2"
      #   Use null for unauthenticated scanning
      cookies: null
      user_agent: "VulnRadar/1.0"

  # ========== TARGET 2: API ==========
  - url: "https://api.example.com"
    name: "Example API"
    timeout: 180
    retries: 1
    options:
      crawl_depth: 2
      timeout: 15
      max_workers: 3
      use_selenium: false
      scan_sqli: true
      scan_xss: false
      port_scan: false

  # ========== TARGET 3: Internal App (Authenticated) ==========
  - url: "https://internal.example.com"
    name: "Internal App"
    timeout: 200        # Longer for internal apps
    retries: 3          # More retries for flaky connections
    options:
      crawl_depth: 4
      timeout: 20
      max_workers: 8
      use_selenium: true # May need JS rendering
      scan_command_injection: false
      cookies: "session_id=abc123; auth_token=xyz789"

# ========== HOW TO ADD MORE TARGETS ==========
# Copy one target block above, modify:
#   - url: your target URL
#   - name: friendly display name
#   - retries: increase for unreliable targets
#   - options: customize for that target

# ========== TIPS ==========
# - Start with crawl_depth: 2-3 for speed
# - Use retries: 2+ for flaky targets
# - Disable unneeded scans to speed up
# - Test with 1 target before scanning many
"""
        return yaml_content

