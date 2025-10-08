#!/usr/bin/env python3
# vulnscan.py - Main entry point for the Web Vulnerability Scanner

import argparse
import asyncio
import time
from pathlib import Path
from typing import Dict, List
import sys

import aiohttp
import colorama
import dns.resolver
from colorama import Fore, Style
from nmap import PortScanner
from tqdm import tqdm
from wafw00f.main import WAFW00F

# Import custom modules
from crawlers import WebCrawler
from detector import TechDetector
from scanners.csrf import CSRFScanner
from scanners.file_inclusion import FileInclusionScanner
from scanners.comm_injection import CommandInjectionScanner
from scanners.path_traversal import PathTraversalScanner
from scanners.sqli import SQLInjectionScanner
from scanners.ssrf import SSRFScanner
from scanners.xss import XSSScanner
from utils.db import VulnscanDatabase
from utils.logger import setup_logger
from utils.reporter import Report, ReportGenerator
from utils.cache import ScanCache
from recon import ReconManager

# Initialize colorama
colorama.init()

# Setup logger
logger = setup_logger("vulnscan")


class VulnerabilityScanner:
    """Main class for the Web Vulnerability Scanner."""

    def __init__(self, target_url: str, options: dict):
        """
        Initialize the scanner with target URL and options.
        
        Args:
            target_url: URL to scan
            options: Dictionary of scan options
        """
        self.target_url = target_url
        self.options = options
        self.results = {
            "target": target_url,
            "scan_time": time.strftime("%d-%m-%Y %H:%M:%S"),
            "vulnerabilities": [],
            "reconnaissance": {},
            "endpoints": set(),
            "technologies": {},
        }
        
        # Headers for HTTP requests
        self.headers = {
            "User-Agent": options.get("user_agent", "VulnScan/1.0"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        
        if options.get("cookies"):
            self.headers["Cookie"] = options.get("cookies")
            
        # Database connection
        if options.get("use_db", False):
            self.db = VulnscanDatabase(options.get("db_path", "vulnscan.db"))
        else:
            self.db = None
            
        # Concurrency settings
        self.max_workers = options.get("max_workers", 5)
        
        # Create output directory if it doesn't exist
        self.output_dir = Path(options.get("output_dir", "vulnscan_results"))
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize cache
        if not options.get("no_cache", False):
            cache_dir = Path(options.get("cache_dir", "cache"))
            self.cache = ScanCache(
                cache_dir, 
                default_ttl=options.get("cache_ttl", 3600)
            )
            # Clear cache if requested
            if options.get("clear_cache", False):
                logger.info(f"{Fore.YELLOW}Clearing cache...{Style.RESET_ALL}")
                self.cache.clear_all()
                logger.info(f"{Fore.GREEN}Cache cleared successfully{Style.RESET_ALL}")
        else:
            self.cache = None
            logger.info(f"{Fore.YELLOW}Caching disabled{Style.RESET_ALL}")

    async def scan(self) -> Dict:
        """
        Execute the full vulnerability scan.
        
        Returns:
            Dict: Scan results
        """
        logger.info(f"{Fore.GREEN}Starting scan against '{self.target_url}{Style.RESET_ALL}'")
        
        # Step 1: Validate target
        if not await self.validate_target():
            logger.error(f"{Fore.RED}Invalid target URL: {self.target_url}{Style.RESET_ALL}")
            return {"error": "Invalid target URL"}
            
        # Step 2: Perform reconnaissance
        logger.info(f"{Fore.BLUE}Starting reconnaissance phase...{Style.RESET_ALL}")
        await self.reconnaissance()

        # If advanced recon only mode is enabled, skip vulnerability scanning
        if self.options.get("advanced_recon_only", False):
            logger.info(f"{Fore.YELLOW}Running in advanced reconnaissance only mode{Style.RESET_ALL}")
            await self.advanced_recon()
            return
        
        # Step 3: Crawl and identify endpoints
        logger.info(f"{Fore.BLUE}Crawling website for endpoints...{Style.RESET_ALL}")
        await self.crawl_site()
        
        # Step 4: Detect technologies
        logger.info(f"{Fore.BLUE}Detecting technologies...{Style.RESET_ALL}")
        await self.detect_technologies()
        
        # Step 5: Run vulnerability tests
        logger.info(f"{Fore.BLUE}Starting vulnerability scanning...{Style.RESET_ALL}")
        await self.run_vulnerability_scans()
        
        # Step 6: Generate reports
        logger.info(f"{Fore.BLUE}Generating reports...{Style.RESET_ALL}")
        self.generate_reports()
        
        logger.info(f"{Fore.GREEN}Scan completed successfully.{Style.RESET_ALL}")
        return self.results
        
    async def validate_target(self) -> bool:
        """
        Validate that the target URL is accessible.
        
        Returns:
            bool: True if target is valid, False otherwise
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, headers=self.headers, timeout=10) as response:
                    return 200 <= response.status < 400
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Error validating target: {e}")
            return False
        
    async def advanced_recon(self):
        """If advanced recon only mode is enabled, skip vulnerability scanning"""
        recon_options = self.options.copy()

        # If no specific recon modules selected, prompt user or use all
        if not any([
            self.options.get("recon_network"),
            self.options.get("recon_security"),
            self.options.get("recon_webapp"),
            self.options.get("recon_infrastructure"),
            self.options.get("recon_misc"),
            self.options.get("recon_all")
        ]):

            # Interactive prompt
            logger.info(f"{Fore.CYAN}No specific recon modules selected. Choose modules:{Style.RESET_ALL}")
            print("1. Network Infrastructure Analysis")
            print("2. Security Infrastructure Analysis")
            print("3. Web Application Analysis")
            print("4. Infrastructure Relationship Mapping")
            print("5. Miscellaneous Analysis")
            print("6. All modules")
            print("Enter module numbers separated by commas (e.g., 1,3,5) or press Enter for all:")
            
            try:
                user_input = input("> ").strip()
                if not user_input:
                    recon_options["recon_all"] = True
                else:
                    selections = [int(x.strip()) for x in user_input.split(",")]
                    recon_options["recon_network"] = 1 in selections
                    recon_options["recon_security"] = 2 in selections
                    recon_options["recon_webapp"] = 3 in selections
                    recon_options["recon_infrastructure"] = 4 in selections
                    recon_options["recon_misc"] = 5 in selections
                    recon_options["recon_all"] = 6 in selections
            except (ValueError, EOFError):
                logger.warning("Invalid input, running all modules")
                recon_options["recon_all"] = True
        
        recon_manager = ReconManager(self.target_url, recon_options)

        try:
            # Run only selected reconnaissance modules
            recon_results = {}
            
            if recon_options.get("recon_all"):
                logger.info("Running all reconnaissance modules...")
                recon_results = await recon_manager.run_reconnaissance()
            else:
                # Run individual modules based on selection
                if recon_options.get("recon_network"):
                    logger.info("Running network infrastructure analysis...")
                    recon_results["network"] = await recon_manager.network_analyzer.analyze()
                    
                if recon_options.get("recon_security"):
                    logger.info("Running security infrastructure analysis...")
                    recon_results["security"] = await recon_manager.security_analyzer.analyze()
                    
                if recon_options.get("recon_webapp"):
                    logger.info("Running web application analysis...")
                    recon_results["webapp"] = await recon_manager.webapp_analyzer.analyze()
                    
                if recon_options.get("recon_infrastructure"):
                    logger.info("Running infrastructure relationship mapping...")
                    recon_results["infrastructure"] = await recon_manager.infra_mapper.analyze()
                    
                if recon_options.get("recon_misc"):
                    logger.info("Running miscellaneous analysis...")
                    recon_results["miscellaneous"] = await recon_manager.misc_analyzer.analyze()
            
            # Store results
            self.results["reconnaissance"] = recon_results
            recon_manager.log_recon_findings(recon_results)
            
        except Exception as e:
            logger.error(f"{Fore.RED}Reconnaissance failed: {str(e)}{Style.RESET_ALL}")
            self.results["reconnaissance"]["error"] = str(e)

        # Generate reports with recon data only
        self.generate_reports()
        logger.info(f"{Fore.GREEN}Advanced reconnaissance completed successfully.{Style.RESET_ALL}")
        return self.results
        
    async def reconnaissance(self) -> None:
        """Perform reconnaissance on the target."""
        # Extract hostname from URL
        from urllib.parse import urlparse
        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.netloc
        
        # DNS lookup
        dns_results = {}
        try:
            # A records
            a_records = dns.resolver.resolve(hostname, 'A')
            dns_results['A'] = [r.address for r in a_records]
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(hostname, 'MX')
                dns_results['MX'] = [str(r.exchange) for r in mx_records]
            except dns.resolver.NoAnswer:
                dns_results['MX'] = []
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(hostname, 'NS')
                dns_results['NS'] = [str(r) for r in ns_records]
            except dns.resolver.NoAnswer:
                dns_results['NS'] = []
                
            # TXT records
            try:
                txt_records = dns.resolver.resolve(hostname, 'TXT')
                dns_results['TXT'] = [str(r) for r in txt_records]
            except dns.resolver.NoAnswer:
                dns_results['TXT'] = []
                
            self.results["reconnaissance"]["dns"] = dns_results
            logger.info(f"DNS lookup completed: Found {len(dns_results['A'])} IP addresses")
            
        except dns.resolver.NXDOMAIN:
            logger.error(f"DNS lookup error: Domain {hostname} does not exist")
            self.results["reconnaissance"]["dns"] = {"error": "Domain does not exist"}
            return
            
        # Port scanning
        if self.options.get("port_scan", False):
            logger.info("Starting port scan...")
            nm = PortScanner()
            ip = dns_results['A'][0]  # Use the first IP from DNS results
            
            # Scan top 1000 ports
            nm.scan(ip, '1-1000', arguments='-T4 -A')
            
            port_results = {}
            for proto in nm[ip].all_protocols():
                ports = sorted(nm[ip][proto].keys())
                for port in ports:
                    service = nm[ip][proto][port]
                    port_results[port] = {
                        "state": service["state"],
                        "service": service["name"],
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                    }
            
            self.results["reconnaissance"]["ports"] = port_results
            logger.info(f"Port scan completed: Found {len(port_results)} open ports")
            
        # WAF detection
        logger.info("Detecting WAF...")
        try:
            waf_detector = WAFW00F()
            waf_results = waf_detector.identwaf(self.target_url)
            # WAFW00F returns a tuple of (name, manufacturer), convert to dict
            waf_info = {
                "detected": bool(waf_results[0]),  # If name is present, WAF is detected
                "name": waf_results[0] or "None",
                "manufacturer": waf_results[1] or "Unknown"
            }
            self.results["reconnaissance"]["waf"] = waf_info
            if waf_info["detected"]:
                logger.info(f"WAF detected: {waf_info['name']} (by {waf_info['manufacturer']})")
            else:
                logger.info("No WAF detected")
        except Exception as e:
            logger.error(f"WAF detection error: {e}")
            self.results["reconnaissance"]["waf"] = {"error": str(e)}
    
    async def crawl_site(self) -> None:
        """Crawl the target site and identify endpoints."""
        crawler = WebCrawler(
            self.target_url, 
            headers=self.headers,
            max_depth=self.options.get("crawl_depth", 3),
            timeout=self.options.get("timeout", 10),
            use_selenium=self.options.get("use_selenium", False),
            max_pages=self.options.get("max_crawl_pages", 1000)
        )
        
        # Use set with maximum size to prevent memory overflow
        max_endpoints = 10000
        endpoints_seen = set()

        with tqdm(desc="Crawling website", unit="pages") as pbar:
            async for url, status_code in crawler.crawl():
                if len(endpoints_seen) >= max_endpoints:
                    logger.warning(f"Reached maximum endpoint limit {max_endpoints}")
                    break
                endpoints_seen.add(url)
                pbar.update(1)

        # Store prioritized subset if too many
        if len(endpoints_seen) > max_endpoints:
            # Prioritize by likelihood of containing vulnerabilities
            prioritized = crawler.prioritize_endpoints(list(endpoints_seen))
            self.results["endpoints"] = prioritized[:max_endpoints]
            logger.info(f"Prioritized {len(self.results['endpoints'])} endpoints from {len(endpoints_seen)} found")
        else:
            self.results["endpoints"] = list(endpoints_seen)        
            logger.info(f"Crawling completed: Found {len(self.results['endpoints'])} endpoints")
    
    async def detect_technologies(self) -> None:
        """Detect technologies used by the target website."""
        tech_detector = TechDetector()
        self.results["technologies"] = await tech_detector.detect(
            self.target_url, 
            headers=self.headers
        )
        
        logger.info(f"Technology detection completed: {', '.join(self.results['technologies'].keys())}")
    
    async def run_vulnerability_scans(self) -> None:
        """Run all selected vulnerability scans."""
        scanners = []
        
        # Initialize selected scanners
        if self.options.get("scan_sqli", True):
            scanners.append(SQLInjectionScanner(
                headers=self.headers,
                timeout=self.options.get("timeout", 10)
            ))
            
        if self.options.get("scan_xss", True):
            scanners.append(XSSScanner(
                headers=self.headers,
                timeout=self.options.get("timeout", 10)
            ))
            
        if self.options.get("scan_csrf", True):
            scanners.append(CSRFScanner(
                headers=self.headers,
                timeout=self.options.get("timeout", 10)
            ))
            
        if self.options.get("scan_ssrf", True):
            scanners.append(SSRFScanner(
                headers=self.headers,
                timeout=self.options.get("timeout", 10)
            ))
            
        if self.options.get("scan_path_traversal", True):
            scanners.append(PathTraversalScanner(
                headers=self.headers,
                timeout=self.options.get("timeout", 10)
            ))
            
        if self.options.get("scan_file_inclusion", True):
            scanners.append(FileInclusionScanner(
                headers=self.headers,
                timeout=self.options.get("timeout", 10)
            ))
            
        if self.options.get("scan_command_injection", True):
            scanners.append(CommandInjectionScanner(
                headers=self.headers,
                timeout=self.options.get("timeout", 10)
            ))
        
        # Run each scanner on all endpoints
        all_vulnerabilities = []
        batch_size = 100
        
        for scanner in scanners:
            scanner_name = scanner.__class__.__name__
            logger.info(f"Running {scanner_name}...")
            
            with tqdm(total=len(self.results["endpoints"]), 
                     desc=f"Running {scanner.__class__.__name__}".lower(), 
                     unit="endpoints") as pbar:
                     
                 # Process endpoints in batches
                for i in range(0, len(self.results["endpoints"]), batch_size):
                    batch = self.results["endpoints"][i:i + batch_size]
                
                    # Create tasks for this batch
                    tasks = []
                    for endpoint in batch:
                        # Check cache only if caching is enabled
                        cached_result = None
                        cache_key = None
                        if self.cache is not None:
                            cache_key = self.cache.generate_key(scanner_name, endpoint)

                        cached_result = self.cache.get(cache_key)
                        if cached_result is not None:
                            pbar.update(1)
                            pbar.set_postfix(cached="yes")
                            if cached_result:
                                self.results["vulnerabilities"].extend(cached_result)
                        else:
                            tasks.append((endpoint, scanner.scan(endpoint), cache_key))

                    # Run tasks concurrently with a limit
                     # Run uncached scans
                    if tasks:
                        endpoints, scan_tasks, cache_keys = zip(*tasks)
                        results = await self.run_concurrently(scan_tasks, self.max_workers)
                        
                        for endpoint, result, cache_key in zip(endpoints, results, cache_keys):
                            if not isinstance(result, Exception) and result:
                                # Cache result if caching is enabled
                                if self.cache is not None and cache_key is not None:
                                    self.cache.set(cache_key, result, ttl=3600)
                                self.results["vulnerabilities"].extend(result)
                            
                            pbar.update(1)
                            pbar.set_postfix(
                                cached="no",
                                found=len(self.results["vulnerabilities"])
                            )
                    # Process results
                    for result in results:
                        if result and not isinstance(result, Exception):
                            all_vulnerabilities.extend(result)
                    pbar.update(len(batch))

        # Log cache statistics
        if self.cache is not None:
            stats = self.cache.get_stats()
            logger.info(f"Cache statistics: {stats}")
                    
        # Validate findings
        logger.info("Validating findings...")
        validated_vulns = await self.validate_findings(all_vulnerabilities)
        
        # Store results
        self.results["vulnerabilities"] = validated_vulns
        
        # Save to database if enabled
        if self.db:
            for vuln in validated_vulns:
                self.db.add_vulnerability(
                    target=self.target_url,
                    vulnerability_type=vuln["type"],
                    endpoint=vuln["endpoint"],
                    severity=vuln["severity"],
                    description=vuln["description"],
                    evidence=vuln["evidence"],
                    remediation=vuln["remediation"]
                )
                
        logger.info(f"Vulnerability scanning completed: Found {len(validated_vulns)} vulnerabilities")
    
    async def validate_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Validate vulnerability findings to reduce false positives.
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            List[Dict]: Validated vulnerabilities
        """
        validated = []
        
        for vuln in vulnerabilities:
            # Basic validation: re-test the vulnerability
            scanner_class = None
            
            if vuln["type"] == "SQL Injection":
                scanner_class = SQLInjectionScanner
            elif vuln["type"] == "XSS":
                scanner_class = XSSScanner
            elif vuln["type"] == "CSRF":
                scanner_class = CSRFScanner
            elif vuln["type"] == "SSRF":
                scanner_class = SSRFScanner
            elif vuln["type"] == "Path Traversal":
                scanner_class = PathTraversalScanner
            elif vuln["type"] == "File Inclusion":
                scanner_class = FileInclusionScanner
            elif vuln["type"] == "Command Injection":
                scanner_class = CommandInjectionScanner
                
            if scanner_class:
                scanner = scanner_class(
                    headers=self.headers,
                    timeout=self.options.get("timeout", 10)
                )
                
                # Perform a focused test on the specific endpoint with payload
                try:
                    validation_result = await scanner.validate(
                        url=vuln["endpoint"],
                        payload=vuln.get("payload", ""),
                        evidence=vuln.get("evidence", "")
                    )
                    
                    if validation_result:
                        validated.append(vuln)
                        
                except Exception as e:
                    logger.warning(f"Validation error for {vuln['type']} at {vuln['endpoint']}: {e}")
            else:
                # If we don't have a validation method, include it anyway
                validated.append(vuln)
                
        return validated
    
    async def run_concurrently(self, tasks, max_workers):
        """Run async tasks concurrently with a worker limit."""
        results = []
        semaphore = asyncio.Semaphore(max_workers)
        
        async def worker(task):
            async with semaphore:
                return await task
                
        results = await asyncio.gather(
            *[worker(task) for task in tasks],
            return_exceptions=True
        )
        
        # Filter out exceptions
        return [r for r in results if not isinstance(r, Exception)]
    
    def generate_reports(self) -> None:
        """Generate scan reports in different formats."""
        report_gen = ReportGenerator(
            title=f"Vulnerability Scan Report for {self.target_url}",
            output_dir=self.output_dir
        )
        
        # Create report object
        report = Report(
            target=self.target_url,
            scan_time=self.results["scan_time"],
            vulnerabilities=self.results["vulnerabilities"],
            reconnaissance=self.results["reconnaissance"],
            endpoints=self.results["endpoints"],
            technologies=self.results["technologies"]
        )
        
        # Generate HTML report
        if self.options.get("html_report", True):
            html_path = report_gen.generate_html_report(report)
            logger.info(f"HTML report generated: {html_path}")
            
        # Generate PDF report  
        if self.options.get("pdf_report", True):
            pdf_path = report_gen.generate_pdf_report(report)
            logger.info(f"PDF report generated: {pdf_path}")
            
        # Generate JSON report
        if self.options.get("json_report", True):
            json_path = report_gen.generate_json_report(report)
            logger.info(f"JSON report generated: {json_path}")
            
        # Generate Excel report
        if self.options.get("excel_report", False):
            excel_path = report_gen.generate_excel_report(report)
            logger.info(f"Excel report generated: {excel_path}")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VulnScan - Web Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Target options
    parser.add_argument("url", nargs='?', help="Target URL to scan")
    parser.add_argument("--cookies", help="Cookies to include with HTTP requests")
    parser.add_argument("--user-agent", default="VulnScan/1.0", help="User-Agent string")

    parser.add_argument("--gui", action="store_true", help="Launch graphical user interface")

    # Scan options
    parser.add_argument("--crawl-depth", type=int, default=3, help="Maximum crawl depth")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--max-workers", type=int, default=5, help="Maximum concurrent workers")
    parser.add_argument("--use-selenium", action="store_true", help="Use Selenium for JavaScript rendering")
    parser.add_argument("--max-crawl-pages", type=int, default=1000, help="Maximum number of pages to crawl")

    # Feature toggles
    parser.add_argument("--port-scan", action="store_true", help="Perform port scanning")
    parser.add_argument("--no-sqli", action="store_true", help="Skip SQL injection scanning")
    parser.add_argument("--no-xss", action="store_true", help="Skip XSS scanning")
    parser.add_argument("--no-csrf", action="store_true", help="Skip CSRF scanning")
    parser.add_argument("--no-ssrf", action="store_true", help="Skip SSRF scanning")
    parser.add_argument("--no-path-traversal", action="store_true", help="Skip path traversal scanning")
    parser.add_argument("--no-file-inclusion", action="store_true", help="Skip file inclusion scanning")
    parser.add_argument("--no-command-injection", action="store_true", help="Skip command injection scanning")
    
    # Recon options
    parser.add_argument("--advanced-recon-only", action="store_true", help="Perform recon only, skip vulnerabilty scanning")
    parser.add_argument("--recon-network", action="store_true", help="Enable network infrastructure analysis")
    parser.add_argument("--recon-security", action="store_true", help="Enable security infrastructure analysis")
    parser.add_argument("--recon-webapp", action="store_true", help="Enable web application analysis")
    parser.add_argument("--recon-infrastructure", action="store_true", help="Enable infrastructure relationship mapping")
    parser.add_argument("--recon-misc", action="store_true", help="Enable miscellaneous analysis")
    parser.add_argument("--recon-all", action="store_true", help="Enable all reconnaissance modules")

     # Recon sub-option toggles
    # Network analysis options
    parser.add_argument("--no-advanced-port-scan", action="store_true", help="Skip portscan during advanced recon")
    parser.add_argument("--no-waf-detect", action="store_true", help="Skip firewall detection")
    parser.add_argument("--no-detect-load-balancers", action="store_true", help="Skip check for load balancers")
    parser.add_argument("--no-service-detection", action="store_true", help="Skip service detection on open ports")
    parser.add_argument("--no-os-detection", action="store_true", help="Skip target OS detection")
    parser.add_argument("--no-script-scan", action="store_true", help="Skip nmap script scan")
    # Web application analysis options
    parser.add_argument("--no-content-discovery", action="store_true", help="Skip content discovery")
    parser.add_argument("--no-js-analysis", action="store_true", help="Skip javascript content analysis")
    parser.add_argument("--dir-enum", action="store_true", help="List app directories")
    # Infrastructure mapping options
    parser.add_argument("--no-subdomain-enum", action="store_true", help="Skip check for sub-domains")
    parser.add_argument("--no-cloud-mapping", action="store_true", help="Skip cloud infrastructure mappng")
    parser.add_argument("--no-dns-bruteforce", action="store_true", help="Skip DNS bruteforce")
    # Security analysis options
    parser.add_argument("--no-ssl-analysis", action="store_true", help="Skip ssl security config analysis")
    parser.add_argument("--no-security-headers", action="store_true", help="Skip security header config analysis")
    # Misc options
    parser.add_argument("--no-error-analysis", action="store_true", help="Skip error codes analysis")
    parser.add_argument("--no-cache-analysis", action="store_true", help="Skip cache config analysis")
    parser.add_argument("--no-debug-mode-check", action="store_true", help="Skip check if debug mode being enabled")
    parser.add_argument("--no-check-dev-artifacts", action="store_true", help="Skip check for dev artifacts")
    parser.add_argument("--no-backend-tests", action="store_true", help="Skip backend tests")
    
    # Output options
    parser.add_argument("--output-dir", default="scan_results", help="Output directory for reports")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF report generation")
    parser.add_argument("--no-json", action="store_true", help="Skip JSON report generation")
    parser.add_argument("--excel", action="store_true", help="Generate Excel report ")
    
    # Database options
    parser.add_argument("--use-db", action="store_true", help="Store results in SQLite database")
    parser.add_argument("--db-path", default="vulnscan.db", help="Path to SQLite database")
    
    # Cache options
    parser.add_argument("--cache-dir", default="cache", help="Directory for caching results")
    parser.add_argument("--cache-ttl", type=int, default=3600, help="Cache time-to-live in seconds")
    parser.add_argument("--no-cache", action="store_true", help="Disable result caching")
    parser.add_argument("--clear-cache", action="store_true", help="Clear cache before scanning")
    args = parser.parse_args()

    if args.url is None:
        show_usage_examples()
        sys.exit(0)

    return args 


def show_usage_examples():
    """Display usage examples when no arguments are provided."""
    print(f"""
            {Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
            ║                           VULNSCAN                                    ║
            ╚═══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

            {Fore.YELLOW}USAGE:{Style.RESET_ALL}
                python vulnscan.py <URL> [OPTIONS]

            {Fore.YELLOW}BASIC EXAMPLES:{Style.RESET_ALL}

            {Fore.GREEN}Quick Scan:{Style.RESET_ALL}
                python vulnscan.py https://example.com

            {Fore.GREEN}Run Scan From GUI:{Style.RESET_ALL}
                python vulnscan.py  https://example.com --gui

            {Fore.GREEN}Basic Authenticated Scan:{Style.RESET_ALL}
                python vulnscan.py https://app.example.com --cookies "session=abc123"

            {Fore.GREEN}Comprehensive Security Assessment:{Style.RESET_ALL}
                python vulnscan.py https://example.com \\
                    --crawl-depth 4 \\
                    --port-scan \\
                    --use-selenium \\
                    --timeout 20 \\
                    --max-workers 8 \\
                    --use-db \\
                    --db-path ./scans.db \\
                    --cache-dir ./cache \\
                    --cache-ttl 7200 \\
                    --excel

            {Fore.YELLOW}PERFORMANCE TUNING:{Style.RESET_ALL}

            {Fore.GREEN}For Slow Sites:{Style.RESET_ALL}
                python vulnscan.py https://slow-site.com --timeout 30 --max-workers 2

            {Fore.GREEN}For Fast Sites:{Style.RESET_ALL}
                python vulnscan.py https://fast-site.com --timeout 5 --max-workers 15

            {Fore.YELLOW}TARGETED SCANNING:{Style.RESET_ALL}

            {Fore.GREEN}SQL Injection and XSS Only:{Style.RESET_ALL}
                python vulnscan.py https://example.com \\
                    --no-csrf --no-ssrf --no-path-traversal \\
                    --no-file-inclusion --no-command-injection \\
                    --clear-cache

            {Fore.GREEN}Skip Vulnerability Scanning (Recon Only):{Style.RESET_ALL}
                python vulnscan.py https://example.com \\
                    --advanced-recon-only 
            
            {Fore.GREEN}Specific Reconnaissance Modules:{Style.RESET_ALL}
                python vulnscan.py https://example.com \\
                    --advanced-recon-only \\
                    --recon-network --recon-security

            {Fore.GREEN}All Reconnaissance Modules:{Style.RESET_ALL}
                python vulnscan.py https://example.com \\
                    --advanced-recon-only --recon-all --clear-cache --cache-dir ./recon_cache

            {Fore.YELLOW}ADVANCED OPTIONS:{Style.RESET_ALL}

            {Fore.GREEN}Custom Output Directory:{Style.RESET_ALL}
                python vulnscan.py https://example.com --output-dir ./my_scan_results

            {Fore.GREEN}Disable Caching:{Style.RESET_ALL}
                python vulnscan.py https://example.com --clear-cache --no-cache

            {Fore.GREEN}Clear Cache Before Scan (but use cache during scan):{Style.RESET_ALL}
                python vulnscan.py https://example.com --clear-cache

            {Fore.GREEN}Different Report Formats:{Style.RESET_ALL}
                python vulnscan.py https://example.com --no-pdf --excel --no-html

            {Fore.GREEN}Database Storage:{Style.RESET_ALL}
                python vulnscan.py https://example.com --use-db --db-path ./my_scans.db

            {Fore.YELLOW}HELP:{Style.RESET_ALL}
                python vulnscan.py --help      # Show all available options

            {Fore.CYAN}For detailed documentation, visit: https://github.com/MykeChidi/Vulnscan{Style.RESET_ALL}
            """)

def launch_gui(prefill_url=None):
    """Launch the GUI application"""
    try:
        import tkinter as tk
        from gui import VulnScanGUI
        
        root = tk.Tk()
        app = VulnScanGUI(root)
        
        if prefill_url:
            app.url_entry.delete(0, tk.END)
            app.url_entry.insert(0, prefill_url)

        # Center window on screen
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')
        
        root.mainloop()
    except Exception as e:
        print(f"{Fore.RED}Error: Unable to launch GUI{Style.RESET_ALL}")
        print(f"Error details: {e}")
        sys.exit(1)

async def main():
    """Main Vulnscan function."""
    # Parse arguments
    args = parse_arguments()

    # Launch GUI if specified
    if args.gui:
        launch_gui(prefill_url=args.url)
        return

    # Convert arguments to options dictionary
    options = {
        # Target options
        "user_agent": args.user_agent,
        "cookies": args.cookies,
        # Scan options
        "crawl_depth": args.crawl_depth,
        "timeout": args.timeout,
        "max_workers": args.max_workers,
        "use_selenium": args.use_selenium,
        "max_crawl_pages":args.max_crawl_pages,
        "port_scan": args.port_scan,
        # Recon options
        "advanced_recon_only": args.advanced_recon_only,
        "recon_network": args.recon_network,
        "recon_security": args.recon_security,
        "recon_webapp": args.recon_webapp,
        "recon_infrastructure": args.recon_infrastructure,
        "recon_misc": args.recon_misc,
        "recon_all": args.recon_all,
        # Features toggles
        "scan_sqli": not args.no_sqli,
        "scan_xss": not args.no_xss,
        "scan_csrf": not args.no_csrf,
        "scan_ssrf": not args.no_ssrf,
        "scan_path_traversal": not args.no_path_traversal,
        "scan_file_inclusion": not args.no_file_inclusion,
        "scan_command_injection": not args.no_command_injection,
        # Network analysis options
        "advanced_port_scan":  not args.no_advanced_port_scan,
        "detect_waf": not args.no_waf_detect,
        "detect_load_balancers": not args.no_detect_load_balancers,
        "service_detection": not args.no_service_detection,
        "os_detection": not args.no_os_detection,
        "script_scan": not args.no_script_scan,
        # Web application analysis options
        "content_discovery": not args.no_content_discovery,
        "js_analysis": not args.no_js_analysis,
        "dir_enum": args.dir_enum,
        # Infrastructure mapping options
        "subdomain_enum":  not args.no_subdomain_enum,
        "cloud_mapping": not args.no_cloud_mapping,
        "dns_bruteforce": not args.no_dns_bruteforce,
        # Security analysis options
        "ssl_analysis": not args.no_ssl_analysis,
        "security_headers": not args.no_security_headers,
        # Misc options
        "error_analysis": not args.no_error_analysis,
        "cache_analysis": not args.no_cache_analysis,
        "check_debug_mode": not args.no_debug_mode_check,
        "check_dev_artifacts": not args.no_check_dev_artifacts,
        "Backend_tests": not args.no_backend_tests,
        # Cache options
        "cache_dir": args.cache_dir,
        "cache_ttl": args.cache_ttl,
        "no_cache": args.no_cache,
        "clear_cache": args.clear_cache,
        # Report options
        "output_dir": args.output_dir,
        "html_report": not args.no_html,
        "pdf_report": not args.no_pdf,
        "json_report": not args.no_json,
        "excel_report": args.excel,
        # Database options
        "use_db": args.use_db,
        "db_path": args.db_path,
    }
    
    # Initialize scanner
    scanner = VulnerabilityScanner(args.url, options)
    
    # Run scan
    results = await scanner.scan()
    
    # Print summary
    if not results.get("error"):
        print(f"\n{Fore.GREEN}Scan completed successfully!{Style.RESET_ALL}")
        print(f"Target: {results['target']}")
        print(f"Scan time: {results['scan_time']}")
        print(f"Endpoints discovered: {len(results['endpoints'])}")
        print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
        
        if results['vulnerabilities']:
            print("\nVulnerability Summary:")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                severity_color = Fore.RED if vuln['severity'] == 'High' else \
                                Fore.YELLOW if vuln['severity'] == 'Medium' else Fore.BLUE
                print(f"{i}. {severity_color}{vuln['type']} ({vuln['severity']}){Style.RESET_ALL} at {vuln['endpoint']}")
        
        print(f"\nReports saved to: {Path(options['output_dir']).absolute()}")
    else:
        print(f"\n{Fore.RED}Scan failed: {results['error']}{Style.RESET_ALL}")
    

if __name__ == "__main__":
    # Run the main function
    asyncio.run(main())
