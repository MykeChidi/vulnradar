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
            self.results["reconnaissance"]["waf"] = waf_results
            if waf_results.get("detected"):
                logger.info(f"WAF detected: {waf_results.get('name', 'Unknown')}")
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
            use_selenium=self.options.get("use_selenium", False)
        )
        
        with tqdm(desc="Crawling website", unit="pages") as pbar:
            async for url, status_code in crawler.crawl():
                self.results["endpoints"].add(url)
                pbar.update(1)
                
        logger.info(f"Crawling completed: Found {len(self.results['endpoints'])} endpoints")
        
        # Convert set to list for JSON serialization
        self.results["endpoints"] = list(self.results["endpoints"])
    
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
        
        for scanner in scanners:
            logger.info(f"Running {scanner.__class__.__name__}...")
            
            with tqdm(total=len(self.results["endpoints"]), 
                     desc=f"Running {scanner.__class__.__name__}", 
                     unit="endpoints") as pbar:
                     
                # Create tasks for scanning each endpoint
                tasks = []
                for endpoint in self.results["endpoints"]:
                    tasks.append(scanner.scan(endpoint))
                    
                # Run tasks concurrently with a limit
                results = await self.run_concurrently(tasks, self.max_workers)
                
                # Process results
                for result in results:
                    if result:  # If vulnerabilities were found
                        all_vulnerabilities.extend(result)
                    pbar.update(1)
                    
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
        description="Web Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Target options
    parser.add_argument("url", nargs='?', help="Target URL to scan")
    parser.add_argument("--cookies", help="Cookies to include with HTTP requests")
    parser.add_argument("--user-agent", default="VulnScan/1.0", help="User-Agent string")
    
    # Scan options
    parser.add_argument("--crawl-depth", type=int, default=3, help="Maximum crawl depth")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--max-workers", type=int, default=5, help="Maximum concurrent workers")
    parser.add_argument("--use-selenium", action="store_true", help="Use Selenium for JavaScript rendering")
    
    # Feature toggles
    parser.add_argument("--port-scan", action="store_true", help="Perform port scanning")
    parser.add_argument("--no-sqli", action="store_true", help="Skip SQL injection scanning")
    parser.add_argument("--no-xss", action="store_true", help="Skip XSS scanning")
    parser.add_argument("--no-csrf", action="store_true", help="Skip CSRF scanning")
    parser.add_argument("--no-ssrf", action="store_true", help="Skip SSRF scanning")
    parser.add_argument("--no-path-traversal", action="store_true", help="Skip path traversal scanning")
    parser.add_argument("--no-file-inclusion", action="store_true", help="Skip file inclusion scanning")
    parser.add_argument("--no-command-injection", action="store_true", help="Skip command injection scanning")
    
    # Output options
    parser.add_argument("--output-dir", default="scan_results", help="Output directory for reports")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF report generation")
    parser.add_argument("--no-json", action="store_true", help="Skip JSON report generation")
    parser.add_argument("--excel", action="store_true", help="Generate Excel report ")
    
    # Database options
    parser.add_argument("--use-db", action="store_true", help="Store results in SQLite database")
    parser.add_argument("--db-path", default="vulnscan.db", help="Path to SQLite database")
    
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
                    --no-file-inclusion --no-command-injection

            {Fore.GREEN}Skip Vulnerability Scanning (Recon Only):{Style.RESET_ALL}
                python vulnscan.py https://example.com \\
                    --no-sqli --no-xss --no-csrf --no-ssrf \\
                    --no-path-traversal --no-file-inclusion --no-command-injection

            {Fore.YELLOW}ADVANCED OPTIONS:{Style.RESET_ALL}

            {Fore.GREEN}Custom Output Directory:{Style.RESET_ALL}
                python vulnscan.py https://example.com --output-dir ./my_scan_results

            {Fore.GREEN}Different Report Formats:{Style.RESET_ALL}
                python vulnscan.py https://example.com --no-pdf --excel --no-html

            {Fore.GREEN}Database Storage:{Style.RESET_ALL}
                python vulnscan.py https://example.com --use-db --db-path ./my_scans.db

            {Fore.YELLOW}HELP:{Style.RESET_ALL}
                python vulnscan.py --help      # Show all available options

            {Fore.CYAN}For detailed documentation, visit: https://github.com/MykeChidi/Vulnscan{Style.RESET_ALL}
            """)


async def main():
    """Main Vulnscan function."""
    # Parse arguments
    args = parse_arguments()

    # Convert arguments to options dictionary
    options = {
        "user_agent": args.user_agent,
        "cookies": args.cookies,
        "crawl_depth": args.crawl_depth,
        "timeout": args.timeout,
        "max_workers": args.max_workers,
        "use_selenium": args.use_selenium,
        "port_scan": args.port_scan,
        "scan_sqli": not args.no_sqli,
        "scan_xss": not args.no_xss,
        "scan_csrf": not args.no_csrf,
        "scan_ssrf": not args.no_ssrf,
        "scan_path_traversal": not args.no_path_traversal,
        "scan_file_inclusion": not args.no_file_inclusion,
        "scan_command_injection": not args.no_command_injection,
        "output_dir": args.output_dir,
        "html_report": not args.no_html,
        "pdf_report": not args.no_pdf,
        "json_report": not args.no_json,
        "excel_report": args.excel,
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
