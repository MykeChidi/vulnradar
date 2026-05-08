#!/usr/bin/env python3
# vulnradar/core.py - Main entry point for the Web Vulnerability Scanner

import asyncio
import time
from functools import partial
from typing import Any, Dict, List, Optional, Set

import aiohttp
import colorama
import dns.resolver
from colorama import Fore, Style
from nmap import PortScanner
from tqdm import tqdm
from wafw00f.main import WAFW00F

from .context import ScanContext

# Import custom modules
from .crawlers import WebCrawler
from .detector import TechDetector
from .models.finding import Finding
from .recon import ReconManager
from .scanners.base import BaseScanner
from .scanners.registry import FINDING_TYPE_REGISTRY, SCANNER_REGISTRY
from .utils.cache import ScanCache
from .utils.db import VulnradarDatabase
from .utils.error_handler import (
    NetworkError,
    ScanError,
    ValidationError,
    get_global_error_handler,
    handle_async_errors,
)
from .utils.logger import setup_logger
from .utils.reporter import Report, ReportGenerator
from .utils.validator import Validator

# Initialize colorama
colorama.init()

# Setup logger
logger = setup_logger("vulnradar")

# Setup error handler
error_handler = get_global_error_handler()


class VulnRadar:
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
        self.results: Dict[str, Any] = {
            "target": target_url,
            "scan_time": time.strftime("%d-%m-%Y %H:%M:%S"),
            "vulnerabilities": [],
            "reconnaissance": {},
            "endpoints": [],
            "technologies": {},
        }

        try:
            Validator.validate_url(self.target_url)
        except ValueError as err:
            error_handler.handle_error(
                ValidationError(f"Invalid target URL: {str(err)}", original_error=err),
                context={"target_url": self.target_url},
            )
            raise

        # Headers for HTTP requests
        self.headers = {
            "User-Agent": Validator.validate_header_value(
                options.get("user_agent", "VulnRadar/1.0"), "User-Agent"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }

        if options.get("cookies"):
            self.headers["Cookie"] = Validator.validate_header_value(
                options["cookies"], "Cookie"
            )

        self.db: Optional[VulnradarDatabase] = None
        # Database connection
        if options.get("use_db", False):
            raw_db_path = options.get("db_path", "vulnradar.db")
            sanitized_db_path = Validator.sanitize_file_path(raw_db_path)
            if sanitized_db_path is None:
                error_handler.handle_error(
                    ValidationError(f"Invalid database path: {raw_db_path}"),
                    context={"db_path": raw_db_path},
                )
                raise ValueError(f"Invalid database path: {raw_db_path}")
            self.db = VulnradarDatabase(str(sanitized_db_path))
        else:
            self.db = None

        # Concurrency settings
        self.max_workers = options.get("max_workers", 5)

        # Create output directory if it doesn't exist
        self.output_dir = Validator.sanitize_file_path(
            options.get("output_dir", "scan_results")
        )
        self.output_dir.mkdir(exist_ok=True, mode=0o755)

        self.cache: Optional[ScanCache] = None
        # Initialize cache
        if not options.get("no_cache", False):
            raw_cache_dir = options.get("cache_dir", "vulnradar_cache")
            cache_dir = Validator.sanitize_file_path(raw_cache_dir)
            if cache_dir is None:
                logger.warning(
                    f"{Fore.YELLOW}Invalid cache directory path '{raw_cache_dir}', "
                    f"falling back to default.{Style.RESET_ALL}"
                )
                cache_dir = Validator.sanitize_file_path("vulnradar_cache")
            self.cache = ScanCache(
                cache_dir, default_ttl=options.get("cache_ttl", 3600)
            )
            # Clear cache if requested
            if options.get("clear_cache", False):
                logger.info(f"{Fore.YELLOW}Clearing cache...{Style.RESET_ALL}")
                self.cache.clear_all()
                logger.info(f"{Fore.GREEN}Cache cleared successfully{Style.RESET_ALL}")
        else:
            self.cache = None
            logger.info(f"{Fore.YELLOW}Caching disabled{Style.RESET_ALL}")

    def display_banner(self):
        """Show modern styled banner with colors."""
        R = Fore.RED
        G = Fore.GREEN
        Y = Fore.YELLOW
        C = Fore.CYAN
        W = Fore.WHITE
        # Gradient-like effect using different colors
        print(f"""
            {R}╔{'═'*79}╗
            {R}║{' '*79}║
            {R}║  {G}██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██████╗  █████╗ ██████╗  █████╗ ██████╗{R}  ║
            {R}║  {G}██║   ██║██║   ██║██║     ████╗  ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗{R} ║
            {R}║  {Y}██║   ██║██║   ██║██║     ██╔██╗ ██║██████╔╝███████║██║  ██║███████║██████╔╝{R} ║
            {R}║  {Y}╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗{R} ║
            {R}║   {C}╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║{R} ║
            {R}║    {C}╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝{R} ║
            {R}║{' '*79}║
            {R}║{W}{Style.BRIGHT}{' '*19}⚡ Web Security & Vulnerability Scanner ⚡{C}{' '*18}{R}║
            {R}║{' '*79}║
            {R}║{Y}{' '*24}[{W}*{Y}]{W} Scan {Y}|{W} Detect {Y}|{W} Report {Y}[{W}*{Y}]{' '*25}{R}║
            {R}║{' '*79}║
            {R}╚{'═'*79}╝{Style.RESET_ALL}
            """)

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Scan execution failed. Please verify the target URL and try again.",
        return_on_error={"error": True, "message": "Scan failed"},
    )
    async def scan(self) -> Dict:
        """
        Execute the full vulnerability scan.

        Returns:
            Dict: Scan results
        """
        logger.info(
            f"{Fore.GREEN}Starting scan against '{self.target_url}{Style.RESET_ALL}'"
        )

        # Step 1: Validate target
        if not await self.validate_target():
            logger.error(
                f"{Fore.RED}Invalid target URL: {self.target_url}{Style.RESET_ALL}"
            )
            return {"error": "Invalid target URL"}

        self.display_banner()

        # Step 2: Perform reconnaissance
        logger.info(
            f"{Fore.BLUE}Starting basic reconnaissance phase...{Style.RESET_ALL}"
        )
        await self.reconnaissance()

        # If advanced recon only mode is enabled, skip vulnerability scanning
        if self.options.get("recon_only", False):
            logger.info(
                f"{Fore.YELLOW}Running in advanced reconnaissance only mode{Style.RESET_ALL}"
            )
            await self.advanced_recon()
            return self.results

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

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Target validation failed.",
        return_on_error=False,
    )
    async def validate_target(self) -> bool:
        """
        Validate that the target URL is accessible.

        Returns:
            bool: True if target is valid, False otherwise
        """
        # Validate accessibility
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        connector = aiohttp.TCPConnector(limit=1)
        try:
            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get(
                    self.target_url, headers=self.headers, allow_redirects=False
                ) as response:
                    return 200 <= response.status < 400
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(f"Error validating target: {str(e)}", original_error=e),
                context={"target_url": self.target_url},
            )
            return False

    async def advanced_recon(self):
        """If advanced recon only mode is enabled, skip vulnerability scanning"""
        recon_options = self.options.copy()

        # If no specific recon modules selected, prompt user or use all
        if not any(
            [
                self.options.get("recon_network"),
                self.options.get("recon_security"),
                self.options.get("recon_webapp"),
                self.options.get("recon_infrastructure"),
                self.options.get("recon_misc"),
                self.options.get("recon_all"),
            ]
        ):

            # Interactive prompt
            logger.info(
                f"{Fore.CYAN}No specific recon modules selected. Choose modules:{Style.RESET_ALL}"
            )
            print("1. Network Infrastructure Analysis")
            print("2. Security Infrastructure Analysis")
            print("3. Web Application Analysis")
            print("4. Infrastructure Relationship Mapping")
            print("5. Miscellaneous Analysis")
            print("6. All modules")
            print(
                "Enter module numbers separated by commas (e.g., 1,3,5) or press Enter for all:"
            )

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
                    recon_results["network"] = (
                        await recon_manager.network_analyzer.analyze()
                    )

                if recon_options.get("recon_security"):
                    logger.info("Running security infrastructure analysis...")
                    recon_results["security"] = (
                        await recon_manager.security_analyzer.analyze()
                    )

                if recon_options.get("recon_webapp"):
                    logger.info("Running web application analysis...")
                    recon_results["webapp"] = (
                        await recon_manager.webapp_analyzer.analyze()
                    )

                if recon_options.get("recon_infrastructure"):
                    logger.info("Running infrastructure relationship mapping...")
                    recon_results["infrastructure"] = (
                        await recon_manager.infra_mapper.analyze()
                    )

                if recon_options.get("recon_misc"):
                    logger.info("Running miscellaneous analysis...")
                    recon_results["miscellaneous"] = (
                        await recon_manager.misc_analyzer.analyze()
                    )

            # Store results
            self.results["reconnaissance"] = recon_results
            recon_manager.log_recon_findings(recon_results)

        except Exception as e:
            error_info = error_handler.handle_error(
                ScanError(f"Reconnaissance failed: {str(e)}", original_error=e),
                context={"target_url": self.target_url},
            )
            self.results["reconnaissance"]["error"] = error_info["message"]

        # Generate reports with recon data only
        self.generate_reports()
        logger.info(
            f"{Fore.GREEN}Advanced reconnaissance completed successfully.{Style.RESET_ALL}"
        )
        return self.results

    async def reconnaissance(self) -> None:
        """Perform reconnaissance on the target."""
        # Extract hostname from URL
        from urllib.parse import urlparse

        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.netloc

        # DNS lookup
        dns_results = {}
        loop = asyncio.get_event_loop()
        try:
            # A records
            a_records = await loop.run_in_executor(
                None, partial(dns.resolver.resolve, hostname, "A")
            )
            dns_results["A"] = [
                str(r.address) for r in a_records if hasattr(r, "address")
            ]

            # MX records
            try:
                mx_records = await loop.run_in_executor(
                    None, partial(dns.resolver.resolve, hostname, "MX")
                )
                dns_results["MX"] = [
                    str(r.exchange) for r in mx_records if hasattr(r, "exchange")
                ]
            except dns.resolver.NoAnswer:
                dns_results["MX"] = []

            # NS records
            try:
                ns_records = loop.run_in_executor(
                    None, partial(dns.resolver.resolve, hostname, "NS")
                )
                dns_results["NS"] = [str(r) for r in ns_records]
            except dns.resolver.NoAnswer:
                dns_results["NS"] = []

            # TXT records
            try:
                txt_records = loop.run_in_executor(
                    None, partial(dns.resolver.resolve, hostname, "TXT")
                )
                dns_results["TXT"] = [str(r) for r in txt_records]
            except dns.resolver.NoAnswer:
                dns_results["TXT"] = []

            self.results["reconnaissance"]["dns"] = dns_results
            logger.info(
                f"DNS lookup completed: Found {len(dns_results['A'])} IP addresses"
            )

        except dns.resolver.NXDOMAIN:
            logger.error(f"DNS lookup error: Domain {hostname} does not exist")
            self.results["reconnaissance"]["dns"] = {"error": "Domain does not exist"}
        except dns.exception.DNSException as e:  # Catch DNS-specific errors
            logger.error(f"DNS Error: {str(e)}")
            return

        # Port scanning
        if self.options.get("port_scan", False):
            logger.info("Starting port scan...")
            nm = PortScanner()
            if not dns_results.get("A"):
                logger.warning("No A records found, skipping port scan")
                return
            ip = dns_results["A"][0]  # Use the first IP from DNS results

            # Validate and use configured port range (F-03: prevents nmap arg injection)
            port_range_raw = self.options.get("port_range", "1-1000")
            try:
                Validator.validate_port_range(port_range_raw)
                safe_port_range = port_range_raw
            except Exception:
                logger.warning(
                    f"Invalid port range '{port_range_raw}', defaulting to 1-1000"
                )
                safe_port_range = "1-1000"

            # Scan configured port range
            nm.scan(ip, safe_port_range, arguments="-T4 -A")

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
                "manufacturer": waf_results[1] or "Unknown",
            }
            self.results["reconnaissance"]["waf"] = waf_info
            if waf_info["detected"]:
                logger.info(
                    f"WAF detected: {waf_info['name']} (by {waf_info['manufacturer']})"
                )
            else:
                logger.info("No WAF detected")
        except Exception as e:
            error_info = error_handler.handle_error(
                ScanError(f"WAF detection error: {str(e)}", original_error=e),
                context={"target_url": self.target_url},
            )
            self.results["reconnaissance"]["waf"] = {"error": error_info["message"]}

    async def crawl_site(self) -> None:
        """Crawl the target site and identify endpoints."""
        crawler = WebCrawler(
            self.target_url,
            headers=self.headers,
            max_depth=self.options.get("crawl_depth", 3),
            timeout=self.options.get("timeout", 10),
            use_selenium=self.options.get("use_selenium", False),
            max_pages=self.options.get("max_crawl_pages", 1000),
        )

        # Use set with maximum size to prevent memory overflow
        max_endpoints = 10000
        endpoints_seen: Set[str] = set()

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
            logger.info(
                f"Prioritized {len(self.results['endpoints'])} endpoints from {len(endpoints_seen)} found"
            )
        else:
            self.results["endpoints"] = list(endpoints_seen)
            logger.info(
                f"Crawling completed: Found {len(self.results['endpoints'])} endpoints"
            )

    async def detect_technologies(self) -> None:
        """Detect technologies used by the target website."""
        tech_detector = TechDetector()
        detection_result = await tech_detector.detect(
            self.target_url, headers=self.headers
        )

        # Extract the technologies dict from DetectionResult object
        if hasattr(detection_result, "technologies"):
            # It's a DetectionResult dataclass
            self.results["technologies"] = detection_result.technologies
            logger.info(
                f"Technology detection completed: {', '.join(detection_result.technologies.keys())}"
            )
        elif isinstance(detection_result, dict):
            # It's already a dict (backward compat)
            self.results["technologies"] = detection_result
            logger.info(
                f"Technology detection completed: {', '.join(detection_result.keys())}"
            )
        else:
            # Fallback
            self.results["technologies"] = {}
            logger.warning(
                f"Unexpected detection result type: {type(detection_result)}"
            )

    async def run_vulnerability_scans(self) -> None:
        """Run all selected vulnerability scans."""
        scanners: List[BaseScanner] = []

        # Build the list of scanners from the registry.
        # Adding a new scanner only requires a line in registry.py — nothing here changes.
        timeout = self.options.get("timeout", 10)
        common_args = {"headers": self.headers, "timeout": timeout}

        scanners: List[BaseScanner] = [
            cls(**common_args)
            for option_key, cls in SCANNER_REGISTRY.items()
            if self.options.get(option_key, True)
        ]

        # Create a shared aiohttp.ClientSession for this scan phase.
        # All scanners receive it via attach_context() so no scanner
        # creates its own session.
        shared_session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=timeout, connect=5, sock_read=timeout),
        )

        # Build a lightweight ScanContext so scanners can access the session.
        from .scanners.target import ScanTarget

        scan_ctx = ScanContext(
            target=ScanTarget.from_url(self.target_url),
            options=self.options,
            session=shared_session,
            semaphore=asyncio.Semaphore(self.max_workers),
            rate_limiter=None,  # full RateLimiter wired up in Phase 6
            cache=self.cache,
        )
        # Seed endpoints from the crawl results already stored in self.results
        for ep in self.results.get("endpoints", []):
            scan_ctx.add_endpoint(ep)

        # Attach the shared context to every scanner
        for scanner in scanners:
            scanner.attach_context(scan_ctx)

        # ── Pre-scan discovery hook ───────────────────────────────────────
        # Duck-typed: scanners that don't need discovery simply don't have
        # the method and are skipped here.
        for scanner in scanners:
            if hasattr(scanner, "discover"):
                logger.info(f"Running discovery for {scanner.__class__.__name__}...")
                await scanner.discover(self.results["endpoints"])

        # Run each scanner on all endpoints
        all_raw: List = []
        batch_size = 100

        try:
            for scanner in scanners:
                scanner_name = scanner.__class__.__name__
                logger.info(f"Running {scanner_name}...")

                with tqdm(
                    total=len(self.results["endpoints"]),
                    desc=f"Running {scanner.__class__.__name__}".lower(),
                    unit="endpoints",
                ) as pbar:

                    for i in range(0, len(self.results["endpoints"]), batch_size):
                        batch = self.results["endpoints"][
                            i : i + batch_size
                        ]  # noqa: E203

                        tasks = []
                        for endpoint in batch:
                            cache_key = None

                            if self.cache is not None:
                                cache_key = self.cache.generate_key(
                                    scanner_name, endpoint
                                )
                                cached_result = self.cache.get(cache_key)
                                if cached_result is not None:
                                    if cached_result:
                                        all_raw.extend(cached_result)
                                    pbar.update(1)
                                    pbar.set_postfix(cached="yes")
                                    continue

                            tasks.append((endpoint, scanner.scan(endpoint), cache_key))

                        if tasks:
                            endpoints, scan_tasks, cache_keys = zip(*tasks)
                            results = await self.run_concurrently(
                                scan_tasks, self.max_workers
                            )

                            for endpoint, result, cache_key in zip(
                                endpoints, results, cache_keys
                            ):
                                if not isinstance(result, Exception) and result:
                                    if self.cache is not None and cache_key is not None:
                                        self.cache.set(cache_key, result, ttl=3600)
                                    all_raw.extend(result)

                                pbar.update(1)
                                pbar.set_postfix(cached="no", found=len(all_raw))

        finally:
            await shared_session.close()

        if self.cache is not None:
            stats = self.cache.get_stats()
            logger.info(f"Cache statistics: {stats}")

        all_vulnerabilities: List[Dict] = []
        for item in all_raw:
            if isinstance(item, Finding):
                all_vulnerabilities.append(item.to_dict())
            else:
                all_vulnerabilities.append(item)  # already a dict (unmigrated scanner)

        logger.info("Validating findings...")
        validated_vulns = await self.validate_findings(all_vulnerabilities)

        self.results["vulnerabilities"] = validated_vulns

        if self.db:
            for vuln in validated_vulns:
                self.db.add_vulnerability(
                    target=self.target_url,
                    vulnerability_type=vuln["type"],
                    endpoint=vuln["endpoint"],
                    severity=vuln["severity"],
                    description=vuln["description"],
                    evidence=vuln["evidence"],
                    remediation=vuln["remediation"],
                )

        logger.info(
            f"Vulnerability scanning completed: Found {len(validated_vulns)} vulnerabilities"
        )

    async def validate_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Re-test each finding to confirm it is not a false positive.

        Args:
            vulnerabilities: List of vulnerability findings

        Returns:
            List[Dict]: Validated vulnerabilities (false positives removed)
        """
        validated = []
        timeout = self.options.get("timeout", 10)
        common_args = {"headers": self.headers, "timeout": timeout}

        # One session shared across all validation calls in this method.
        validation_session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=timeout, connect=5, sock_read=timeout),
        )

        from .scanners.target import ScanTarget

        validation_ctx = ScanContext(
            target=ScanTarget.from_url(self.target_url),
            options=self.options,
            session=validation_session,
            semaphore=asyncio.Semaphore(self.max_workers),
            rate_limiter=None,
        )

        try:
            for vuln in vulnerabilities:
                vuln_type = vuln.get("type", "")
                scanner_class = FINDING_TYPE_REGISTRY.get(vuln_type)

                if scanner_class is None:
                    # No validator registered for this type — include it as-is
                    validated.append(vuln)
                    continue

                scanner = scanner_class(**common_args)
                scanner.attach_context(validation_ctx)

                try:
                    confirmed = await scanner.validate(
                        url=vuln.get("endpoint", ""),
                        payload=vuln.get("payload", ""),
                        evidence=vuln.get("evidence", ""),
                    )
                    if confirmed:
                        validated.append(vuln)

                except Exception as e:
                    error_handler.handle_error(
                        ScanError(
                            f"Validation error for {vuln_type} at "
                            f"{vuln.get('endpoint', '?')}: {str(e)}",
                            original_error=e,
                        ),
                        context={"vulnerability": vuln},
                    )
                    # On validation error, include the finding (conservative approach)
                    validated.append(vuln)

        finally:
            await validation_session.close()

        return validated

    async def run_concurrently(self, tasks, max_workers):
        """Run async tasks concurrently with a worker limit."""
        results = []
        semaphore = asyncio.Semaphore(max_workers)

        async def worker(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(
            *[worker(task) for task in tasks], return_exceptions=True
        )

        # Log exceptions for debugging, then filter them out
        for r in results:
            if isinstance(r, Exception):
                error_handler.handle_error(
                    ScanError(
                        f"Concurrent task failed: {str(r)}",
                        original_error=r,
                    ),
                    context={},
                )
        return [r for r in results if not isinstance(r, Exception)]

    def generate_reports(self) -> None:
        """Generate scan reports in different formats."""
        is_recon_only = self.options.get("recon_only", False)

        report_title = (
            "Reconnaissance Report" if is_recon_only else "Vulnerability Scan Report"
        )
        report_gen = ReportGenerator(
            title=f"{report_title} for {self.target_url}", output_dir=self.output_dir
        )

        # Create report object
        report = Report(
            target=self.target_url,
            scan_time=self.results["scan_time"],
            vulnerabilities=self.results["vulnerabilities"],
            reconnaissance=self.results["reconnaissance"],
            endpoints=self.results["endpoints"],
            technologies=self.results["technologies"],
            is_recon_only=is_recon_only,
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
