import argparse
import asyncio
import sys
from pathlib import Path

from colorama import Fore, Style

from .core import VulnRadar
from .multi_target import MultiTargetScanner
from .utils.error_handler import get_global_error_handler, handle_errors

# Setup error handler
error_handler = get_global_error_handler()


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VulnRadar - Web Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Target options
    parser.add_argument("url", nargs="?", help="Target URL to scan")
    parser.add_argument("--cookies", help="Cookies to include with HTTP requests")
    parser.add_argument(
        "--user-agent", default="VulnRadar/1.0", help="User-Agent string"
    )
    parser.add_argument(
        "--gui", action="store_true", help="Launch graphical user interface"
    )

    # Scan options
    scan_opt = parser.add_argument_group(
        "Scan Options", "Configure scan behaviour and performance"
    )
    scan_opt.add_argument(
        "--crawl-depth", type=int, default=3, help="Maximum crawl depth"
    )
    scan_opt.add_argument(
        "--timeout", type=int, default=10, help="Request timeout in seconds"
    )
    scan_opt.add_argument(
        "--max-workers", type=int, default=5, help="Maximum concurrent workers"
    )
    scan_opt.add_argument(
        "--use-selenium",
        action="store_true",
        help="Use Selenium for JavaScript rendering",
    )
    scan_opt.add_argument(
        "--max-crawl-pages",
        type=int,
        default=1000,
        help="Maximum number of pages to crawl",
    )
    scan_opt.add_argument(
        "--port-scan", action="store_true", help="Perform port scanning"
    )

    # Feature toggles
    scanner_opt = parser.add_argument_group(
        "Vulnerability Scanning", "Enable/disable specific vulnerability scans"
    )
    scanner_opt.add_argument(
        "--no-sqli", action="store_true", help="Skip SQL injection scanning"
    )
    scanner_opt.add_argument("--no-xss", action="store_true", help="Skip XSS scanning")
    scanner_opt.add_argument(
        "--no-csrf", action="store_true", help="Skip CSRF scanning"
    )
    scanner_opt.add_argument(
        "--no-ssrf", action="store_true", help="Skip SSRF scanning"
    )
    scanner_opt.add_argument(
        "--no-path-traversal", action="store_true", help="Skip path traversal scanning"
    )
    scanner_opt.add_argument(
        "--no-file-inclusion", action="store_true", help="Skip file inclusion scanning"
    )
    scanner_opt.add_argument(
        "--no-command-injection",
        action="store_true",
        help="Skip command injection scanning",
    )

    # Recon options
    recon_opt = parser.add_argument_group(
        "Reconnaissance Modules",
        "Select Reconnaissance module(s) (requires `--recon-only` flag)",
    )
    recon_opt.add_argument(
        "--recon-only",
        action="store_true",
        help="Perform recon only, skip vulnerabilty scanning",
    )
    recon_opt.add_argument(
        "--recon-network",
        action="store_true",
        help="Enable network infrastructure analysis",
    )
    recon_opt.add_argument(
        "--recon-security",
        action="store_true",
        help="Enable security infrastructure analysis",
    )
    recon_opt.add_argument(
        "--recon-webapp", action="store_true", help="Enable web application analysis"
    )
    recon_opt.add_argument(
        "--recon-infrastructure",
        action="store_true",
        help="Enable infrastructure relationship mapping",
    )
    recon_opt.add_argument(
        "--recon-misc", action="store_true", help="Enable miscellaneous analysis"
    )
    recon_opt.add_argument(
        "--recon-all", action="store_true", help="Enable all reconnaissance modules"
    )

    # Recon sub-option toggles
    # Network analysis options
    net_recon_opt = parser.add_argument_group(
        "Network Recon Options",
        "Fine-tune network recon (requires `--recon-network` flag)",
    )
    net_recon_opt.add_argument(
        "--no-advanced-port-scan",
        action="store_true",
        help="Skip portscan during advanced recon",
    )
    net_recon_opt.add_argument(
        "--no-waf-detect", action="store_true", help="Skip firewall detection"
    )
    net_recon_opt.add_argument(
        "--no-detect-load-balancers",
        action="store_true",
        help="Skip check for load balancers",
    )
    net_recon_opt.add_argument(
        "--no-service-detection",
        action="store_true",
        help="Skip service detection on open ports",
    )
    net_recon_opt.add_argument(
        "--no-os-detection", action="store_true", help="Skip target OS detection"
    )
    net_recon_opt.add_argument(
        "--port-range", default="1-1000", help="Range of ports to scan"
    )
    net_recon_opt.add_argument(
        "--no-script-scan", action="store_true", help="Skip nmap script scan"
    )

    # Web application analysis options
    web_recon_opt = parser.add_argument_group(
        "WebApp Recon Options",
        "Fine-tune Webapp recon (requires `--recon-webapp` flag)",
    )
    web_recon_opt.add_argument(
        "--no-content-discovery", action="store_true", help="Skip content discovery"
    )
    web_recon_opt.add_argument(
        "--no-js-analysis", action="store_true", help="Skip javascript content analysis"
    )
    web_recon_opt.add_argument(
        "--dir-enum", action="store_true", help="List app directories"
    )

    # Infrastructure mapping options
    infra_recon_opt = parser.add_argument_group(
        "Infrastructure Mapping Options",
        "Fine-tune infrastructure recon (requires `--recon-infrastructure` flag)",
    )
    infra_recon_opt.add_argument(
        "--no-subdomain-enum", action="store_true", help="Skip check for sub-domains"
    )
    infra_recon_opt.add_argument(
        "--no-cloud-mapping",
        action="store_true",
        help="Skip cloud infrastructure mappng",
    )
    infra_recon_opt.add_argument(
        "--no-dns-bruteforce", action="store_true", help="Skip DNS bruteforce"
    )

    # Security analysis options
    sec_recon_opt = parser.add_argument_group(
        "Security Recon Options",
        "Fine-tune security recon (requires `--recon-security` flag)",
    )
    sec_recon_opt.add_argument(
        "--no-ssl-analysis",
        action="store_true",
        help="Skip ssl security config analysis",
    )
    sec_recon_opt.add_argument(
        "--no-security-headers",
        action="store_true",
        help="Skip security header config analysis",
    )

    # Misc options
    misc_recon_opt = parser.add_argument_group(
        "Miscellaneous Recon Options",
        "Fine-tune miscellaneous recon (requires `--recon-misc` flag)",
    )
    misc_recon_opt.add_argument(
        "--no-error-analysis", action="store_true", help="Skip error codes analysis"
    )
    misc_recon_opt.add_argument(
        "--no-cache-analysis", action="store_true", help="Skip cache config analysis"
    )
    misc_recon_opt.add_argument(
        "--no-debug-mode-check",
        action="store_true",
        help="Skip check if debug mode being enabled",
    )
    misc_recon_opt.add_argument(
        "--no-check-dev-artifacts",
        action="store_true",
        help="Skip check for dev artifacts",
    )
    misc_recon_opt.add_argument(
        "--no-backend-tests", action="store_true", help="Skip backend tests"
    )

    # Output options
    output_put = parser.add_argument_group(
        "Output Options", "Configure report generation and storage"
    )
    output_put.add_argument(
        "--output-dir", default="scan_results", help="Output directory for reports"
    )
    output_put.add_argument(
        "--no-html", action="store_true", help="Skip HTML report generation"
    )
    output_put.add_argument(
        "--no-pdf", action="store_true", help="Skip PDF report generation"
    )
    output_put.add_argument(
        "--no-json", action="store_true", help="Skip JSON report generation"
    )
    output_put.add_argument(
        "--excel", action="store_true", help="Generate Excel report "
    )

    # Database options
    db_opt = parser.add_argument_group("Database Options", "Configure database storage")
    db_opt.add_argument(
        "--use-db", action="store_true", help="Store results in SQLite database"
    )
    db_opt.add_argument(
        "--db-path", default="vulnradar.db", help="Path to SQLite database"
    )

    # Cache options
    cache_opt = parser.add_argument_group("Cache Options", "Configure result caching")
    cache_opt.add_argument(
        "--cache-dir", default="cache", help="Directory for caching results"
    )
    cache_opt.add_argument(
        "--cache-ttl", type=int, default=3600, help="Cache time-to-live in seconds"
    )
    cache_opt.add_argument(
        "--no-cache", action="store_true", help="Disable result caching"
    )
    cache_opt.add_argument(
        "--clear-cache", action="store_true", help="Clear cache before scanning"
    )

    # Multi-target options
    multi_opt = parser.add_argument_group(
        "Multi-Target Options", "Configure multi-target scanning"
    )
    multi_opt.add_argument(
        "--show-multi-config",
        help="Generate multi-target config template (yaml) and exit",
    )
    multi_opt.add_argument(
        "--targets-file",
        metavar="CONFIG_FILE",
        help="Scan multiple targets using configuration file",
    )
    multi_opt.add_argument(
        "--max-concurrent", type=int, default=3, help="Max concurrent target scans"
    )
    multi_opt.add_argument(
        "--sequential",
        action="store_true",
        help="Run multi-target scans sequentially (no concurrency)",
    )

    args = parser.parse_args()

    # Handle --show-multi-config option
    if args.show_multi_config:
        return handle_multi_config()

    if args.url is None and not args.gui and not args.targets_file:
        show_usage_examples()
        sys.exit(0)

    # Validate that both url and targets_file are not provided
    if args.url is not None and args.targets_file is not None:
        parser.error(
            "Cannot specify both 'url' and '--targets-file'. Please use one or the other."
        )

    return args


def handle_multi_config():
    """Generate and save multi-target config template."""
    try:
        MultiTargetScanner.generate_config_template()

        filename = "multi_target_config.yaml"
        output_path = Path.cwd() / filename

        print(
            f"\n{Fore.GREEN}✓ Configuration template generated successfully!{Style.RESET_ALL}"
        )
        print(f"  {Fore.CYAN}Location:{Style.RESET_ALL} {output_path.absolute()}")
        print(f"\n{Fore.YELLOW}Next steps:{Style.RESET_ALL}")
        print(f" 1. Open '{filename}' in your editor")
        print("  2. Add your target URLs and customize options")
        print("  3. Save the file")
        print(
            f"  4. Run: {Fore.CYAN}python -m vulnradar --targets-file {filename}{Style.RESET_ALL}"
        )
        print()

        sys.exit(0)
    except Exception as e:
        print(
            f"{Fore.RED}✗ Error generating config: {str(e)}{Style.RESET_ALL}",
            file=sys.stderr,
        )
        sys.exit(1)


def show_usage_examples():
    """Display usage examples when no arguments are provided."""
    print(f"""
            {Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
            ║                           VULNRADAR                                   ║
            ╚═══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

            {Fore.YELLOW}USAGE:{Style.RESET_ALL}
                python -m vulnradar <URL> [OPTIONS]

            {Fore.YELLOW}BASIC EXAMPLES:{Style.RESET_ALL}

            {Fore.GREEN}Quick Scan:{Style.RESET_ALL}
                python -m vulnradar https://example.com

            {Fore.GREEN}Run Scan From GUI:{Style.RESET_ALL}
                python -m vulnradar  https://example.com --gui

            {Fore.GREEN}Basic Authenticated Scan:{Style.RESET_ALL}
                python -m vulnradar https://app.example.com --cookies "session=abc123"

            {Fore.GREEN}Comprehensive Security Assessment:{Style.RESET_ALL}
                python -m vulnradar https://example.com \\
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
                python -m vulnradar https://slow-site.com --timeout 30 --max-workers 2

            {Fore.GREEN}For Fast Sites:{Style.RESET_ALL}
                python -m vulnradar https://fast-site.com --timeout 5 --max-workers 15

            {Fore.YELLOW}TARGETED SCANNING:{Style.RESET_ALL}

            {Fore.GREEN}SQL Injection and XSS Only:{Style.RESET_ALL}
                python -m vulnradar https://example.com \\
                    --no-csrf --no-ssrf --no-path-traversal \\
                    --no-file-inclusion --no-command-injection \\
                    --clear-cache

            {Fore.GREEN}Skip Vulnerability Scanning (Recon Only):{Style.RESET_ALL}
                python -m vulnradar https://example.com \\
                    --recon-only

            {Fore.GREEN}Specific Reconnaissance Modules:{Style.RESET_ALL}
                python -m vulnradar https://example.com \\
                    --recon-only \\
                    --recon-network --recon-security

            {Fore.GREEN}All Reconnaissance Modules:{Style.RESET_ALL}
                python -m vulnradar https://example.com \\
                    --recon-only --recon-all --clear-cache --cache-dir ./recon_cache

            {Fore.YELLOW}MULTI-TARGET SCANNING:{Style.RESET_ALL}

            {Fore.GREEN}Generate Multi-Target Config Template:{Style.RESET_ALL}
                python -m vulnradar --show-multi-config

            {Fore.GREEN}Scan Multiple Targets:{Style.RESET_ALL}
                python -m vulnradar --targets-file multi_target_config.yaml

            {Fore.GREEN}Sequential Multi-Target Scan:{Style.RESET_ALL}
                python -m vulnradar --targets-file multi_target_config.yaml --sequential

            {Fore.GREEN}Concurrent with Custom Limit:{Style.RESET_ALL}
                python -m vulnradar --targets-file multi_target_config.yaml --max-concurrent 5

            {Fore.YELLOW}ADVANCED OPTIONS:{Style.RESET_ALL}

            {Fore.GREEN}Custom Output Directory:{Style.RESET_ALL}
                python -m vulnradar https://example.com --output-dir ./my_scan_results

            {Fore.GREEN}Disable Caching:{Style.RESET_ALL}
                python -m vulnradar https://example.com --clear-cache --no-cache

            {Fore.GREEN}Clear Cache Before Scan (but use cache during scan):{Style.RESET_ALL}
                python -m vulnradar https://example.com --clear-cache

            {Fore.GREEN}Different Report Formats:{Style.RESET_ALL}
                python -m vulnradar https://example.com --no-pdf --excel --no-html

            {Fore.GREEN}Database Storage:{Style.RESET_ALL}
                python -m vulnradar https://example.com --use-db --db-path ./my_scans.db

            {Fore.YELLOW}HELP:{Style.RESET_ALL}
                python -m vulnradar --help      # Show all available options

            {Fore.CYAN}For detailed documentation, visit: https://github.com/MykeChidi/vulnradar {Style.RESET_ALL}
            """)


@handle_errors(
    error_handler=error_handler,
    user_message="Failed to launch GUI. Please check your system and try again.",
    return_on_error=None,
)
def launch_gui(prefill_url=None):
    """Launch the GUI application"""
    import tkinter as tk

    from .gui import VulnRadarGUI

    root = tk.Tk()
    app = VulnRadarGUI(root)

    if prefill_url:
        app.url_entry.delete(0, tk.END)
        app.url_entry.insert(0, prefill_url)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")

    root.mainloop()


@handle_errors(
    error_handler=error_handler,
    user_message="Failed to run multi-target scan. Please check your configuration and try again.",
    return_on_error=None,
)
def run_multi_target_scan(args, options) -> int:
    """Run multi-target scan from configuration file."""
    try:
        config_file = Path(args.targets_file)

        if not config_file.exists():
            print(
                f"{Fore.RED}Error: Configuration file not found: {config_file}{Style.RESET_ALL}",
                file=sys.stderr,
            )
            return 1

        print(
            f"{Fore.CYAN}Loading multi-target configuration from: {config_file.absolute()}{Style.RESET_ALL}\n"
        )

        # Initialize multi-target scanner
        scanner = MultiTargetScanner(
            config_file=config_file,
            default_options=options,
            concurrent=not args.sequential,
            max_concurrent=args.max_concurrent,
        )

        print(f"{Fore.CYAN}Loaded {len(scanner.targets)} target(s){Style.RESET_ALL}\n")

        # Run scans
        asyncio.run(scanner.scan_all())

        # Generate and display summary
        scanner.print_summary()

        # Save detailed reports
        output_dir = Path(args.output_dir)
        scanner.save_summary(output_dir / "multi_target_summary.json")
        scanner.save_detailed_results(output_dir / "multi_target_results")

        print(f"{Fore.GREEN}✓ Multi-target scan completed!{Style.RESET_ALL}")
        print(f"  Summary: {output_dir / 'multi_target_summary.json'}")
        print(f"  Results: {output_dir / 'multi_target_results'}\n")

        return 0

    except Exception:
        return 1


@handle_errors(
    error_handler=error_handler,
    user_message="Failed to run scan. Please check your configuration and try again.",
    return_on_error=None,
)
def run_single_target_scan(url: str, options):
    """Run scan on a single target."""
    # Initialize scanner
    scanner = VulnRadar(url, options)

    # Run scan
    results = asyncio.run(scanner.scan())

    # Print summary
    if not results.get("error"):
        print(f"\n{Fore.GREEN}Scan completed successfully!{Style.RESET_ALL}")
        print(f"Target: {results['target']}")
        print(f"Scan time: {results['scan_time']}")
        print(f"Endpoints discovered: {len(results['endpoints'])}")
        print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")

        if results["vulnerabilities"]:
            print("\nVulnerability Summary:")
            for i, vuln in enumerate(results["vulnerabilities"], 1):
                severity_color = (
                    Fore.RED
                    if vuln["severity"] == "High"
                    else Fore.YELLOW if vuln["severity"] == "Medium" else Fore.BLUE
                )
                print(
                    f"{i}. {severity_color}{vuln['type']} ({vuln['severity']}){Style.RESET_ALL} at {vuln['endpoint']}"
                )

        print(f"\nReports saved to: {Path(options['output_dir']).absolute()}")
    else:
        print(f"\n{Fore.RED}Scan failed: {results['error']}{Style.RESET_ALL}")


@handle_errors(
    error_handler=error_handler,
    user_message="VulnRadar scan failed. Please check your configuration and try again.",
    return_on_error=1,
)
def main():
    """Main Vulnradar function."""
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
        "max_crawl_pages": args.max_crawl_pages,
        "port_scan": args.port_scan,
        # Recon options
        "recon_only": args.recon_only,
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
        "advanced_port_scan": not args.no_advanced_port_scan,
        "detect_waf": not args.no_waf_detect,
        "detect_load_balancers": not args.no_detect_load_balancers,
        "service_detection": not args.no_service_detection,
        "os_detection": not args.no_os_detection,
        "script_scan": not args.no_script_scan,
        "port_range": args.port_range,
        # Web application analysis options
        "content_discovery": not args.no_content_discovery,
        "js_analysis": not args.no_js_analysis,
        "dir_enum": args.dir_enum,
        # Infrastructure mapping options
        "subdomain_enum": not args.no_subdomain_enum,
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

    if args.targets_file:
        run_multi_target_scan(args, options)
    else:
        # Single target mode
        run_single_target_scan(args.url, options)


if __name__ == "__main__":
    # Run the main function
    sys.exit(main())
