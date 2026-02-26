# vulnradar/reconn/network.py - Network Infrastructure Analysis Module
import asyncio
import socket
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast

import aiohttp
import dns.resolver
import nmap
import OpenSSL

from ..utils.cache import ScanCache
from ..utils.error_handler import (
    NetworkError,
    ValidationError,
    get_global_error_handler,
    handle_async_errors,
)
from ..utils.logger import setup_logger
from ..utils.rate_limit import RateLimiter
from ..utils.validator import Validator
from ._target import ReconTarget

error_handler = get_global_error_handler()


class NetworkInfrastructureAnalyzer:
    """
    Handles all network infrastructure related reconnaissance including DNS analysis,
    port scanning, and load balancer detection.
    """

    def __init__(self, target: ReconTarget, options: Dict):
        """
        Initialize the network infrastructure analyzer.

        Args:
            target: ReconTarget object containing target information
            options: Dictionary containing scan options and configurations
        """
        self.target = target
        self.options = options
        self.logger = setup_logger("network_recon", file_specific=True)
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10
        self.rate_limiter = RateLimiter()

        self._cache: Optional[ScanCache] = None
        # Initialize cache if no disabled
        if not options.get("no_cache", False):
            cache_dir = Path(options.get("cache_dir", "vulnradar_cache")) / "network"
            self._cache = ScanCache(
                cache_dir, default_ttl=options.get("cache_ttl", 3600)
            )
        else:
            self._cache = None

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Network reconnaissance analysis encountered an error",
        return_on_error={},
    )
    async def analyze(self) -> Dict:
        """
        Perform comprehensive network infrastructure analysis.

        Returns:
            Dict containing all network infrastructure findings
        """
        results = {}

        # Run DNS analysis
        results["dns"] = await self._analyze_dns()

        # Run port scanning if enabled
        if self.options.get("advanced_port_scan", True):
            results["ports"] = await self._scan_ports()

        # Detect load balancers
        if self.options.get("detect_load_balancers", True):
            results["load_balancer"] = await self._detect_load_balancer()

        return results

    async def _analyze_dns(self) -> Dict:
        """
        Perform comprehensive DNS analysis including various record types
        and DNSSEC validation.
        """
        dns_results: Dict[str, Union[List[str], Dict[str, Any]]] = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"]

        try:
            # Quick A record check to validate domain
            self.dns_resolver.resolve(self.target.hostname, "A")
        except dns.resolver.NXDOMAIN:
            error_msg = f"Domain {self.target.hostname} does not exist"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "domain_not_found",
                },
            )
            return {"error": "domain_not_found", "message": error_msg}
        except dns.resolver.NoNameservers:
            error_msg = f"No nameservers found for {self.target.hostname}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "no_nameservers",
                },
            )
            return {
                "error": "no_nameservers",
                "message": "No nameservers respond for this domain",
            }
        except dns.resolver.Timeout:
            error_msg = f"DNS timeout for {self.target.hostname}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "dns_timeout",
                    "retryable": True,
                },
            )
            return {
                "error": "timeout",
                "message": "DNS query timed out",
                "retryable": True,
            }
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No answer for {self.target.hostname}")
            return {"error": "no_answer", "message": "DNS query returned no answer"}
        except dns.exception.DNSException as e:
            error_msg = f"DNS exception: {str(e)}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "dns_exception",
                },
            )
            return {"error": "dns_exception", "message": str(e)}
        except Exception as e:
            error_msg = f"Unexpected DNS error: {str(e)}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "unexpected_dns_error",
                },
            )
            return {"error": "unexpected", "message": str(e)}

        for record_type in record_types:
            try:
                records = self.dns_resolver.resolve(self.target.hostname, record_type)
                dns_results[record_type] = [str(r) for r in records]
                self.logger.info(
                    f"Found {len(dns_results[record_type])} {record_type} records"
                )
            except dns.resolver.NoAnswer:
                dns_results[record_type] = []
                self.logger.debug(
                    f"No {record_type} records for {self.target.hostname}"
                )
            except dns.resolver.NXDOMAIN as e:
                error_msg = f"Domain {self.target.hostname} does not exist during {record_type} lookup {str(e)}"
                self.logger.error(error_msg)
                error_handler.handle_error(
                    NetworkError(error_msg),
                    context={
                        "hostname": self.target.hostname,
                        "record_type": record_type,
                        "error_type": "domain_not_found",
                    },
                )
                return {
                    "error": "domain_not_found",
                    "message": f"Domain {self.target.hostname} does not exist",
                }
            except dns.resolver.Timeout:
                warning_msg = (
                    f"Timeout querying {record_type} records for {self.target.hostname}"
                )
                self.logger.warning(warning_msg)
                dns_results[record_type] = {"error": "timeout", "retryable": True}
            except Exception as e:
                warning_msg = f"DNS error querying {record_type}: {str(e)}"
                self.logger.warning(warning_msg)
                error_handler.handle_error(
                    NetworkError(warning_msg),
                    context={
                        "hostname": self.target.hostname,
                        "record_type": record_type,
                        "error_type": "query_failed",
                    },
                )
                dns_results[record_type] = {"error": "query_failed", "details": str(e)}

        # Check DNSSEC
        try:
            dns_results["dnssec"] = await self._check_dnssec()
        except Exception as e:
            error_msg = f"DNSSEC check failed: {str(e)}"
            self.logger.exception(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "dnssec_check_failed",
                },
            )
            dns_results["dnssec"] = {"error": "dnssec_check_failed", "details": str(e)}

        return dns_results

    async def _scan_ports(self) -> Dict:
        """
        Perform advanced port scanning including service detection
        and OS fingerprinting.
        """
        if not self.target.ip:
            self.logger.error("No IP address available for port scanning")
            return {"error": "no_ip", "message": "Target IP address not resolved"}

        # Validate port range safely
        port_range_str = self.options.get("port_range", "1-1000")

        try:
            # Validate port range format
            if port_range_str == "common":
                port_range = (
                    "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
                )
            else:
                # Validate it's safe
                ports = Validator.validate_port_range(port_range_str)
                port_range = port_range_str  # Use validated string

        except ValidationError as e:
            self.logger.error(f"Invalid port range: {e}")
            error_handler.handle_error(e)
            return {"error": "invalid_port_range", "message": str(e)}

        capabilities = self._get_nmap_capabilities()
        port_results = {
            "scan_type": "privileged" if capabilities["syn_scan"] else "unprivileged",
            "capabilities": capabilities,
            "ports": {},
        }
        try:
            # Initialize port scanner
            scanner = nmap.PortScanner()

            # Determine scan type based on options
            scan_args = []

            if capabilities["syn_scan"]:
                scan_args.append("-sS")  # SYN scan
            else:
                scan_args.append("-sT")  # TCP connect scan
            if self.options.get("service_detection", True):
                scan_args.append("-sV")
            if self.options.get("os_detection", True):
                scan_args.append("-O")
            if self.options.get("script_scan", True):
                scan_args.append("-sC")

            # Adjust timing based on privileges
            if capabilities["syn_scan"]:
                scan_args.append("-T4")  # Aggressive timing for SYN scan
            else:
                scan_args.append("-T3")  # Normal timing for connect sca

            # Convert args list to string
            args = " ".join(scan_args)

            # Run the scan
            self.logger.info(
                f"Starting port scan on {self.target.ip} with args: {args}"
            )
            scanner.scan(self.target.ip, port_range, arguments=args)

            # Check if scan was successful
            if self.target.ip not in scanner.all_hosts():
                self.logger.warning(f"No scan results for {self.target.ip}")
                return {
                    "error": "no_results",
                    "message": "Port scan returned no results",
                }

            # Process results
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        service = scanner[host][proto][port]
                        port_results[port] = {
                            "state": service["state"],
                            "service": service["name"],
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "extrainfo": service.get("extrainfo", ""),
                            "reason": service.get("reason", ""),
                            "cpe": service.get("cpe", ""),
                        }

            self.logger.info(
                f"Port scan completed. Found {len(port_results)} open ports"
            )
            return port_results

        except nmap.PortScannerError as e:
            error_msg = f"Nmap scan error: {str(e)}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={"target_ip": self.target.ip, "error_type": "nmap_scan_error"},
            )
            return {"error": "scan_failed", "message": str(e)}
        except KeyError as e:
            error_msg = f"Error parsing port scan results: {str(e)}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "target_ip": self.target.ip,
                    "error_type": "parse_error",
                    "key": str(e),
                },
            )
            return {"error": "parse_error", "message": "Failed to parse nmap output"}
        except Exception as e:
            error_msg = f"Unexpected error during port scan: {str(e)}"
            self.logger.exception(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "target_ip": self.target.ip,
                    "error_type": "unexpected_port_scan_error",
                },
            )
            return {"error": "unexpected", "message": str(e)}

    def _has_root_privileges(self) -> bool:
        """Check if running with root/admin privileges."""
        import os
        import platform

        system = platform.system()

        if system in ["Linux", "Darwin"]:  # Unix-like
            return hasattr(os, "geteuid") and os.geteuid() == 0
        elif system == "Windows":
            try:
                import ctypes

                return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
            except Exception:
                return False
        return False

    def _get_nmap_capabilities(self) -> Dict[str, bool]:
        """Get available nmap scanning capabilities."""
        is_root = self._has_root_privileges()

        return {
            "syn_scan": is_root,  # -sS requires root
            "os_detection": is_root,  # -O requires root
            "version_detection": True,  # -sV doesn't require root
            "script_scan": True,  # -sC doesn't require root
            "connect_scan": True,  # -sT doesn't require root
            "udp_scan": is_root,  # -sU requires root
        }

    async def _detect_load_balancer(self) -> Dict:
        """
        Detect presence and type of load balancers through various techniques.
        """
        results: Dict[str, Any] = {"detected": False, "type": None, "evidence": []}

        try:
            # DNS round-robin detection
            a_records = await self._get_multiple_dns_responses()
            if len(a_records) > 1:
                results["detected"] = True
                results["type"] = "DNS Round-Robin"
                results["evidence"].append(f"Multiple A records: {a_records}")

            # Application-level load balancing detection
            lb_headers = await self._check_lb_headers()
            if lb_headers:
                results["detected"] = True
                results["type"] = "Application-Level"
                results["evidence"].extend(lb_headers)

            # SSL certificate analysis
            if self.target.is_https:
                cert_info = await self._analyze_ssl_certificates()
                if cert_info.get("multiple_certificates"):
                    results["detected"] = True
                    results["type"] = "SSL-Based"
                    results["evidence"].append("Multiple SSL certificates detected")

            return results

        except Exception as e:
            self.logger.error(f"Load balancer detection failed: {str(e)}")
            return {"error": str(e)}

    async def _analyze_ssl_certificates(self) -> Dict:
        """
        Analyze SSL certificates for load balancer detection.
        Returns information about certificate variations that may indicate load balancing.
        """
        cert_info = {
            "multiple_certificates": False,
            "certificates": [],
            "variations": {},
        }

        try:
            # Make multiple requests to check for certificate variations
            seen_certs = set()
            cert_details = []

            for _ in range(5):  # Make multiple requests to detect variations
                context = ssl.create_default_context()
                with socket.create_connection((self.target.hostname, 443)) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=self.target.hostname
                    ) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        cert_hash = hash(cert)

                        if cert_hash not in seen_certs:
                            seen_certs.add(cert_hash)
                            if cert is not None:
                                x509 = OpenSSL.crypto.load_certificate(
                                    OpenSSL.crypto.FILETYPE_ASN1, cert
                                )
                            else:
                                continue
                            peer_cert = ssock.getpeercert()
                            if (
                                peer_cert
                                and "subject" in peer_cert
                                and "issuer" in peer_cert
                            ):
                                pc = cast(Dict[str, Any], peer_cert)
                                # Build subject dict safely
                                subject_dict: Dict[str, str] = {}
                                for item in pc.get(
                                    "subject", ()
                                ):  # typically a sequence of tuples
                                    if (
                                        isinstance(item, (list, tuple))
                                        and len(item) > 0
                                    ):
                                        first = item[0]
                                        if (
                                            isinstance(first, (list, tuple))
                                            and len(first) >= 2
                                        ):
                                            key, value = first[0], first[1]
                                            subject_dict[key] = value
                                # Build issuer dict safely
                                issuer_dict: Dict[str, str] = {}
                                for item in pc.get("issuer", ()):
                                    if (
                                        isinstance(item, (list, tuple))
                                        and len(item) > 0
                                    ):
                                        first = item[0]
                                        if (
                                            isinstance(first, (list, tuple))
                                            and len(first) >= 2
                                        ):
                                            key, value = first[0], first[1]
                                            issuer_dict[key] = value
                                cert_details.append(
                                    {
                                        "subject": subject_dict,
                                        "issuer": issuer_dict,
                                        "serial": x509.get_serial_number(),
                                        "fingerprint": x509.digest("sha256").hex(),
                                    }
                                )

            # Analyze variations
            cert_info["multiple_certificates"] = len(seen_certs) > 1
            cert_info["certificates"] = cert_details
            issuers_set = set()
            subjects_set = set()
            for cert_item in cert_details:
                issuer = cert_item.get("issuer")
                if isinstance(issuer, dict):
                    issuers_set.add(issuer.get("organizationName", ""))
                subject = cert_item.get("subject")
                if isinstance(subject, dict):
                    subjects_set.add(subject.get("commonName", ""))

            cert_info["variations"] = {
                "unique_certs": len(seen_certs),
                "issuers": len(issuers_set),
                "subjects": len(subjects_set),
            }

            return cert_info

        except Exception as e:
            self.logger.error(f"SSL certificate analysis failed: {str(e)}")
            return {"error": str(e)}

    async def _get_multiple_dns_responses(self) -> List[str]:
        """Helper method to get multiple DNS responses"""
        responses = set()
        for _ in range(5):  # Make multiple requests to detect round-robin
            try:
                records = self.dns_resolver.resolve(self.target.hostname, "A")
                responses.update([str(r) for r in records])
            except Exception:
                self.logger.debug(
                    "DNS query failed during round-robin detection", exc_info=False
                )
                continue
        return list(responses)

    async def _check_lb_headers(self) -> List[str]:
        """Check for load balancer related headers"""
        lb_headers = []

        await self.rate_limiter.acquire()

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    self.target.url, headers=self.options.get("headers", {})
                ) as response:
                    await self.rate_limiter.report_success()
                    headers = response.headers
                    lb_indicators = {
                        "X-Load-Balancer": "Generic LB",
                        "X-Backend-Server": "Backend Server",
                        "Via": "Proxy/LB",
                        "X-Cache": "Caching Proxy",
                    }

                    for header, indicator in lb_indicators.items():
                        if header in headers:
                            lb_headers.append(f"{indicator} detected via {header}")
            except aiohttp.ClientResponseError as e:
                if e.status == 429:
                    # Rate limited by server
                    await self.rate_limiter.report_failure(is_rate_limit=True)
                    self.logger.warning("Rate limited by server, backing off")
                else:
                    await self.rate_limiter.report_failure()
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                await self.rate_limiter.report_failure()
                self.logger.error(f"Header check failed: {str(e)}")

        return lb_headers

    async def _check_dnssec(self) -> Dict:
        """Check DNSSEC configuration"""
        try:
            # Check for DNSKEY records
            dnskey = self.dns_resolver.resolve(self.target.hostname, "DNSKEY")
            # Check for DS records
            ds = self.dns_resolver.resolve(self.target.hostname, "DS")

            return {
                "enabled": bool(dnskey and ds),
                "dnskey_count": len(dnskey) if dnskey else 0,
                "ds_count": len(ds) if ds else 0,
            }
        except dns.resolver.NoAnswer:
            return {"enabled": False}
        except Exception as e:
            return {"error": str(e)}
