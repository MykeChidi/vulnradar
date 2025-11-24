# vulnscan/-recon/network.py - Network Infrastructure Analysis Module
import asyncio
import ssl
import socket
import dns.resolver
import aiohttp
from typing import Dict, List
import nmap
import OpenSSL
from pathlib import Path
from utils.logger import setup_logger
from utils.rate_limit import RateLimiter
from utils.cache import ScanCache
from reconn._target import ReconTarget


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
        self.logger = setup_logger("network_recon", scanner_specific=True)
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10
        self.rate_limiter = RateLimiter()
        
        # Initialize cache if no disabled
        if not options.get("no_cache", False):
            cache_dir = Path(options.get("cache_dir", "cache")) / "network"
            self._cache = ScanCache(cache_dir, default_ttl=options.get("cache_ttl", 3600))
        else:
            self._cache = None

    async def analyze(self) -> Dict:
        """
        Perform comprehensive network infrastructure analysis.
        
        Returns:
            Dict containing all network infrastructure findings
        """
        results = {}
        
        # Run DNS analysis
        results['dns'] = await self._analyze_dns()
        
        # Run port scanning if enabled
        if self.options.get('advanced_port_scan', True):
            results['ports'] = await self._scan_ports()
            
        # Detect load balancers
        if self.options.get('detect_load_balancers', True):
            results['load_balancer'] = await self._detect_load_balancer()
            
        return results
        
    async def _analyze_dns(self) -> Dict:
        """
        Perform comprehensive DNS analysis including various record types
        and DNSSEC validation.
        """
        dns_results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'SOA']
        
        try:
            # Quick A record check to validate domain
            self.dns_resolver.resolve(self.target.hostname, 'A')
        except dns.resolver.NXDOMAIN:
            self.logger.error(f"Domain {self.target.hostname} does not exist")
            return {"error": "domain_not_found", "message": f"Domain {self.target.hostname} does not exist"}
        except dns.resolver.NoNameservers:
            self.logger.error(f"No nameservers found for {self.target.hostname}")
            return {"error": "no_nameservers", "message": "No nameservers respond for this domain"}
        except dns.resolver.Timeout:
            self.logger.error(f"DNS timeout for {self.target.hostname}")
            return {"error": "timeout", "message": "DNS query timed out", "retryable": True}
        except Exception as e:
            self.logger.error(f"DNS error: {str(e)}")
            return {"error": "dns_error", "message": str(e)}
        
        for record_type in record_types:
            try:
                records = self.dns_resolver.resolve(self.target.hostname, record_type)
                dns_results[record_type] = [str(r) for r in records]
                self.logger.info(f"Found {len(dns_results[record_type])} {record_type} records")
            except dns.resolver.NoAnswer:
                dns_results[record_type] = []
                self.logger.debug(f"No {record_type} records for {self.target.hostname}")
            except dns.resolver.NXDOMAIN:
                self.logger.error(f"Domain {self.target.hostname} does not exist")
                return {"error": "Domain does not exist"}
            except dns.resolver.Timeout:
                self.logger.warning(f"Timeout querying {record_type} records")
                dns_results[record_type] = {"error": "timeout", "retryable": True}
            except Exception as e:
                self.logger.warning(f"DNS error querying {record_type}: {str(e)}")
                dns_results[record_type] = {"error": "query_failed", "details": str(e)}
                
                
        # Check DNSSEC
        try:
            dns_results['dnssec'] = await self._check_dnssec()
        except Exception as e:
           self.logger.exception(f"Unexpected error in DNSSEC check: {str(e)}")
           dns_results['dnssec'] = {"error": "unexpected", "details": str(e)}
            
        return dns_results
        
    async def _scan_ports(self) -> Dict:
        """
        Perform advanced port scanning including service detection
        and OS fingerprinting.
        """
        if not self.target.ip:
            self.logger.error("No IP address available for port scanning")
            return {"error": "no_ip", "message": "Target IP address not resolved"}

        capabilities = self._get_nmap_capabilities()
        port_results = {
            "scan_type": "privileged" if capabilities["syn_scan"] else "unprivileged",
            "capabilities": capabilities,
            "ports": {}
        }
        try:
            # Initialize port scanner
            scanner = nmap.PortScanner()
            
            # Determine scan type based on options
            scan_args = []

            if capabilities["syn_scan"]:
                scan_args.append('-sS')  # SYN scan 
            else:
                scan_args.append('-sT')  # TCP connect scan 
            if self.options.get('service_detection', True):
                scan_args.append('-sV')
            if self.options.get('os_detection', True):
                scan_args.append('-O')
            if self.options.get('script_scan', False):
                scan_args.append('-sC')
                
            # Adjust timing based on privileges
            if capabilities["syn_scan"]:
                scan_args.append('-T4')  # Aggressive timing for SYN scan
            else:
                scan_args.append('-T3')  # Normal timing for connect sca
            
            # Convert args list to string
            args = ' '.join(scan_args)
            
            # Run the scan
            self.logger.info(f"Starting port scan on {self.target.ip} with args: {args}")
            scanner.scan(self.target.ip, '1-1000', arguments=args)
            
            # Check if scan was successful
            if self.target.ip not in scanner.all_hosts():
                self.logger.warning(f"No scan results for {self.target.ip}")
                return {"error": "no_results", "message": "Port scan returned no results"}
        
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
                            "cpe": service.get("cpe", "")
                        }
                        
            self.logger.info(f"Port scan completed. Found {len(port_results)} open ports")
            return port_results
            
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan error: {str(e)}")
            return {"error": "scan_failed", "message": str(e)}
        except KeyError as e:
            self.logger.error(f"Error parsing scan results: {str(e)}")
            return {"error": "parse_error", "message": "Failed to parse nmap output"}
        except Exception as e:
            self.logger.exception(f"Unexpected error during port scan: {str(e)}")
            return {"error": "unexpected", "message": str(e)}
    
    def _has_root_privileges(self) -> bool:
        """Check if running with root/admin privileges."""
        import platform, os
        system = platform.system()
        
        if system in ['Linux', 'Darwin']:  # Unix-like
            return os.geteuid() == 0
        elif system == 'Windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
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
            "udp_scan": is_root  # -sU requires root
        }
    
    async def _detect_load_balancer(self) -> Dict:
        """
        Detect presence and type of load balancers through various techniques.
        """
        results = {
            "detected": False,
            "type": None,
            "evidence": []
        }
        
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
            "variations": {}
        }

        try:
            # Make multiple requests to check for certificate variations
            seen_certs = set()
            cert_details = []

            for _ in range(5):  # Make multiple requests to detect variations
                context = ssl.create_default_context()
                with socket.create_connection((self.target.hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target.hostname) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        cert_hash = hash(cert)
                        
                        if cert_hash not in seen_certs:
                            seen_certs.add(cert_hash)
                            x509 = OpenSSL.crypto.load_certificate(
                                OpenSSL.crypto.FILETYPE_ASN1,
                                cert
                            )
                            cert_details.append({
                                "subject": dict(x[0] for x in ssock.getpeercert()["subject"]),
                                "issuer": dict(x[0] for x in ssock.getpeercert()["issuer"]),
                                "serial": x509.get_serial_number(),
                                "fingerprint": x509.digest("sha256").hex()
                            })

            # Analyze variations
            cert_info["multiple_certificates"] = len(seen_certs) > 1
            cert_info["certificates"] = cert_details
            cert_info["variations"] = {
                "unique_certs": len(seen_certs),
                "issuers": len(set(cert["issuer"].get("organizationName", "") 
                                 for cert in cert_details)),
                "subjects": len(set(cert["subject"].get("commonName", "") 
                                  for cert in cert_details))
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
                records = self.dns_resolver.resolve(self.target.hostname, 'A')
                responses.update([str(r) for r in records])
            except Exception:
                continue
        return list(responses)
        
    async def _check_lb_headers(self) -> List[str]:
        """Check for load balancer related headers"""
        lb_headers = []

        await self.rate_limiter.acquire()

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.target.url, headers=self.options.get("headers", {})) as response:
                    await self.rate_limiter.report_success()
                    headers = response.headers
                    lb_indicators = {
                        "X-Load-Balancer": "Generic LB",
                        "X-Backend-Server": "Backend Server",
                        "Via": "Proxy/LB",
                        "X-Cache": "Caching Proxy"
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
            dnskey = self.dns_resolver.resolve(self.target.hostname, 'DNSKEY')
            # Check for DS records
            ds = self.dns_resolver.resolve(self.target.hostname, 'DS')
            
            return {
                "enabled": bool(dnskey and ds),
                "dnskey_count": len(dnskey) if dnskey else 0,
                "ds_count": len(ds) if ds else 0
            }
        except dns.resolver.NoAnswer:
            return {"enabled": False}
        except Exception as e:
            return {"error": str(e)}

