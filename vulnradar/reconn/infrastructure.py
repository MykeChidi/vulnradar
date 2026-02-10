# vulnradar/reconn/infrastructure.py - Infrastructure relationship mapping for vulnerability scans.
import asyncio
import json
import re
import socket
import ssl
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, cast
from urllib.parse import urlparse

import aiohttp
import dns.resolver
from bs4 import BeautifulSoup

from ..utils.cache import ScanCache
from ..utils.error_handler import (
    NetworkError,
    get_global_error_handler,
    handle_async_errors,
)
from ..utils.logger import setup_logger
from ..utils.rate_limit import RateLimiter
from ._target import ReconTarget

error_handler = get_global_error_handler()


class InfrastructureRelationshipMapper:
    """
    Maps relationships between different infrastructure components,
    including asset discovery, cloud services, and third-party integrations.
    """

    def __init__(self, target: ReconTarget, options: Dict):
        self.target = target
        self.options = options
        self.logger = setup_logger("infra_mapper", file_specific=True)
        self.rate_limiter = RateLimiter()

        self._cache: Optional[ScanCache] = None
        # Initialize cache
        if not options.get("no_cache", False):
            cache_dir = Path(options.get("cache_dir", "cache")) / "infrastructure"
            self._cache = ScanCache(
                cache_dir, default_ttl=options.get("cache_ttl", 3600)
            )
        else:
            self._cache = None

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Infrastructure reconnaissance analysis encountered an error",
        return_on_error={},
    )
    async def analyze(self) -> Dict:
        """
        Perform comprehensive infrastructure relationship mapping.

        Returns:
            Dict containing all infrastructure relationship findings
        """
        results = {}

        # Map subdomains and related assets
        if self.options.get("subdomain_enum", True):
            results["subdomains"] = await self._enumerate_subdomains()

        # Map cloud infrastructure
        if self.options.get("cloud_mapping", True):
            results["cloud_infrastructure"] = await self._map_cloud_infrastructure()

        # Map third-party services
        results["third_party_services"] = await self._map_third_party_services()

        # Asset relationships
        results["asset_relationships"] = await self._map_asset_relationships()

        return results

    async def _enumerate_subdomains(self) -> Dict:
        """
        Comprehensive subdomain enumeration using multiple techniques.
        """
        subdomain_results: Dict[str, Any] = {
            "found": [],
            "sources": {},
            "total_count": 0,
            "live_count": 0,
        }

        try:
            await self.rate_limiter.acquire()
            # Certificate transparency logs
            cert_subdomains = await self._check_cert_transparency()
            subdomain_results["sources"]["cert_transparency"] = cert_subdomains

            # DNS bruteforce
            if self.options.get("dns_bruteforce", True):
                brute_subdomains = await self._dns_bruteforce()
                subdomain_results["sources"]["bruteforce"] = brute_subdomains

            # Search engine discovery
            search_subdomains = await self._search_engine_discovery()
            subdomain_results["sources"]["search_engines"] = search_subdomains

            # Zone transfer attempt
            zone_subdomains = await self._try_zone_transfer()
            if zone_subdomains:
                subdomain_results["sources"]["zone_transfer"] = zone_subdomains

            # Combine all findings
            all_subdomains = set()
            for source_results in subdomain_results["sources"].values():
                all_subdomains.update(source_results)

            # Verify live subdomains
            live_subdomains = await self._verify_subdomains(all_subdomains)

            subdomain_results["found"] = list(all_subdomains)
            subdomain_results["total_count"] = len(all_subdomains)
            subdomain_results["live_count"] = len(live_subdomains)

            return subdomain_results

        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {str(e)}")
            return {"error": str(e)}

    async def _check_cert_transparency(self) -> List[str]:
        """
        Check certificate transparency logs for subdomains.
        """
        subdomains = set()

        ct_sources: List[Dict[str, Any]] = [
            {
                "name": "crt.sh",
                "url": f"https://crt.sh/?q=%.{self.target.hostname}&output=json",
                "parser": cast(Callable[[Any], List[str]], self._parse_crtsh),
            },
            {
                "name": "certspotter",
                "url": f"https://api.certspotter.com/v1/issuances?domain={self.target.hostname}&include_subdomains=true&expand=dns_names",  # noqa
                "parser": cast(Callable[[Any], List[str]], self._parse_certspotter),
            },
        ]

        for source in ct_sources:
            try:
                await self.rate_limiter.acquire()

                timeout = aiohttp.ClientTimeout(total=30)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
                    }

                    url = source.get("url")
                    if not isinstance(url, str):
                        self.logger.warning(
                            f"Invalid CT source URL for {source.get('name')}"
                        )
                        continue
                    parser = source.get("parser")
                    async with session.get(url, headers=headers) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                domains: List[str] = []
                                if callable(parser):
                                    domains = parser(data)  # type: ignore[arg-type]
                                subdomains.update(domains)
                                self.logger.info(
                                    f"Found {len(domains)} subdomains from {source['name']}"
                                )
                                await self.rate_limiter.report_success()
                            except json.JSONDecodeError as e:
                                warning_msg = f"Failed to parse {source['name']} response: {str(e)}"
                                self.logger.warning(warning_msg)
                                error_handler.handle_error(
                                    NetworkError(warning_msg),
                                    context={
                                        "source": source["name"],
                                        "error_type": "json_parse_error",
                                    },
                                )
                        elif response.status == 429:
                            self.logger.warning(f"Rate limited by {source['name']}")
                            await self.rate_limiter.report_failure(is_rate_limit=True)
                        else:
                            self.logger.warning(
                                f"{source['name']} returned status {response.status}"
                            )

            except asyncio.TimeoutError:
                warning_msg = f"Timeout querying {source['name']} for subdomains"
                self.logger.warning(warning_msg)
                error_handler.handle_error(
                    NetworkError(warning_msg),
                    context={
                        "source": source["name"],
                        "error_type": "subdomain_query_timeout",
                        "retryable": True,
                    },
                )
            except aiohttp.ClientError as e:
                warning_msg = f"HTTP error querying {source['name']}: {str(e)}"
                self.logger.warning(warning_msg)
                error_handler.handle_error(
                    NetworkError(warning_msg),
                    context={"source": source["name"], "error_type": "http_error"},
                )
            except Exception as e:
                error_msg = f"Unexpected error with {source['name']}: {str(e)}"
                self.logger.error(error_msg)
                error_handler.handle_error(
                    NetworkError(error_msg),
                    context={
                        "source": source["name"],
                        "error_type": "unexpected_subdomain_error",
                    },
                )

        # Filter to only return valid subdomains
        valid_subdomains = set()
        for domain in subdomains:
            domain = domain.strip().lower()
            # Remove wildcards
            domain = domain.replace("*.", "")
            # Only include if it's actually a subdomain of target
            if domain.endswith(self.target.hostname) and domain != self.target.hostname:
                valid_subdomains.add(domain)

        return list(valid_subdomains)

    def _parse_crtsh(self, data: List[Dict]) -> Set[str]:
        """Parse crt.sh CT log response."""
        domains = set()
        for entry in data:
            if "name_value" in entry:
                # name_value can contain multiple domains separated by newlines
                names = entry["name_value"].split("\n")
                for name in names:
                    name = name.strip().lower()
                    if name:
                        domains.add(name)
        return domains

    def _parse_certspotter(self, data: List[Dict]) -> Set[str]:
        """Parse Certspotter API response."""
        domains = set()
        for entry in data:
            if "dns_names" in entry:
                for name in entry["dns_names"]:
                    name = name.strip().lower()
                    if name:
                        domains.add(name)
        return domains

    async def _dns_bruteforce(self) -> List[str]:
        """
        Perform DNS bruteforce using common subdomain wordlist.
        """
        subdomains = set()
        common_subdomains = [
            "www",
            "mail",
            "ftp",
            "webmail",
            "admin",
            "test",
            "dev",
            "staging",
            "api",
            "cdn",
            "blog",
            "shop",
            "app",
            "m",
            "mobile",
            "store",
            "portal",
            "beta",
        ]

        # Create tasks with rate limiting
        async def resolve_with_limit(subdomain):
            await self.rate_limiter.acquire()
            try:
                hostname = f"{subdomain}.{self.target.hostname}"
                result = await self._resolve_dns(hostname)
                if result:
                    await self.rate_limiter.report_success()
                    return hostname
            except Exception as e:
                await self.rate_limiter.report_failure()
                self.logger.debug(f"DNS resolution failed for {subdomain}: {str(e)}")
            return None

        # Execute with concurrency limit
        tasks = [resolve_with_limit(sub) for sub in common_subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        subdomains = {str(r) for r in results if r and not isinstance(r, Exception)}
        return list(subdomains)

    async def _resolve_dns(self, hostname: str) -> List[str]:
        """Helper method to resolve DNS records."""
        try:
            answers = dns.resolver.resolve(hostname, "A")
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    async def _search_engine_discovery(self) -> List[str]:
        """
        Discover subdomains through search engine results.
        """
        subdomains: Set[str] = set()

        try:
            async with aiohttp.ClientSession() as session:  # noqa
                # Use site: operator to find subdomains
                search_query = f"site:{self.target.hostname}"  # noqa
                headers = {  # noqa
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/91.0.4472.124 Safari/537.36"
                }

                # Implement search engine specific logic here
                # Note: In a real implementation, you'd want to use proper search
                # APIs that respect terms of service

                # Example pattern matching for domains
                domain_pattern = rf"[a-zA-Z0-9-]+\.{self.target.hostname}"  # noqa

        except Exception as e:
            self.logger.error(f"Search engine discovery failed: {str(e)}")

        return list(subdomains)

    async def _try_zone_transfer(self) -> List[str]:
        """
        Attempt DNS zone transfer.
        """
        subdomains = set()

        try:
            # Get nameservers
            ns_records = dns.resolver.resolve(self.target.hostname, "NS")
            nameservers = [str(ns) for ns in ns_records]

            for ns in nameservers:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.target.hostname))
                    if zone:
                        for name, _ in zone.nodes.items():
                            subdomain = str(name) + "." + self.target.hostname
                            if subdomain.endswith("." + self.target.hostname):
                                subdomains.add(subdomain)
                except Exception:
                    self.logger.debug(
                        f"Zone transfer failed for nameserver {ns}", exc_info=False
                    )
                    continue

        except Exception as e:
            self.logger.error(f"Zone transfer attempt failed: {str(e)}")

        return list(subdomains)

    async def _verify_subdomains(self, subdomains: Set[str]) -> List[str]:
        """
        Verify discovered subdomains are active.
        """
        live_subdomains = []

        try:
            async with aiohttp.ClientSession() as session:
                tasks = []
                for subdomain in subdomains:
                    # Try both HTTP and HTTPS
                    tasks.extend(
                        [
                            self._check_subdomain(session, f"http://{subdomain}"),
                            self._check_subdomain(session, f"https://{subdomain}"),
                        ]
                    )

                results = await asyncio.gather(*tasks, return_exceptions=True)

                for subdomain, is_live in zip(
                    [s for s in subdomains for _ in range(2)],  # Each subdomain twice
                    results,
                ):
                    if isinstance(is_live, bool) and is_live:
                        live_subdomains.append(subdomain)

        except Exception as e:
            self.logger.error(f"Subdomain verification failed: {str(e)}")

        return list(set(live_subdomains))

    async def _check_subdomain(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Helper method to check if a subdomain is live."""
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                return response.status < 500  # Consider any non-server-error as live
        except Exception:
            return False

    async def _map_cloud_infrastructure(self) -> Dict:
        """
        Map cloud infrastructure and services used by the target.
        """
        cloud_results: Dict[str, Any] = {
            "providers": [],
            "services": [],
            "regions": [],
            "resources": [],
        }

        try:
            # Check common cloud providers
            providers = await self._detect_cloud_providers()
            cloud_results["providers"] = providers

            # For each detected provider, map services
            for provider in providers:
                services = await self._map_cloud_services(provider)
                cloud_results["services"].extend(services)

            # Detect CDN usage
            cdn_info = await self._detect_cdn()
            if cdn_info:
                cloud_results["services"].append({"type": "CDN", "details": cdn_info})

            # Map geographic distribution
            cloud_results["regions"] = await self._map_geographic_distribution()

            return cloud_results

        except Exception as e:
            self.logger.error(f"Cloud infrastructure mapping failed: {str(e)}")
            return {"error": str(e)}

    async def _detect_cloud_providers(self) -> List[Dict]:
        """
        Detect cloud providers being used by the target.
        """
        providers = []

        cloud_signatures = {
            "AWS": {
                "headers": ["x-amz-", "x-amzn-", "aws-"],
                "domains": ["amazonaws.com", "cloudfront.net"],
                "ip_ranges": ["52.84.", "52.219."],  # Simplified ranges
            },
            "Azure": {
                "headers": ["x-ms-", "azure-"],
                "domains": ["azurewebsites.net", "cloudapp.net"],
                "ip_ranges": ["13.64.", "13.65."],
            },
            "GCP": {
                "headers": ["x-goog-", "gcp-"],
                "domains": ["appspot.com", "googleusercontent.com"],
                "ip_ranges": ["34.64.", "34.65."],
            },
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target.url) as response:
                    headers = response.headers

                    for provider, sigs in cloud_signatures.items():
                        evidence = []

                        # Check headers
                        for header_prefix in sigs["headers"]:
                            matching_headers = [
                                h
                                for h in headers.keys()
                                if h.lower().startswith(header_prefix)
                            ]
                            if matching_headers:
                                evidence.append(
                                    f"Found {provider} headers: {matching_headers}"
                                )

                        # Check domains
                        target_domain = self.target.hostname.lower()
                        for domain in sigs["domains"]:
                            if domain in target_domain:
                                evidence.append(f"Domain matches {provider} pattern")

                        # Check IP ranges (simplified)
                        if self.target.ip:
                            for ip_range in sigs["ip_ranges"]:
                                if self.target.ip.startswith(ip_range):
                                    evidence.append(
                                        f"IP in {provider} range: {ip_range}"
                                    )

                        if evidence:
                            providers.append(
                                {
                                    "provider": provider,
                                    "confidence": (
                                        "high" if len(evidence) > 1 else "medium"
                                    ),
                                    "evidence": evidence,
                                }
                            )

        except Exception as e:
            self.logger.error(f"Cloud provider detection failed: {str(e)}")

        return providers

    async def _map_cloud_services(self, provider: Dict) -> List[Dict]:
        """
        Map cloud services used by the detected provider.
        """
        services = []
        provider_name = provider["provider"]

        service_signatures = {
            "AWS": {
                "S3": {"domains": ["s3.amazonaws.com"], "headers": ["x-amz-bucket"]},
                "CloudFront": {
                    "domains": ["cloudfront.net"],
                    "headers": ["x-amz-cf-id"],
                },
                "ELB": {
                    "domains": ["elb.amazonaws.com"],
                    "headers": ["x-amzn-trace-id"],
                },
            },
            "Azure": {
                "Blob Storage": {
                    "domains": ["blob.core.windows.net"],
                    "headers": ["x-ms-blob-type"],
                },
                "CDN": {
                    "domains": ["azureedge.net"],
                    "headers": ["x-ms-edge-location"],
                },
            },
            "GCP": {
                "Cloud Storage": {
                    "domains": ["storage.googleapis.com"],
                    "headers": ["x-goog-storage-class"],
                },
                "Cloud CDN": {
                    "domains": ["googleusercontent.com"],
                    "headers": ["x-goog-cache"],
                },
            },
        }

        try:
            if provider_name in service_signatures:
                await self.rate_limiter.acquire()
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.get(self.target.url) as response:
                            await self.rate_limiter.report_success()
                            headers = response.headers

                            for service, sigs in service_signatures[
                                provider_name
                            ].items():
                                evidence = []

                                # Check domains
                                target_domain = self.target.hostname.lower()
                                for domain in sigs["domains"]:
                                    if domain in target_domain:
                                        evidence.append(
                                            f"Domain pattern match: {domain}"
                                        )

                                # Check headers
                                for header in sigs["headers"]:
                                    if any(
                                        h.lower().startswith(header.lower())
                                        for h in headers.keys()
                                    ):
                                        evidence.append(f"Header match: {header}")

                                if evidence:
                                    services.append(
                                        {
                                            "provider": provider_name,
                                            "service": service,
                                            "evidence": evidence,
                                            "confidence": (
                                                "high"
                                                if len(evidence) > 1
                                                else "medium"
                                            ),
                                        }
                                    )
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        await self.rate_limiter.report_failure()
                        self.logger.error(f"Could not map cloud service: {str(e)}")
                        raise

        except Exception as e:
            self.logger.error(f"Cloud service mapping failed: {str(e)}")

        return services

    async def _detect_cdn(self) -> Optional[Dict]:
        """
        Detect CDN usage and provider.
        """
        cdn_info = None

        cdn_signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status"],
                "nameservers": ["cloudflare.com"],
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "akamai-origin-hop"],
                "domains": ["akamai.net"],
            },
            "Fastly": {
                "headers": ["fastly-debug-digest", "x-served-by"],
                "domains": ["fastly.net"],
            },
            "CloudFront": {
                "headers": ["x-amz-cf-id", "x-cache"],
                "domains": ["cloudfront.net"],
            },
        }

        try:
            await self.rate_limiter.acquire()
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(self.target.url) as response:
                        await self.rate_limiter.report_success()
                        headers = response.headers

                        for cdn, sigs in cdn_signatures.items():
                            evidence = []

                            # Check headers
                            for header in sigs["headers"]:
                                if header.lower() in [
                                    h.lower() for h in headers.keys()
                                ]:
                                    evidence.append(f"Found {cdn} header: {header}")

                            # Check nameservers if present in signatures
                            if "nameservers" in sigs:
                                try:
                                    ns_records = dns.resolver.resolve(
                                        self.target.hostname, "NS"
                                    )
                                    for ns in ns_records:
                                        ns_str = str(ns).lower()
                                        for ns_pattern in sigs["nameservers"]:
                                            if ns_pattern in ns_str:
                                                evidence.append(
                                                    f"Nameserver match: {ns_str}"
                                                )
                                except Exception:
                                    self.logger.debug(
                                        "Failed to resolve NS records for CDN detection",
                                        exc_info=False,
                                    )
                                    pass

                            # Check CNAME records for CDN domains
                            if "domains" in sigs:
                                try:
                                    cname_records = dns.resolver.resolve(
                                        self.target.hostname, "CNAME"
                                    )
                                    for cname in cname_records:
                                        cname_str = str(cname).lower()
                                        for domain in sigs["domains"]:
                                            if domain in cname_str:
                                                evidence.append(
                                                    f"CNAME match: {cname_str}"
                                                )
                                except Exception:
                                    self.logger.debug(
                                        "Failed to resolve CNAME records for CDN detection",
                                        exc_info=False,
                                    )
                                    pass

                            if evidence:
                                cdn_info = {
                                    "provider": cdn,
                                    "evidence": evidence,
                                    "confidence": (
                                        "high" if len(evidence) > 1 else "medium"
                                    ),
                                }
                                break
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    await self.rate_limiter.report_failure()
                    self.logger.error(f"Could not detect CDN {str(e)}")
                    raise

        except Exception as e:
            self.logger.error(f"CDN detection failed: {str(e)}")

        return cdn_info

    async def _map_geographic_distribution(self) -> List[Dict]:
        """
        Map geographic distribution of infrastructure.
        Uses multiple geolocation services with fallbacks.
        """
        distribution = []

        # Get all IP addresses
        ips: Set[str] = set()
        try:
            a_records = dns.resolver.resolve(self.target.hostname, "A")
            ips.update(str(r) for r in a_records)
        except dns.exception.DNSException as e:
            self.logger.error(f"Failed to resolve A records: {str(e)}")
            return []

        # Geolocate each IP
        for ip in ips:
            location = await self._geolocate_ip(ip)
            if location:
                distribution.append(location)

        return distribution

    async def _geolocate_ip(self, ip: str) -> Optional[Dict]:
        """
        Geolocate an IP address using multiple services.

        Args:
            ip: IP address to geolocate

        Returns:
            Geolocation data or None
        """
        # Try multiple services in order
        services = [
            self._geolocate_ipapi,
            self._geolocate_ipwhois,
            self._geolocate_ipinfo,
        ]

        for service in services:
            try:
                result = await service(ip)
                if result:
                    return result
            except Exception as e:
                self.logger.debug(f"Geolocation service failed: {str(e)}")
                continue

        # If all services fail, return basic info
        return {
            "ip": ip,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "coordinates": {"latitude": None, "longitude": None},
            "asn": "Unknown",
            "isp": "Unknown",
        }

    async def _geolocate_ipapi(self, ip: str) -> Optional[Dict]:
        """
        Geolocate using ip-api.com (No API key required).
        """
        await self.rate_limiter.acquire()

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,as"

                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        if data.get("status") == "success":
                            await self.rate_limiter.report_success()
                            return {
                                "ip": ip,
                                "country": data.get("country", "Unknown"),
                                "region": data.get("regionName", "Unknown"),
                                "city": data.get("city", "Unknown"),
                                "coordinates": {
                                    "latitude": data.get("lat"),
                                    "longitude": data.get("lon"),
                                },
                                "asn": data.get("as", "Unknown"),
                                "isp": data.get("isp", "Unknown"),
                                "source": "ip-api.com",
                            }
                        else:
                            self.logger.warning(
                                f"ip-api.com error: {data.get('message')}"
                            )

        except asyncio.TimeoutError:
            self.logger.debug(f"Timeout geolocating {ip} with ip-api.com")
        except aiohttp.ClientError as e:
            self.logger.debug(f"Error with ip-api.com: {str(e)}")
        except Exception as e:
            self.logger.debug(f"Unexpected error with ip-api.com: {str(e)}")

        return None

    async def _geolocate_ipwhois(self, ip: str) -> Optional[Dict]:
        """
        Geolocate using ipwhois.io (free, no API key required).
        """
        await self.rate_limiter.acquire()

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"https://ipwhois.app/json/{ip}"

                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        if data.get("success"):
                            await self.rate_limiter.report_success()
                            return {
                                "ip": ip,
                                "country": data.get("country", "Unknown"),
                                "region": data.get("region", "Unknown"),
                                "city": data.get("city", "Unknown"),
                                "coordinates": {
                                    "latitude": data.get("latitude"),
                                    "longitude": data.get("longitude"),
                                },
                                "asn": data.get("asn", "Unknown"),
                                "isp": data.get("isp", "Unknown"),
                                "source": "ipwhois.io",
                            }

        except asyncio.TimeoutError:
            self.logger.debug(f"Timeout geolocating {ip} with ipwhois.io")
        except aiohttp.ClientError as e:
            self.logger.debug(f"Error with ipwhois.io: {str(e)}")
        except Exception as e:
            self.logger.debug(f"Unexpected error with ipwhois.io: {str(e)}")

        return None

    async def _geolocate_ipinfo(self, ip: str) -> Optional[Dict]:
        """
        Geolocate using ipinfo.io (requires API token for high volume).
        """
        # Check if API token is provided in options
        api_token = self.options.get("ipinfo_token")

        await self.rate_limiter.acquire()

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"https://ipinfo.io/{ip}/json"

                headers = {}
                if api_token:
                    headers["Authorization"] = f"Bearer {api_token}"

                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()

                        # Parse location coordinates
                        loc = data.get("loc", ",").split(",")
                        lat = float(loc[0]) if len(loc) > 0 and loc[0] else None
                        lon = float(loc[1]) if len(loc) > 1 and loc[1] else None

                        await self.rate_limiter.report_success()
                        return {
                            "ip": ip,
                            "country": data.get("country", "Unknown"),
                            "region": data.get("region", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "coordinates": {"latitude": lat, "longitude": lon},
                            "asn": data.get("org", "Unknown"),
                            "isp": data.get("org", "Unknown"),
                            "source": "ipinfo.io",
                        }

        except asyncio.TimeoutError:
            self.logger.debug(f"Timeout geolocating {ip} with ipinfo.io")
        except aiohttp.ClientError as e:
            self.logger.debug(f"Error with ipinfo.io: {str(e)}")
        except Exception as e:
            self.logger.debug(f"Unexpected error with ipinfo.io: {str(e)}")

        return None

    async def _map_third_party_services(self) -> Dict:
        """
        Identify and map third-party service integrations.
        """
        services: Dict[str, Any] = {
            "analytics": [],
            "marketing": [],
            "security": [],
            "infrastructure": [],
            "external_apis": [],
        }

        try:
            await self.rate_limiter.acquire()
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(self.target.url) as response:
                        await self.rate_limiter.report_success()
                        html = await response.text()

                        # Analyze script tags
                        try:
                            soup = BeautifulSoup(html, "lxml")
                        except Exception:
                            soup = BeautifulSoup(html, "html.parser")
                        scripts = soup.find_all("script", src=True)

                        for script in scripts:
                            service = await self._identify_third_party_service(
                                script["src"]
                            )
                            if service:
                                category = service.get("category", "infrastructure")
                                services[category].append(service)

                        # Check for API endpoints
                        services["external_apis"] = await self._discover_external_apis(
                            soup
                        )

                        return services
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    await self.rate_limiter.report_failure()
                    self.logger.error(f"Error mapping third party services {str(e)}")
                    raise

        except Exception as e:
            self.logger.error(f"Third-party service mapping failed: {str(e)}")
            return {"error": str(e)}

    async def _identify_third_party_service(self, script_src: str) -> Optional[Dict]:
        """
        Identify third-party service from script source URL.
        """
        service_signatures = {
            "analytics": {
                "Google Analytics": {
                    "patterns": ["google-analytics.com", "analytics.google.com"],
                    "risk": "low",
                },
                "Mixpanel": {"patterns": ["mixpanel.com", "mxpnl.com"], "risk": "low"},
            },
            "marketing": {
                "HubSpot": {
                    "patterns": ["hubspot.com", "hs-scripts.com"],
                    "risk": "low",
                },
                "Marketo": {"patterns": ["marketo.com", "marketo.net"], "risk": "low"},
            },
            "security": {
                "reCAPTCHA": {
                    "patterns": ["google.com/recaptcha", "gstatic.com/recaptcha"],
                    "risk": "low",
                },
                "Cloudflare": {"patterns": ["cloudflare.com/ajax"], "risk": "low"},
            },
            "infrastructure": {
                "jQuery": {
                    "patterns": ["jquery.com", "code.jquery.com"],
                    "risk": "low",
                },
                "Bootstrap": {
                    "patterns": ["bootstrapcdn.com", "bootstrap.min.js"],
                    "risk": "low",
                },
            },
        }

        try:
            script_src = script_src.lower()

            for category, services in service_signatures.items():
                for service_name, info in services.items():
                    for pattern in info["patterns"]:
                        if pattern in script_src:
                            return {
                                "name": service_name,
                                "category": category,
                                "url": script_src,
                                "risk_level": info["risk"],
                            }

        except Exception as e:
            self.logger.error(f"Service identification failed: {str(e)}")

        return None

    async def _discover_external_apis(self, soup: BeautifulSoup) -> List[Dict]:
        """
        Discover external API endpoints from HTML content.
        """
        apis = []

        try:
            # Look for API endpoints in scripts
            scripts = soup.find_all("script")
            api_patterns = [
                r'https?://api\.[^/"\'\s]+',
                r'https?://[^/"\'\s]+/api/',
                r'https?://[^/"\'\s]+/v\d+/',
                r'https?://[^/"\'\s]+/rest/',
            ]

            for script in scripts:
                # Check script content if available
                if script.string:
                    for pattern in api_patterns:
                        matches = re.finditer(pattern, script.string)
                        for match in matches:
                            api_url = match.group(0)
                            if not api_url.startswith(self.target.url):
                                apis.append(
                                    {
                                        "url": api_url,
                                        "type": "external",
                                        "source": "script",
                                        "risk_level": "medium",
                                    }
                                )

            # Look for API endpoints in data attributes
            elements = soup.find_all(attrs={"data-api": True})
            for element in elements:
                api_url = element.get("data-api")
                if api_url and not api_url.startswith(self.target.url):
                    apis.append(
                        {
                            "url": api_url,
                            "type": "external",
                            "source": "data-attribute",
                            "risk_level": "medium",
                        }
                    )

            # Look for common API formats in link tags
            links = soup.find_all("link", href=True)
            for link in links:
                href = link["href"]
                for pattern in api_patterns:
                    if re.search(pattern, href):
                        if not href.startswith(self.target.url):
                            apis.append(
                                {
                                    "url": href,
                                    "type": "external",
                                    "source": "link",
                                    "risk_level": "medium",
                                }
                            )

            # Deduplicate results
            seen_urls = set()
            unique_apis = []
            for api in apis:
                if api["url"] not in seen_urls:
                    seen_urls.add(api["url"])
                    unique_apis.append(api)

            return unique_apis

        except Exception as e:
            self.logger.error(f"API discovery failed: {str(e)}")
            return []

    async def _map_asset_relationships(self) -> Dict:
        """
        Map relationships between different assets and infrastructure components.
        """
        relationships: Dict[str, Any] = {
            "dependencies": [],
            "connections": [],
            "shared_infrastructure": [],
            "ownership": {},
        }

        try:
            # Get IP block information
            ip_info = await self._get_ip_block_info()
            relationships["ownership"]["ip_blocks"] = ip_info

            # Get ASN information
            asn_info = await self._get_asn_info()
            relationships["ownership"]["asn"] = asn_info

            # Map infrastructure dependencies
            dependencies = await self._map_dependencies()
            relationships["dependencies"] = dependencies

            # Identify shared infrastructure
            shared = await self._identify_shared_infrastructure()
            relationships["shared_infrastructure"] = shared

            return relationships

        except Exception as e:
            self.logger.error(f"Asset relationship mapping failed: {str(e)}")
            return {"error": str(e)}

    async def _get_ip_block_info(self) -> Dict:
        """
        Get information about IP blocks associated with the target.
        """
        ip_info = {
            "blocks": [],
            "total_ips": 0,
            "network_ranges": [],
        }  # type: Dict[str, Any]

        try:
            # Get all IP addresses associated with the domain
            ips: Set[str] = set()
            try:
                a_records = dns.resolver.resolve(self.target.hostname, "A")
                ips.update(str(r) for r in a_records)
            except Exception as e:
                self.logger.error(f"Failed to resolve A records: {str(e)}")

            for ip in ips:
                try:
                    # Query WHOIS information for each IP
                    # Note: In a real implementation, you'd want to use a proper WHOIS library
                    # or API service that respects rate limits
                    whois_info = {
                        "ip": ip,
                        "network": f"{ip}/24",  # Placeholder
                        "organization": "Unknown",
                        "allocation_date": "Unknown",
                    }
                    ip_info["blocks"].append(whois_info)

                except Exception as e:
                    self.logger.error(f"Failed to get WHOIS info for {ip}: {str(e)}")

            # Calculate total IPs and network ranges
            ip_info["total_ips"] = len(ips)
            ip_info["network_ranges"] = [
                block["network"] for block in ip_info["blocks"]
            ]

        except Exception as e:
            self.logger.error(f"IP block information retrieval failed: {str(e)}")

        return ip_info

    async def _get_asn_info(self) -> Dict:
        """
        Get ASN (Autonomous System Number) information for the target.
        """
        asn_info: Dict[str, Any] = {
            "asn": None,
            "organization": None,
            "network_ranges": [],
            "peers": [],
        }

        try:
            # Get IP addresses
            ips: Set[str] = set()
            try:
                a_records = dns.resolver.resolve(self.target.hostname, "A")
                ips.update(str(r) for r in a_records)
            except Exception as e:
                self.logger.error(f"Failed to resolve A records: {str(e)}")

            if ips:
                # For the first IP, try to get ASN information
                # Note: In a real implementation, you'd want to use a proper ASN
                # lookup service or database
                first_ip = next(iter(ips))
                # Placeholder ASN data
                asn_info.update(
                    {
                        "asn": "AS12345",
                        "organization": "Example Network",
                        "network_ranges": [f"{first_ip}/24"],
                        "peers": ["AS54321", "AS98765"],
                    }
                )

        except Exception as e:
            self.logger.error(f"ASN information retrieval failed: {str(e)}")

        return asn_info

    async def _map_dependencies(self) -> List[Dict]:
        """
        Map infrastructure dependencies by analyzing connections and services.
        """
        dependencies = []

        try:
            await self.rate_limiter.acquire()
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(self.target.url) as response:
                        await self.rate_limiter.report_success()
                        html = await response.text()
                        try:
                            soup = BeautifulSoup(html, "lxml")
                        except Exception:
                            soup = BeautifulSoup(html, "html.parser")

                        # Check for external resources
                        external_resources = {
                            "scripts": soup.find_all("script", src=True),
                            "stylesheets": soup.find_all("link", rel="stylesheet"),
                            "images": soup.find_all("img", src=True),
                            "fonts": soup.find_all("link", rel="stylesheet"),
                        }

                        for resource_type, elements in external_resources.items():
                            for element in elements:
                                url = element.get("src") or element.get("href")
                                if url and not url.startswith(("data:", "blob:")):
                                    try:
                                        parsed_url = urlparse(url)
                                        if (
                                            parsed_url.netloc
                                            and parsed_url.netloc
                                            != self.target.hostname
                                        ):
                                            dependencies.append(
                                                {
                                                    "type": resource_type,
                                                    "url": url,
                                                    "domain": parsed_url.netloc,
                                                    "status": "active",
                                                }
                                            )
                                    except Exception:
                                        self.logger.debug(
                                            f"Failed to parse URL {url} for dependency mapping",
                                            exc_info=False,
                                        )
                                        continue

                        # Check for API dependencies
                        api_dependencies = await self._discover_external_apis(soup)
                        dependencies.extend(
                            [
                                {"type": "api", "url": api["url"], "status": "active"}
                                for api in api_dependencies
                            ]
                        )
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    await self.rate_limiter.report_failure()
                    self.logger.error(f"Could not map dependencies {str(e)}")
                    raise
        except Exception as e:
            self.logger.error(f"Dependency mapping failed: {str(e)}")

        return dependencies

    async def _identify_shared_infrastructure(self) -> List[Dict]:
        """
        Identify infrastructure shared with other domains or services.
        """
        shared_infra = []

        try:
            # Get IP addresses for the target
            target_ips: Set[str] = set()
            try:
                a_records = dns.resolver.resolve(self.target.hostname, "A")
                target_ips.update(str(r) for r in a_records)
            except Exception as e:
                self.logger.error(f"Failed to resolve A records: {str(e)}")

            # Check reverse DNS for each IP
            for ip in target_ips:
                try:
                    ptr_records = dns.resolver.resolve_address(ip)
                    domains = [str(r) for r in ptr_records]

                    if len(domains) > 1:
                        shared_infra.append(
                            {
                                "type": "shared_ip",
                                "ip": ip,
                                "domains": domains,
                                "risk_level": "medium" if len(domains) > 5 else "low",
                            }
                        )
                except Exception:
                    self.logger.debug(
                        f"Reverse DNS lookup failed for {ip}", exc_info=False
                    )
                    continue

            # Check for shared name servers
            try:
                ns_records = dns.resolver.resolve(self.target.hostname, "NS")
                nameservers = [str(r) for r in ns_records]

                for ns in nameservers:
                    try:
                        # This would need to be replaced with a proper zone transfer or
                        # DNS enumeration service in a real implementation
                        shared_infra.append(
                            {
                                "type": "shared_nameserver",
                                "nameserver": ns,
                                "risk_level": "low",
                            }
                        )
                    except Exception:
                        self.logger.debug(
                            f"Failed to check nameserver {ns} for shared infrastructure",
                            exc_info=False,
                        )
                        continue

            except Exception as e:
                self.logger.error(f"Nameserver check failed: {str(e)}")

            # Check for shared SSL certificates
            if self.target.is_https:
                try:
                    shared_cert_domains = await self._check_shared_certificates()
                    if shared_cert_domains:
                        shared_infra.append(
                            {
                                "type": "shared_ssl_certificate",
                                "domains": shared_cert_domains,
                                "risk_level": "low",
                            }
                        )
                except Exception as e:
                    self.logger.error(f"SSL certificate check failed: {str(e)}")

        except Exception as e:
            self.logger.error(f"Shared infrastructure identification failed: {str(e)}")

        return shared_infra

    async def _check_shared_certificates(self) -> List[str]:
        """
        Check for other domains sharing the same SSL certificate.
        """
        shared_domains = []

        try:
            # Create SSL context
            context = ssl.create_default_context()
            with socket.create_connection((self.target.hostname, 443)) as sock:
                with context.wrap_socket(
                    sock, server_hostname=self.target.hostname
                ) as ssock:
                    cert = ssock.getpeercert()

                    # Get all subject alternative names
                    if cert and "subjectAltName" in cert and cert["subjectAltName"]:
                        san = cert.get("subjectAltName")
                        if isinstance(san, (list, tuple)):
                            for item in san:
                                if (
                                    isinstance(item, (list, tuple))
                                    and len(item) == 2
                                    and isinstance(item[0], str)
                                    and isinstance(item[1], str)
                                ):
                                    type_name, name = item[0], item[1]
                                    if (
                                        type_name == "DNS"
                                        and name != self.target.hostname
                                    ):
                                        shared_domains.append(name)

        except Exception as e:
            self.logger.error(f"Certificate check failed: {str(e)}")

        return shared_domains
