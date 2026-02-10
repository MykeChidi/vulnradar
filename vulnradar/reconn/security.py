# vulnradar/reconn/security.py - Security Infrastructure Analysis Module
import asyncio
import re
import socket
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
import OpenSSL

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


class SecurityInfrastructureAnalyzer:
    """
    Handles security infrastructure analysis including WAF detection,
    SSL/TLS analysis, and security header analysis.
    """

    def __init__(self, target: ReconTarget, options: Dict):
        self.target = target
        self.options = options
        self.logger = setup_logger("security_recon", file_specific=True)
        self.rate_limiter = RateLimiter()

        # Initialize cache
        self._cache: Optional[ScanCache]
        if not options.get("no_cache", False):
            cache_dir = Path(options.get("cache_dir", "cache")) / "security"
            self._cache = ScanCache(
                cache_dir, default_ttl=options.get("cache_ttl", 3600)
            )
        else:
            self._cache = None

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Security reconnaissance analysis encountered an error",
        return_on_error={},
    )
    async def analyze(self) -> Dict:
        """
        Perform comprehensive security infrastructure analysis.

        Returns:
            Dict containing all security infrastructure findings
        """
        results = {}

        # Analyze WAF/IPS
        if self.options.get("detect_waf", True):
            results["waf"] = await self._detect_waf()

        # Analyze SSL/TLS
        if self.target.is_https:
            results["ssl_tls"] = await self._analyze_ssl_tls()

        # Analyze security headers
        results["security_headers"] = await self._analyze_security_headers()

        return results

    async def _detect_waf(self) -> Dict:
        """
        Enhanced WAF detection using multiple techniques.
        """
        waf_results: Dict[str, Any] = {
            "detected": False,
            "type": None,
            "confidence": 0,
            "evidence": [],
        }

        try:
            # Check for common WAF headers
            header_results = await self._check_waf_headers()
            if header_results["detected"]:
                waf_results.update(header_results)
                # Ensure evidence remains a list to satisfy typing
                if not isinstance(waf_results.get("evidence"), list):
                    waf_results["evidence"] = []

            # Behavioral analysis
            if not waf_results["detected"]:
                behavior_results = await self._analyze_waf_behavior()
                if behavior_results["detected"]:
                    waf_results.update(behavior_results)
                    # Ensure evidence remains a list to satisfy typing
                    if not isinstance(waf_results.get("evidence"), list):
                        waf_results["evidence"] = []

            # Rate limiting detection
            rate_limit_info = await self._detect_rate_limits()
            if rate_limit_info["detected"]:
                waf_results["evidence"].append("Rate limiting detected")
                waf_results["detected"] = True

            return waf_results

        except Exception as e:
            self.logger.error(f"WAF detection failed: {str(e)}")
            return {"error": str(e)}

    async def _check_waf_headers(self) -> Dict:
        """Check response headers for WAF signatures."""
        waf_signatures = {
            "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status"],
            "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"],
            "Imperva": ["x-iinfo", "x-cdn", "incap_ses"],
            "Akamai": ["x-akamai-transformed", "akamai-origin-hop"],
            "F5 BIG-IP": ["x-cnection", "x-wa-info"],
            "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        }

        result: Dict[str, Any] = {"detected": False, "type": None, "evidence": []}

        try:
            await self.rate_limiter.acquire()
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                try:
                    headers_param = self.options.get("headers", {})
                    if not isinstance(headers_param, dict):
                        headers_param = {}
                    async with session.get(
                        self.target.url, headers=headers_param
                    ) as response:
                        await self.rate_limiter.report_success()
                        headers = response.headers
                        for waf_name, signatures in waf_signatures.items():
                            for signature in signatures:
                                if signature.lower() in [
                                    h.lower() for h in headers.keys()
                                ]:
                                    result["detected"] = True
                                    result["type"] = waf_name
                                    result["evidence"].append(
                                        f"Found header: {signature}"
                                    )
                                    return result
                except aiohttp.ClientResponseError as e:
                    if e.status == 429:
                        await self.rate_limiter.report_failure(is_rate_limit=True)
                    else:
                        await self.rate_limiter.report_failure()
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    await self.rate_limiter.report_failure()

            return result
        except aiohttp.ClientConnectorError as e:
            self.logger.error(f"Connection failed for WAF header check: {str(e)}")
            return {
                "detected": False,
                "error": "connection_failed",
                "message": "Cannot connect to target",
            }
        except aiohttp.ClientResponseError as e:
            self.logger.warning(f"HTTP error during WAF check: {e.status}")
            return {"detected": False, "error": "http_error", "status": e.status}
        except asyncio.TimeoutError:
            self.logger.warning("Timeout during WAF header check")
            return {"detected": False, "error": "timeout", "retryable": True}
        except aiohttp.ClientError as e:
            self.logger.error(f"Client error during WAF check: {str(e)}")
            return {"detected": False, "error": "client_error", "message": str(e)}
        except Exception as e:
            self.logger.exception(f"Unexpected error in WAF header check: {str(e)}")
            return {"detected": False, "error": "unexpected", "message": str(e)}

    async def _analyze_waf_behavior(self) -> Dict:
        """Analyze WAF behavior using various test payloads."""
        test_payloads = [
            ("Safe XSS Test", "<test>"),
            ("Safe SQL Test", "' AND '1'='1"),
            ("Path Test", "../test"),
        ]

        result: Dict[str, Any] = {"detected": False, "type": None, "evidence": []}

        try:
            async with aiohttp.ClientSession() as session:
                for attack_type, payload in test_payloads:
                    url = f"{self.target.url}?test={payload}"
                    await self.rate_limiter.acquire()
                    try:
                        headers_param = self.options.get("headers", {})
                        if not isinstance(headers_param, dict):
                            headers_param = {}
                        async with session.get(url, headers=headers_param) as response:
                            await self.rate_limiter.report_success()
                            if response.status == 403 or response.status == 406:
                                result["detected"] = True
                                result["evidence"].append(
                                    f"Blocked {attack_type} attempt"
                                )

                            # Check response body for WAF block pages
                            body = await response.text()
                            if any(
                                sig in body.lower()
                                for sig in [
                                    "blocked",
                                    "forbidden",
                                    "waf",
                                    "security block",
                                ]
                            ):
                                result["detected"] = True
                                result["evidence"].append(
                                    f"WAF block page detected for {attack_type}"
                                )
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        await self.rate_limiter.report_failure()
                        continue
            return result
        except Exception as e:
            self.logger.error(f"WAF behavior analysis failed: {str(e)}")
            return {"detected": False, "error": str(e)}

    async def _detect_rate_limits(self) -> Dict:
        """Detect rate limiting by sending rapid requests."""
        result: Dict[str, Any] = {"detected": False, "evidence": []}

        try:
            async with aiohttp.ClientSession() as session:
                tasks = []
                headers_param = self.options.get("headers", {})
                if not isinstance(headers_param, dict):
                    headers_param = {}
                for _ in range(20):  # Send 20 requests rapidly
                    tasks.append(session.get(self.target.url, headers=headers_param))

                responses = await asyncio.gather(*tasks, return_exceptions=True)

                for resp in responses:
                    if isinstance(resp, aiohttp.ClientResponse):
                        if resp.status == 429:  # Too Many Requests
                            result["detected"] = True
                            result["evidence"].append("Received 429 Too Many Requests")
                            return result

                        headers = resp.headers
                        rate_limit_headers = [
                            "x-ratelimit-limit",
                            "x-ratelimit-remaining",
                            "retry-after",
                            "ratelimit-reset",
                        ]

                        for header in rate_limit_headers:
                            if header in headers:
                                result["detected"] = True
                                result["evidence"].append(
                                    f"Found rate limit header: {header}"
                                )

            return result
        except Exception as e:
            self.logger.error(f"Rate limit detection failed: {str(e)}")
            return {"detected": False, "error": str(e)}

    async def _analyze_ssl_tls(self) -> Dict:
        """
        Comprehensive SSL/TLS analysis.
        """
        ssl_results: Dict[str, Any] = {
            "protocols": {},
            "cipher_suites": [],
            "certificate": {},
            "vulnerabilities": [],
            "configuration": {},
        }

        try:
            # Check supported protocols
            ssl_results["protocols"] = await self._check_ssl_protocols()

            # Analyze certificate
            ssl_results["certificate"] = await self._analyze_certificate()

            # Check for known vulnerabilities
            ssl_results["vulnerabilities"] = await self._check_ssl_vulnerabilities()

            # Analyze cipher suites
            ssl_results["cipher_suites"] = await self._analyze_cipher_suites()

            return ssl_results

        except Exception as e:
            self.logger.error(f"SSL/TLS analysis failed: {str(e)}")
            return {"error": str(e)}

    async def _check_ssl_protocols(self) -> Dict:
        """
        Test support for different SSL/TLS protocol versions.
        """
        results = {}

        # Define protocols to test
        protocols_to_test = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]

        port = 443 if self.target.is_https else 80

        for protocol_name, protocol_version in protocols_to_test:
            try:
                # Create context with specific protocol version
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = protocol_version
                context.maximum_version = protocol_version

                # Disable certificate verification for testing
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Try to connect
                loop = asyncio.get_event_loop()

                def test_connection():
                    with socket.create_connection(
                        (self.target.hostname, port), timeout=10
                    ) as sock:
                        with context.wrap_socket(
                            sock, server_hostname=self.target.hostname
                        ) as ssock:
                            return {
                                "supported": True,
                                "cipher": ssock.cipher(),
                                "version": ssock.version(),
                                "protocol": protocol_name,
                            }

                # Run in executor to avoid blocking
                result = await loop.run_in_executor(None, test_connection)
                results[protocol_name] = result

                cipher_val = result.get("cipher")
                cipher_name = (
                    cipher_val[0]
                    if isinstance(cipher_val, (list, tuple)) and len(cipher_val) > 0
                    else "unknown"
                )
                self.logger.debug(f"{protocol_name}: Supported (cipher: {cipher_name})")

            except ssl.SSLError as e:
                error_msg = str(e)
                results[protocol_name] = {
                    "supported": False,
                    "error": error_msg,
                    "reason": "SSL handshake failed",
                }
                self.logger.debug(f"{protocol_name}: Not supported ({error_msg})")

            except socket.timeout:
                results[protocol_name] = {
                    "supported": False,
                    "error": "timeout",
                    "reason": "Connection timeout",
                }
                self.logger.debug(f"{protocol_name}: Timeout")

            except ConnectionRefusedError:
                results[protocol_name] = {
                    "supported": False,
                    "error": "connection_refused",
                    "reason": "Connection refused",
                }
                # If connection is refused, likely not an HTTPS port
                break

            except socket.gaierror as e:
                results[protocol_name] = {
                    "supported": False,
                    "error": "dns_error",
                    "reason": f"DNS resolution failed: {str(e)}",
                }
                # DNS error affects all protocols
                break

            except Exception as e:
                results[protocol_name] = {
                    "supported": False,
                    "error": "unexpected",
                    "reason": str(e),
                }
                self.logger.debug(f"{protocol_name}: Unexpected error - {str(e)}")

        # Add security assessment
        results["assessment"] = self._assess_protocol_support(results)

        return results

    def _assess_protocol_support(self, results: Dict) -> Dict:
        """
        Assess the security of supported protocols.

        Args:
            results: Dictionary of protocol test results

        Returns:
            Security assessment
        """
        assessment: Dict[str, Any] = {
            "secure": True,
            "warnings": [],
            "recommendations": [],
        }

        # Check for insecure protocols
        if results.get("TLSv1.0", {}).get("supported"):
            assessment["secure"] = False
            assessment["warnings"].append(
                "TLS 1.0 is deprecated and should be disabled"
            )
            assessment["recommendations"].append("Disable TLS 1.0 support")

        if results.get("TLSv1.1", {}).get("supported"):
            assessment["secure"] = False
            assessment["warnings"].append(
                "TLS 1.1 is deprecated and should be disabled"
            )
            assessment["recommendations"].append("Disable TLS 1.1 support")

        # Check for modern protocols
        if not results.get("TLSv1.2", {}).get("supported"):
            assessment["warnings"].append("TLS 1.2 is not supported")
            assessment["recommendations"].append("Enable TLS 1.2 support")

        if not results.get("TLSv1.3", {}).get("supported"):
            assessment["recommendations"].append(
                "Consider enabling TLS 1.3 for better security"
            )

        return assessment

    async def _analyze_certificate(self) -> Dict:
        """Analyze SSL certificate details."""
        try:
            cert_info: Dict[str, Any] = {}
            context = ssl.create_default_context()
            with socket.create_connection((self.target.hostname, 443)) as sock:
                with context.wrap_socket(
                    sock, server_hostname=self.target.hostname
                ) as ssock:
                    cert = ssock.getpeercert()

                    if not cert:
                        return {
                            "error": "no_certificate",
                            "message": "No certificate presented by server",
                        }

                    # Safely build subject and issuer dictionaries
                    subjects_raw: Any = cert.get("subject", [])
                    if isinstance(subjects_raw, list):
                        subjects: List[Any] = subjects_raw
                    else:
                        subjects = [subjects_raw]
                    subject_dict: Dict[str, str] = {}
                    for item in subjects:
                        if isinstance(item, (list, tuple)) and item:
                            first = item[0]
                            if isinstance(first, (list, tuple)) and len(first) >= 2:
                                subject_dict[str(first[0])] = str(first[1])
                    cert_info["subject"] = subject_dict

                    issuers_raw: Any = cert.get("issuer", [])
                    if isinstance(issuers_raw, list):
                        issuers: List[Any] = issuers_raw
                    else:
                        issuers = [issuers_raw]
                    issuer_dict: Dict[str, str] = {}
                    for item in issuers:
                        if isinstance(item, (list, tuple)) and item:
                            first = item[0]
                            if isinstance(first, (list, tuple)) and len(first) >= 2:
                                issuer_dict[str(first[0])] = str(first[1])
                    cert_info["issuer"] = issuer_dict
                    cert_info["version"] = cert["version"]
                    cert_info["serialNumber"] = cert["serialNumber"]
                    cert_info["notBefore"] = cert["notBefore"]
                    cert_info["notAfter"] = cert["notAfter"]
                    cert_info["subjectAltName"] = cert.get("subjectAltName", [])

                    # Get the certificate in DER format
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        return {
                            "error": "no_certificate",
                            "message": "No certificate presented by server",
                        }

                    x509 = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1, der_cert
                    )

                    # Get signature algorithm
                    cert_info["signatureAlgorithm"] = (
                        x509.get_signature_algorithm().decode()
                    )

                    # Get public key details
                    pubkey = x509.get_pubkey()
                    cert_info["publicKeySize"] = pubkey.bits()
                    cert_info["publicKeyType"] = pubkey.type()

            return cert_info

        except socket.timeout:
            error_msg = f"Timeout connecting for certificate analysis on {self.target.hostname}:{self.target.port}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "port": self.target.port,
                    "error_type": "timeout",
                    "retryable": True,
                },
            )
            return {
                "error": "timeout",
                "message": "Connection timeout",
                "retryable": True,
            }
        except socket.gaierror as e:
            error_msg = f"DNS resolution failed for {self.target.hostname}: {str(e)}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "dns_resolution_failed",
                },
            )
            return {"error": "dns_failed", "message": "Cannot resolve hostname"}
        except ConnectionRefusedError:
            error_msg = f"Connection refused on {self.target.hostname}:443"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "port": 443,
                    "error_type": "connection_refused",
                },
            )
            return {
                "error": "connection_refused",
                "message": "Server refused connection on port 443",
            }
        except ssl.SSLError as e:
            error_msg = f"SSL error analyzing {self.target.hostname}: {str(e)}"
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "ssl_error",
                    "ssl_error_details": str(e),
                },
            )
            return {"error": "ssl_error", "message": str(e)}
        except OpenSSL.crypto.Error as e:
            error_msg = (
                f"Certificate parsing error for {self.target.hostname}: {str(e)}"
            )
            self.logger.error(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "cert_parse_error",
                },
            )
            return {"error": "parse_error", "message": "Failed to parse certificate"}
        except Exception as e:
            error_msg = f"Unexpected error in certificate analysis for {self.target.hostname}: {str(e)}"
            self.logger.exception(error_msg)
            error_handler.handle_error(
                NetworkError(error_msg),
                context={
                    "hostname": self.target.hostname,
                    "error_type": "unexpected_cert_error",
                },
            )
            return {"error": "unexpected", "message": str(e)}

    async def _check_ssl_vulnerabilities(self) -> List[Dict]:
        """Check for known SSL/TLS vulnerabilities."""
        vulnerabilities = []

        try:
            # Check for CRIME
            crime_vulnerable = await self._check_crime_vulnerability()
            if crime_vulnerable:
                vulnerabilities.append(
                    {
                        "name": "CRIME",
                        "severity": "High",
                        "description": "TLS compression enabled, vulnerable to CRIME attack",
                    }
                )

            # Check for BEAST
            beast_vulnerable = await self._check_beast_vulnerability()
            if beast_vulnerable:
                vulnerabilities.append(
                    {
                        "name": "BEAST",
                        "severity": "Medium",
                        "description": "CBC in TLS 1.0 vulnerable to BEAST attack",
                    }
                )

            # Check for Heartbleed
            heartbleed_vulnerable = await self._check_heartbleed_vulnerability()
            if heartbleed_vulnerable:
                vulnerabilities.append(
                    {
                        "name": "Heartbleed",
                        "severity": "Critical",
                        "description": "OpenSSL heartbeat vulnerable to Heartbleed",
                    }
                )

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Vulnerability check failed: {str(e)}")
            return [{"error": str(e)}]

    async def _check_crime_vulnerability(self) -> bool:
        """
        Check if the server is vulnerable to CRIME attack.
        CRIME (Compression Ratio Info-leak Made Easy) exploits TLS compression.
        """
        try:
            context = ssl.create_default_context()

            # Create a connection with specific SSL options
            with socket.create_connection((self.target.hostname, 443)) as sock:
                with context.wrap_socket(
                    sock, server_hostname=self.target.hostname
                ) as ssock:
                    # Check if compression is enabled
                    compression = ssock.compression()
                    if compression is not None and compression != "":
                        return True

                    # Check for TLS compression support
                    try:
                        # Send a request with Accept-Encoding to check compression
                        request = (
                            b"GET / HTTP/1.1\r\n"
                            b"Host: " + self.target.hostname.encode() + b"\r\n"
                            b"Accept-Encoding: gzip, deflate\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                        ssock.send(request)
                        response = ssock.recv(4096)

                        # Check if response indicates compression support
                        if b"Content-Encoding:" in response:
                            return True
                    except Exception:
                        self.logger.debug(
                            "TLS compression support failed, assuming not vulnerable",
                            exc_info=False,
                        )
                        pass

            return False

        except Exception as e:
            self.logger.error(f"CRIME vulnerability check failed: {str(e)}")
            return False

    async def _check_beast_vulnerability(self) -> bool:
        """
        Check if the server is vulnerable to BEAST attack.
        BEAST (Browser Exploit Against SSL/TLS) affects TLS 1.0 and earlier with CBC mode ciphers.
        """
        try:
            context = ssl.create_default_context()

            # Force TLS 1.0 to check BEAST vulnerability
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1

            with socket.create_connection((self.target.hostname, 443)) as sock:
                try:
                    with context.wrap_socket(
                        sock, server_hostname=self.target.hostname
                    ) as ssock:
                        # Check if using CBC cipher
                        cipher = ssock.cipher()
                        if isinstance(cipher, (list, tuple)) and len(cipher) > 0:
                            cipher_name = str(cipher[0]).upper()
                        else:
                            cipher_name = ""

                        # BEAST affects CBC ciphers in TLS 1.0
                        is_vulnerable = (
                            "CBC" in cipher_name
                            and ssock.version() == "TLSv1"
                            and not ("GCM" in cipher_name or "CCM" in cipher_name)
                        )

                        return is_vulnerable
                except ssl.SSLError:
                    # If connection fails with TLS 1.0, server is not vulnerable
                    return False

        except Exception as e:
            self.logger.error(f"BEAST vulnerability check failed: {str(e)}")
            return False

    async def _check_heartbleed_vulnerability(self) -> bool:
        """
        Check if the server is vulnerable to Heartbleed.
        Heartbleed affects OpenSSL 1.0.1 through 1.0.1f.
        """
        try:
            # Check server headers for OpenSSL version
            await self.rate_limiter.acquire()
            async with aiohttp.ClientSession() as session:
                try:
                    timeout = aiohttp.ClientTimeout(total=10)
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with session.get(
                        self.target.url, timeout=timeout
                    ) as response:
                        await self.rate_limiter.report_success()
                        server_header = response.headers.get("Server", "").lower()

                        # Check for vulnerable OpenSSL versions in Server header
                        if "openssl/1.0.1" in server_header:
                            # Extract version letter
                            match = re.search(r"openssl/1\.0\.1([a-z]?)", server_header)
                            if match:
                                version_letter = match.group(1)
                                # Vulnerable: 1.0.1 through 1.0.1f (inclusive)
                                # Fixed: 1.0.1g and later
                                if not version_letter or version_letter <= "f":
                                    self.logger.warning(
                                        f"Potentially vulnerable OpenSSL version detected: {server_header}"
                                    )
                                    return True
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    await self.rate_limiter.report_failure()
                    self.logger.debug(f"Could not check headers: {str(e)}")

            try:
                # Check SSL certificate and handshake details
                # First, get OpenSSL version from the certificate
                context = ssl.create_default_context()
                with socket.create_connection((self.target.hostname, 443)) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=self.target.hostname
                    ) as ssock:
                        # Get SSL version being used
                        ssl_version = ssock.version()
                        cipher = ssock.cipher()

                        # Log for manual review
                        self.logger.debug(
                            f"SSL Version: {ssl_version}, Cipher: {cipher}"
                        )
                        cert = ssock.getpeercert(binary_form=True)
                        if cert:
                            x509 = OpenSSL.crypto.load_certificate(
                                OpenSSL.crypto.FILETYPE_ASN1, cert
                            )
                            # Get certificate signature algorithm
                            sig_alg = x509.get_signature_algorithm().decode()
                            self.logger.debug(
                                f"Certificate signature algorithm: {sig_alg}"
                            )
                        else:
                            self.logger.debug(
                                "No certificate in handshake; skipping x509 checks"
                            )

                        # Check server software from response headers
                        async with aiohttp.ClientSession() as session:
                            async with session.get(self.target.url) as response:
                                server = response.headers.get("Server", "")

                                # Check for vulnerable OpenSSL versions
                                if "openssl/1.0.1" in server.lower():
                                    version_parts = server.lower().split(
                                        "openssl/1.0.1"
                                    )
                                    if len(version_parts) > 1:
                                        version_letter = version_parts[1][0:1]
                                        # Vulnerable versions: 1.0.1 through 1.0.1f
                                        if not version_letter or version_letter <= "f":
                                            return True

                return False
            except ssl.SSLError as e:
                self.logger.debug(f"SSL connection details unavailable: {str(e)}")
            except socket.timeout:
                self.logger.debug("Timeout during SSL check")
            except Exception as e:
                self.logger.debug(f"Certificate check error: {str(e)}")

            # Method 3: Check for known vulnerable platforms/distributions
            # by examining server behavior patterns (passive)
            try:
                async with aiohttp.ClientSession() as session:
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with session.get(
                        self.target.url, timeout=timeout
                    ) as response:
                        # Check for other headers that might indicate old software
                        headers_to_check = [
                            "X-Powered-By",
                            "X-AspNet-Version",
                            "X-Runtime",
                        ]

                        for header in headers_to_check:
                            value = response.headers.get(header, "").lower()
                            if value:
                                self.logger.debug(f"{header}: {value}")

                                # Look for old software versions that shipped with vulnerable OpenSSL
                                vulnerable_patterns = [
                                    "ubuntu/12.04",
                                    "debian/7",
                                    "centos/6",
                                    "rhel/6",
                                ]

                                for pattern in vulnerable_patterns:
                                    if pattern in value:
                                        self.logger.warning(
                                            "Server may be running OS version that shipped with vulnerable OpenSSL"
                                        )

            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

            return False
        except Exception as e:
            self.logger.error(f"Heartbleed vulnerability check failed: {str(e)}")
        return False

    async def _analyze_cipher_suites(self) -> List[Dict]:
        """Analyze supported cipher suites and their security."""
        ciphers = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target.hostname, 443)) as sock:
                with context.wrap_socket(
                    sock, server_hostname=self.target.hostname
                ) as ssock:
                    cipher = ssock.cipher()
                    if isinstance(cipher, (list, tuple)) and len(cipher) >= 3:
                        cipher_name = cipher[0]
                        cipher_bits = cipher[2]
                    else:
                        cipher_name = "unknown"
                        cipher_bits = 0

                    ciphers.append(
                        {
                            "name": cipher_name,
                            "bits": cipher_bits,
                            "security_level": self._assess_cipher_security(
                                cipher_name, cipher_bits
                            ),
                        }
                    )

            return ciphers

        except Exception as e:
            self.logger.error(f"Cipher suite analysis failed: {str(e)}")
            return [{"error": str(e)}]

    def _assess_cipher_security(self, cipher_name: str, bits: int) -> str:
        """Assess the security level of a cipher suite."""
        if "NULL" in cipher_name or "anon" in cipher_name:
            return "Critical"
        elif "RC4" in cipher_name or "DES" in cipher_name:
            return "Low"
        elif bits < 128:
            return "Low"
        elif "GCM" in cipher_name and bits >= 256:
            return "High"
        else:
            return "Medium"

    async def _analyze_security_headers(self) -> Dict:
        """
        Analyze security-related HTTP headers.
        """
        present: Dict[str, Any] = {}
        missing: List[str] = []
        misconfigured: List[Dict[str, Any]] = []
        recommendations: List[str] = []
        headers_results: Dict[str, Any] = {
            "present": present,
            "missing": missing,
            "misconfigured": misconfigured,
            "recommendations": recommendations,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target.url) as response:
                    headers = response.headers

                    # Check for required security headers
                    security_headers = {
                        "Strict-Transport-Security": self._check_hsts,
                        "Content-Security-Policy": self._check_csp,
                        "X-Frame-Options": self._check_xfo,
                        "X-Content-Type-Options": self._check_xcto,
                        "X-XSS-Protection": self._check_xss_protection,
                        "Referrer-Policy": self._check_referrer_policy,
                    }

                    for header, checker in security_headers.items():
                        if header in headers:
                            result = await checker(headers[header])
                            headers_results["present"][header] = result
                            if result.get("issues"):
                                headers_results["misconfigured"].append(
                                    {
                                        "header": header,
                                        "issues": result["issues"],
                                        "recommendations": result.get(
                                            "recommendations", []
                                        ),
                                    }
                                )
                        else:
                            headers_results["missing"].append(header)
                            if header in [
                                "Strict-Transport-Security",
                                "Content-Security-Policy",
                            ]:
                                headers_results["recommendations"].append(
                                    f"Add {header} header for enhanced security"
                                )

                    return headers_results

        except Exception as e:
            self.logger.error(f"Security header analysis failed: {str(e)}")
            return {"error": str(e)}

    async def _check_hsts(self, value: str) -> Dict:
        """Check HSTS header configuration."""
        result: Dict[str, Any] = {"valid": False, "issues": [], "recommendations": []}
        issues: List[str] = []
        recommendations: List[str] = []

        try:
            directives = [d.strip() for d in value.split(";")]
            max_age = None
            include_subdomains = False
            preload = False

            for directive in directives:
                if "max-age" in directive:
                    max_age = int(directive.split("=")[1])
                elif "includeSubDomains" in directive:
                    include_subdomains = True
                elif "preload" in directive:
                    preload = True

            result["valid"] = True
            result["max_age"] = max_age
            result["include_subdomains"] = include_subdomains
            result["preload"] = preload

            # Check for best practices
            if isinstance(max_age, int) and max_age < 31536000:  # Less than 1 year
                issues.append("max-age is less than 1 year")
                recommendations.append(
                    "Increase max-age to at least 31536000 seconds (1 year)"
                )

            if not include_subdomains:
                recommendations.append("Consider adding includeSubDomains directive")

            if not preload:
                recommendations.append(
                    "Consider adding preload directive for maximum security"
                )

        except Exception as e:
            result["valid"] = False
            issues.append(f"Invalid HSTS header: {str(e)}")

        result["issues"] = issues
        result["recommendations"] = recommendations
        return result

    async def _check_csp(self, value: str) -> Dict:
        """Check Content Security Policy configuration."""
        result: Dict[str, Any] = {
            "valid": False,
            "directives": {},
            "issues": [],
            "recommendations": [],
        }
        issues: List[str] = []
        recommendations: List[str] = []

        try:
            directives = [d.strip() for d in value.split(";")]

            for directive in directives:
                if directive:
                    parts = directive.split()
                    if parts:
                        directive_name = parts[0]
                        directive_values = parts[1:] if len(parts) > 1 else []
                        result["directives"][directive_name] = directive_values

            # Check for common security issues
            if "default-src" not in result["directives"]:
                issues.append("Missing default-src directive")
                recommendations.append("Add default-src directive")

            if "'unsafe-inline'" in str(result["directives"]):
                issues.append("Uses unsafe-inline which is not recommended")
                recommendations.append(
                    "Remove 'unsafe-inline' and use nonces or hashes instead"
                )

            if "'unsafe-eval'" in str(result["directives"]):
                issues.append("Uses unsafe-eval which is not recommended")
                recommendations.append(
                    "Remove 'unsafe-eval' and refactor code to avoid eval()"
                )

            result["valid"] = True

        except Exception as e:
            issues.append(f"Invalid CSP header: {str(e)}")

        result["issues"] = issues
        result["recommendations"] = recommendations
        return result

    async def _check_xfo(self, value: str) -> Dict:
        """Check X-Frame-Options header configuration."""
        result: Dict[str, Any] = {"valid": False, "issues": [], "recommendations": []}

        valid_values = ["DENY", "SAMEORIGIN"]
        value = value.upper()

        if value in valid_values:
            result["valid"] = True
            result["value"] = value
        else:
            result["issues"].append(f"Invalid X-Frame-Options value: {value}")
            result["recommendations"].append(f"Use one of: {', '.join(valid_values)}")

        return result

    async def _check_xcto(self, value: str) -> Dict:
        """Check X-Content-Type-Options header configuration."""
        result: Dict[str, Any] = {"valid": False, "issues": [], "recommendations": []}

        if value.lower() == "nosniff":
            result["valid"] = True
        else:
            result["issues"].append("Invalid X-Content-Type-Options value")
            result["recommendations"].append("Set value to 'nosniff'")

        return result

    async def _check_xss_protection(self, value: str) -> Dict:
        """Check X-XSS-Protection header configuration."""
        result: Dict[str, Any] = {"valid": False, "issues": [], "recommendations": []}

        try:
            parts = value.split(";")
            mode = parts[0].strip()

            if mode in ["0", "1"]:
                result["valid"] = True
                result["mode"] = mode

                if len(parts) > 1 and "mode=block" in parts[1]:
                    result["block"] = True

                if mode == "0":
                    result["recommendations"].append(
                        "Consider enabling XSS protection with mode=block"
                    )

            else:
                result["issues"].append("Invalid X-XSS-Protection value")
                result["recommendations"].append(
                    "Use '1; mode=block' for best protection"
                )

        except Exception as e:
            result["issues"].append(f"Invalid X-XSS-Protection header: {str(e)}")

        return result

    async def _check_referrer_policy(self, value: str) -> Dict:
        """Check Referrer-Policy header configuration."""
        result: Dict[str, Any] = {"valid": False, "issues": [], "recommendations": []}

        valid_values = [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        ]

        value = value.lower()

        if value in valid_values:
            result["valid"] = True
            result["value"] = value

            if value == "unsafe-url":
                result["issues"].append(
                    "Using unsafe-url which may leak referrer information"
                )
                result["recommendations"].append(
                    "Consider using 'strict-origin-when-cross-origin' instead"
                )

        else:
            result["issues"].append(f"Invalid Referrer-Policy value: {value}")
            result["recommendations"].append(f"Use one of: {', '.join(valid_values)}")

        return result
