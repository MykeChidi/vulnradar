# vulnradar/recon.py - Advanced Reconnaissance module

import asyncio
from pathlib import Path
from typing import Dict, Optional, Union
from urllib.parse import urlparse

from .reconn._target import ReconTarget
from .reconn.infrastructure import InfrastructureRelationshipMapper
from .reconn.misc import MiscellaneousAnalyzer
from .reconn.network import NetworkInfrastructureAnalyzer
from .reconn.security import SecurityInfrastructureAnalyzer
from .reconn.webapp import WebApplicationAnalyzer
from .utils.cache import ScanCache
from .utils.error_handler import get_global_error_handler, handle_async_errors
from .utils.logger import setup_logger

error_handler = get_global_error_handler()


class ReconManager:
    """
    Main class that manages and coordinates all reconnaissance activities.
    """

    def __init__(self, url: str, options: Optional[Dict] = None):
        """
        Initialize the reconnaissance manager.

        Args:
            url: Target URL
            options: Dictionary of scan options and configurations
        """
        self.options = options or {}
        self.target = self._create_target(url)
        self.logger = setup_logger("recon_manager")

        # Handle cache options
        if not self.options.get("no_cache", False):
            cache_dir = Path(self.options.get("cache_dir", "vulnradar_cache"))

            # Clear cache if requested
            if self.options.get("clear_cache", False):
                # Clear all analyzer caches
                for subdir in [
                    "network",
                    "security",
                    "webapp",
                    "infrastructure",
                    "misc",
                ]:
                    subdir_path = cache_dir / subdir
                    if subdir_path.exists():
                        cache = ScanCache(subdir_path)
                        cache.clear_all()
                self.logger.info("All reconnaissance caches cleared")

        # Initialize analyzers
        self.network_analyzer = NetworkInfrastructureAnalyzer(self.target, self.options)
        self.security_analyzer = SecurityInfrastructureAnalyzer(
            self.target, self.options
        )
        self.webapp_analyzer = WebApplicationAnalyzer(self.target, self.options)
        self.infra_mapper = InfrastructureRelationshipMapper(self.target, self.options)
        self.misc_analyzer = MiscellaneousAnalyzer(self.target, self.options)

    def _create_target(self, url: str) -> ReconTarget:
        """Create and validate target object"""
        parsed = urlparse(url)
        return ReconTarget(
            url=url,
            hostname=parsed.netloc,
            is_https=parsed.scheme == "https",
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
        )

    @handle_async_errors(
        error_handler=error_handler,
        user_message="Reconnaissance analysis encountered an error",
        return_on_error={},
    )
    async def run_reconnaissance(self) -> Dict:
        """
        Run all reconnaissance modules and return combined results.

        Returns:
            Dict containing all reconnaissance findings
        """
        results = {}

        try:
            # Run all analyzers concurrently
            network_task = self.network_analyzer.analyze()
            security_task = self.security_analyzer.analyze()
            webapp_task = self.webapp_analyzer.analyze()
            infra_task = self.infra_mapper.analyze()
            misc_task = self.misc_analyzer.analyze()

            network_results: Union[Dict, Exception]
            security_results: Union[Dict, Exception]
            webapp_results: Union[Dict, Exception]
            infra_results: Union[Dict, Exception]
            misc_results: Union[Dict, Exception]

            # Gather results
            (
                network_results,
                security_results,
                webapp_results,
                infra_results,
                misc_results,
            ) = await asyncio.gather(
                network_task,
                security_task,
                webapp_task,
                infra_task,
                misc_task,
                return_exceptions=True,
            )

            # Process results
            if isinstance(network_results, Exception):
                self.logger.error(f"Network analysis failed: {str(network_results)}")
                results["network"] = {"error": str(network_results)}
            else:
                results["network"] = network_results

            if isinstance(security_results, Exception):
                self.logger.error(f"Security analysis failed: {str(security_results)}")
                results["security"] = {"error": str(security_results)}
            else:
                results["security"] = security_results

            if isinstance(webapp_results, Exception):
                self.logger.error(
                    f"Web application analysis failed: {str(webapp_results)}"
                )
                results["webapp"] = {"error": str(webapp_results)}
            else:
                results["webapp"] = webapp_results

            if isinstance(infra_results, Exception):
                self.logger.error(
                    f"Infrastructure mapping failed: {str(infra_results)}"
                )
                results["infrastructure"] = {"error": str(infra_results)}
            else:
                results["infrastructure"] = infra_results

            if isinstance(misc_results, Exception):
                self.logger.error(f"Miscellaneous analysis failed: {str(misc_results)}")
                results["miscellaneous"] = {"error": str(misc_results)}
            else:
                results["miscellaneous"] = misc_results

            return results

        except Exception as e:
            self.logger.error(f"Reconnaissance failed: {str(e)}")
            return {"error": str(e)}

    def get_summary(self) -> Dict:
        """
        Get a summary of the reconnaissance findings.

        Returns:
            Dict containing summary of key findings
        """
        # Implementation would depend on what kind of summary is needed
        return {}

    def log_recon_findings(self, recon_results: Dict) -> None:
        """Log important reconnaissance findings."""
        if "network" in recon_results:
            net_info = recon_results["network"]
            if "dns" in net_info:
                self.logger.info(
                    f"DNS Analysis: Found {len(net_info['dns'].get('A', []))} IP addresses"
                )
            if "ports" in net_info:
                self.logger.info(
                    f"Port Scan: Found {len(net_info['ports'])} open ports"
                )

        if "security" in recon_results:
            sec_info = recon_results["security"]
            if "waf" in sec_info and sec_info["waf"].get("detected"):
                self.logger.info(
                    f"WAF detected: {sec_info['waf'].get('type', 'Unknown')}"
                )
            if "ssl_tls" in sec_info:
                vulns = sec_info["ssl_tls"].get("vulnerabilities", [])
                if vulns:
                    self.logger.warning(f"Found {len(vulns)} SSL/TLS vulnerabilities")

        if "web_application" in recon_results:
            web_info = recon_results["web_application"]
            if "technologies" in web_info:
                techs = web_info["technologies"]
                self.logger.info(
                    f"Detected technologies: {', '.join(t['name'] for t in techs.get('frameworks', []))}"
                )

        if "infrastructure" in recon_results:
            infra_info = recon_results["infrastructure"]
            if "cloud_infrastructure" in infra_info:
                cloud = infra_info["cloud_infrastructure"]
                if cloud.get("provider"):
                    self.logger.info(f"Cloud provider detected: {cloud['provider']}")
