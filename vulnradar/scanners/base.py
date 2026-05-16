# vulnradar/scanners/base.py - Base Scanner class

import abc
from typing import TYPE_CHECKING, Dict, List, Optional

import aiohttp
from bs4 import BeautifulSoup

from ..models.finding import Finding
from ..utils.error_handler import ParseError, ValidationError, get_global_error_handler

if TYPE_CHECKING:
    from ..context import ScanContext

# Hard cap on response body size to prevent memory exhaustion when scanning
# a malicious target that returns an unbounded stream (F-01).
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB

# Setup error handler
error_handler = get_global_error_handler()


class BaseScanner(abc.ABC):
    """Base class for vulnerability scanners."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        """
        Initialize the scanner.

        Args:
            headers: HTTP headers to use
            timeout: Request timeout in seconds
        """
        self.headers = headers or {}
        # store an aiohttp.ClientTimeout so call-sites can pass it directly
        self.timeout: aiohttp.ClientTimeout = aiohttp.ClientTimeout(
            total=timeout, connect=5, sock_read=timeout
        )

        self._context: Optional["ScanContext"] = None

    def attach_context(self, context: "ScanContext") -> None:
        """
        Inject the shared ScanContext before scanning begins.
        """
        self._context = context

    @property
    def session(self) -> aiohttp.ClientSession:
        """
        Return the shared aiohttp.ClientSession from the attached ScanContext.
        instead of creating a new session.
        """
        if self._context is None or self._context.session is None:
            raise RuntimeError(
                f"{self.__class__.__name__}: ScanContext not attached. "
                "Call attach_context() before scan()."
            )
        return self._context.session

    @abc.abstractmethod
    async def scan(self, url: str) -> List[Finding]:
        """
        Scan a URL for vulnerabilities.

        Args:
            url: URL to scan

        Returns:
            List[Finding]: List of vulnerability findings
        """
        pass

    @abc.abstractmethod
    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Validate a vulnerability finding.

        Args:
            url: URL where vulnerability was found
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability

        Returns:
            bool: True if vulnerability is confirmed valid, False otherwise
        """
        pass

    @staticmethod
    async def _safe_read(
        response: aiohttp.ClientResponse,
        limit: int = MAX_RESPONSE_BYTES,
    ) -> str:
        """
        Read at most ``limit`` bytes from a response and return decoded text.
        """
        body = await response.content.read(limit)
        return body.decode(errors="replace")

    async def _get_form_inputs(self, url: str) -> List[Dict]:
        """
        Extract forms and their inputs from a URL.

        Args:
            url: URL to extract forms from

        Returns:
            List[Dict]: List of forms with their inputs
        """
        from urllib.parse import urljoin

        # Determine whether we have a shared session to reuse.
        _own_session = self._context is None or self._context.session is None
        _session: aiohttp.ClientSession

        try:
            if _own_session:
                _session = aiohttp.ClientSession(
                    headers=self.headers, timeout=self.timeout
                )
            else:
                _session = self._context.session  # type: ignore[union-attr]

            try:
                async with _session.get(url) as response:
                    if response.status != 200:
                        return []

                    html = await self._safe_read(response)
                    try:
                        soup = BeautifulSoup(html, "lxml")
                    except Exception:
                        soup = BeautifulSoup(html, "html.parser")
                    forms = []

                    for form in soup.find_all("form"):
                        action = form.get("action", "")
                        form_info = {
                            "action": urljoin(url, action) if action else url,
                            "method": form.get("method", "get").lower(),
                            "inputs": [],
                        }

                        for input_tag in form.find_all(["input", "textarea", "select"]):
                            input_type = input_tag.get("type", "")
                            input_name = input_tag.get("name", "")

                            if input_type in ["submit", "button", "reset", "image"]:
                                continue
                            if not input_name:
                                continue

                            form_info["inputs"].append(
                                {
                                    "name": input_name,
                                    "type": input_type,
                                    "value": input_tag.get("value", ""),
                                }
                            )

                        forms.append(form_info)

                    return forms

            finally:
                # Only close the session if we created it ourselves.
                if _own_session:
                    await _session.close()

        except Exception as e:
            error_handler.handle_error(
                ParseError(
                    f"Error extracting forms from {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return []

    async def _extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract parameters from URL query string.

        Args:
            url: URL to extract parameters from

        Returns:
            Dict[str, str]: Dictionary of parameter names and values
        """
        from urllib.parse import parse_qs, urlparse

        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Convert list values to single strings
            return {k: v[0] if v else "" for k, v in query_params.items()}

        except Exception as e:
            error_handler.handle_error(
                ValidationError(
                    f"Error extracting parameters from {url}: {str(e)}",
                    original_error=e,
                ),
                context={"url": url},
            )
            return {}
