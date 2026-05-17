# vulnradar/scanners/stateful.py

from typing import Dict, List, Optional

import aiohttp
from bs4 import BeautifulSoup

from ..utils.error_handler import NetworkError, ParseError, get_global_error_handler
from .base import BaseScanner

error_handler = get_global_error_handler()


class StatefulScanner(BaseScanner):
    """BaseScanner + a persistent session for multi-step flows."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    # ── session lifecycle ─────────────────────────────────────────────────

    async def _get_session(self) -> aiohttp.ClientSession:
        """
        Return the shared session from the attached ScanContext.

        Stateful scanners still need a persistent session for multi-step
        flows, but they must reuse the shared session provided by core.
        """
        return self.session

    async def _close_session(self) -> None:
        """Reset cookies on the shared session so the next flow starts fresh."""
        if self._context is not None and self._context.session is not None:
            try:
                self.session.cookie_jar.clear()
            except Exception:
                pass  # nosec

    # ── stateful request helpers ──────────────────────────────────────────
    # These mirror BaseScanner's patterns but route through the persistent
    # session so cookies from earlier steps in a flow are carried forward.
    # They return None on network failure (logged via error_handler) so
    # callers don't need individual try/except for every request.

    async def _stateful_get(
        self, url: str, **kwargs
    ) -> Optional[aiohttp.ClientResponse]:
        """GET through the persistent session.  Returns None on error."""
        session = await self._get_session()
        try:
            return await session.get(url, **kwargs)
        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"Stateful GET failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return None

    async def _stateful_post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        """
        POST through the persistent session.

        Accepts either form data (data=) or JSON body (json=), matching
        the two submission styles web apps typically use.
        Returns None on error.
        """
        session = await self._get_session()
        try:
            return await session.post(url, data=data, json=json, **kwargs)
        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"Stateful POST failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url, "data": data},
            )
            return None

    async def _get_form_inputs_stateful(self, url: str) -> List[Dict]:
        """
        Extract forms using the persistent session.

        Identical parsing logic to BaseScanner._get_form_inputs() but the
        GET goes through _stateful_get so cookies already in the jar
        (e.g. a CSRF token set on a prior request) are sent along.
        """
        response = await self._stateful_get(url)
        if response is None or response.status != 200:
            return []

        try:
            html = await self._safe_read(response)
            try:
                soup = BeautifulSoup(html, "lxml")
            except Exception:
                soup = BeautifulSoup(html, "html.parser")

            forms = []
            for form in soup.find_all("form"):
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").lower(),
                    "inputs": [],
                }

                # Resolve relative action URLs — same logic as BaseScanner
                if form_info["action"].startswith("/"):
                    from urllib.parse import urlparse

                    parsed = urlparse(url)
                    form_info["action"] = (
                        f"{parsed.scheme}://{parsed.netloc}{form_info['action']}"
                    )
                elif not form_info["action"]:
                    form_info["action"] = url

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

        except Exception as e:
            error_handler.handle_error(
                ParseError(
                    f"Error parsing forms from {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return []
