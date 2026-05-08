# vulnradar/scanners/contextual.py

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import aiohttp

from ..utils.error_handler import NetworkError, ParseError, get_global_error_handler
from .base import BaseScanner

error_handler = get_global_error_handler()

# ── shared context dataclass ──────────────────────────────────────────────────


@dataclass
class EndpointContext:
    """
    Structural information about the target, populated by discover().

    id_endpoints:
        Maps a normalised URL pattern to metadata about the IDs it carries.
        Key:   pattern with the ID segment replaced
               e.g. "https://host/api/users/{id}"
        Value: {
            "id_type":       "int" | "uuid" | "slug"
            "sample_ids":    [concrete values seen during crawl]
            "original_urls": [full URLs that matched this pattern]
            "min_id":        lowest int ID observed  (int patterns only)
            "max_id":        highest int ID observed (int patterns only)
        }

    schemas:
        Maps a base endpoint to the list of field names seen in a sample
        JSON response.  Used by Mass Assignment to know which fields an
        object exposes (and therefore which *extra* fields to try injecting).
        Key:   endpoint URL (no ID segment)
        Value: list of field name strings

    methods:
        Maps each endpoint to the HTTP methods it was observed to accept.
        Key:   endpoint URL
        Value: list of method strings, e.g. ["GET", "POST"]
    """

    id_endpoints: Dict[str, Dict] = field(default_factory=dict)
    schemas: Dict[str, List[str]] = field(default_factory=dict)
    methods: Dict[str, List[str]] = field(default_factory=dict)
    api_endpoints: Dict[str, Dict] = field(default_factory=dict)
    non_production_endpoints: List[str] = field(default_factory=list)


# ── base class ────────────────────────────────────────────────────────────────


class ContextualScanner(BaseScanner):
    """BaseScanner + a pre-populated structural context about the target."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)
        self.context: Optional[EndpointContext] = None

    # ── discovery entry point (called once by core.py) ───────────────────

    async def discover(self, endpoints: List[str]) -> EndpointContext:
        """
        Analyse the crawled endpoint list and populate self.context.

        Subclasses override this with their specific logic.  The base
        implementation returns an empty context so that a subclass that
        forgets to override doesn't crash — scan() will just see nothing
        to act on and return [].
        """
        self.context = EndpointContext()
        return self.context

    # ── shared discovery helpers ─────────────────────────────────────────
    # Reusable building blocks for subclass discover() methods.
    # _classify_endpoints is pure string analysis — no network calls.
    # _probe_response_schema and _probe_allowed_methods hit the wire.

    # Compiled once at class level — zero per-call cost.
    _INT_ID_RE = re.compile(r"/(\d+)(?:/|$|\?)")
    _UUID_ID_RE = re.compile(
        r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$|\?)"
    )
    _SLUG_ID_RE = re.compile(r"/([a-zA-Z0-9][-a-zA-Z0-9]{2,63})(?:/|$|\?)")

    @staticmethod
    def _normalise_id_url(url: str, match: re.Match) -> str:
        """
        Replace the matched ID segment with {id} to produce a pattern key.

        e.g. "https://host/api/users/42?detail=true"
             → "https://host/api/users/{id}?detail=true"
        """
        start, end = match.span(1)
        return url[:start] + "{id}" + url[end:]

    def _classify_endpoints(self, endpoints: List[str]) -> Dict[str, Dict]:
        """
        Walk the crawled endpoint list and group URLs by ID pattern.

        Returns the id_endpoints dict ready to be stored on EndpointContext.
        Pure string analysis — no network requests.

        Patterns are checked in order of specificity: UUID first (most
        constrained), then plain integer, then slug last (most greedy).
        First match wins for each URL.
        """
        id_endpoints: Dict[str, Dict] = {}

        for url in endpoints:
            for regex, id_type in [
                (self._UUID_ID_RE, "uuid"),
                (self._INT_ID_RE, "int"),
                (self._SLUG_ID_RE, "slug"),
            ]:
                match = regex.search(url)
                if not match:
                    continue

                pattern = self._normalise_id_url(url, match)
                raw_id = match.group(1)

                if pattern not in id_endpoints:
                    id_endpoints[pattern] = {
                        "id_type": id_type,
                        "sample_ids": [],
                        "original_urls": [],
                        "min_id": None,
                        "max_id": None,
                    }

                entry = id_endpoints[pattern]
                entry["original_urls"].append(url)

                if id_type == "int":
                    int_id = int(raw_id)
                    entry["sample_ids"].append(int_id)
                    if entry["min_id"] is None or int_id < entry["min_id"]:
                        entry["min_id"] = int_id
                    if entry["max_id"] is None or int_id > entry["max_id"]:
                        entry["max_id"] = int_id
                else:
                    entry["sample_ids"].append(raw_id)

                break  # first matching pattern wins

        return id_endpoints

    async def _probe_response_schema(self, url: str) -> Optional[List[str]]:
        """
        Fetch a URL and extract top-level field names from a JSON response.

        Returns None if the response isn't JSON or the request fails.
        If the body is a JSON array, inspects the first element.
        """
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        return None

                    content_type = response.headers.get("Content-Type", "")
                    if "application/json" not in content_type:
                        return None

                    body = await response.json(content_type=None)

                    # If the body is a list, inspect the first element
                    if isinstance(body, list):
                        body = body[0] if body else None

                    if isinstance(body, dict):
                        return list(body.keys())

                    return None

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"Schema probe failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return None
        except Exception as e:
            error_handler.handle_error(
                ParseError(
                    f"Error parsing response from {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return None

    async def _probe_allowed_methods(self, url: str) -> List[str]:
        """
        Determine which HTTP methods an endpoint accepts.

        Tries OPTIONS first — if the server returns an Allow header we
        trust it directly.  Otherwise probes GET, POST, PUT, DELETE, PATCH
        individually and records whichever ones don't return 405.
        """
        methods: List[str] = []
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                # Attempt OPTIONS first
                async with session.options(url) as resp:
                    allow = resp.headers.get("Allow", "")
                    if allow:
                        return [m.strip() for m in allow.split(",") if m.strip()]

                # OPTIONS didn't help — probe individually
                for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    async with session.request(method, url) as resp:
                        if resp.status != 405:
                            methods.append(method)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"Method probe failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return methods
