# vulnradar/scanners/idor.py

import hashlib
import json
from typing import Dict, List, Optional, Set, Tuple

import aiohttp

from ..models.finding import Finding
from ..models.severity import Severity
from ..models.standards import get_standards
from ..utils.error_handler import NetworkError, get_global_error_handler
from .contextual import ContextualScanner, EndpointContext

error_handler = get_global_error_handler()

# How many IDs in the "floor" range to always probe regardless of what
# the crawl found.  Catches apps that only linked to high IDs.
_FLOOR_RANGE = 5

# Minimum body length to consider a response "real data" vs an error page.
# Most error pages are shorter than this; a real object serialization is longer.
_MIN_BODY_LENGTH = 50

# How many sample IDs per pattern to probe during discover() for baseline.
_BASELINE_SAMPLE_SIZE = 3


class IDORScanner(ContextualScanner):
    """Scan for Insecure Direct Object Reference vulnerabilities."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)
        # Baseline: pattern → {id_value → (status, body_len, body_hash)}
        self._baselines: Dict[str, Dict] = {}

    # ── discovery ─────────────────────────────────────────────────────────

    async def discover(self, endpoints: List[str]) -> EndpointContext:
        """
        1. Classify all crawled URLs by ID pattern.
        2. For each pattern, probe a sample of the observed IDs to record
           a baseline response fingerprint.  The baseline is what "normal"
           looks like for this endpoint — anything substantially different
           during scanning is suspicious.
        """
        # Step 1: pure string classification (no network calls)
        id_endpoints = self._classify_endpoints(endpoints)

        # Step 2: probe a sample of each pattern to build baselines
        self._baselines = {}
        for pattern, info in id_endpoints.items():
            self._baselines[pattern] = {}
            sample_ids = info["sample_ids"][:_BASELINE_SAMPLE_SIZE]

            for sid in sample_ids:
                url = self._build_url_for_id(pattern, sid)
                fingerprint = await self._fetch_fingerprint(url)
                if fingerprint:
                    self._baselines[pattern][str(sid)] = fingerprint

        self.context = EndpointContext(id_endpoints=id_endpoints)
        return self.context

    # ── scan ──────────────────────────────────────────────────────────────

    async def scan(self, url: str) -> List[Finding]:
        """
        Test a single URL for IDOR.

        Only acts on URLs that matched a known ID pattern during discovery.
        Probes adjacent IDs and the floor range; flags any that return
        real data for an ID we have no baseline for.
        """
        if not self.context:
            return []

        findings: List[Finding] = []

        for pattern, info in self.context.id_endpoints.items():
            if url not in info["original_urls"]:
                continue

            # Determine which IDs to probe
            ids_to_test = self._ids_to_probe(info)
            baseline = self._baselines.get(pattern, {})

            for test_id in ids_to_test:
                # Skip IDs we already have a baseline for — those are known-good
                if str(test_id) in baseline:
                    continue

                test_url = self._build_url_for_id(pattern, test_id)
                fingerprint = await self._fetch_fingerprint(test_url)
                if fingerprint is None:
                    continue

                status, body_len, body_hash = fingerprint

                # Flag if: returned 200, body is substantial, and we have
                # no baseline entry for this ID (i.e. it wasn't in the crawl)
                if status == 200 and body_len >= _MIN_BODY_LENGTH:
                    findings.append(
                        Finding(
                            type="IDOR",
                            endpoint=test_url,
                            severity=Severity.HIGH,
                            description=(
                                f"Unauthorized access to object ID {test_id} "
                                f"via {pattern}"
                            ),
                            evidence=(
                                f"GET {test_url} returned status 200 with "
                                f"{body_len} bytes of content. This ID was not "
                                f"present in the crawl results but the server "
                                f"returned data without an access-control error."
                            ),
                            remediation=(
                                "Enforce server-side authorization checks on every "
                                "object access. Verify the requesting user has permission "
                                "to access the specific resource ID. Do not rely on "
                                "ID unpredictability as an access control mechanism."
                            ),
                            payload=json.dumps(
                                {
                                    "pattern": pattern,
                                    "test_id": test_id,
                                    "test_url": test_url,
                                }
                            ),
                            **get_standards("IDOR"),
                        )
                    )

            # Only test the first matching pattern for this URL
            break

        return findings

    # ── validation ────────────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-fetch the specific unauthorized URL from the original finding.
        Confirm it still returns 200 with substantial content.
        """
        try:
            data = json.loads(payload)
            test_url = data.get("test_url", url)

            fingerprint = await self._fetch_fingerprint(test_url)
            if fingerprint is None:
                return False

            status, body_len, _ = fingerprint
            return status == 200 and body_len >= _MIN_BODY_LENGTH

        except (json.JSONDecodeError, KeyError):
            # Fallback: just re-fetch the endpoint itself
            fingerprint = await self._fetch_fingerprint(url)
            if fingerprint is None:
                return False
            status, body_len, _ = fingerprint
            return status == 200 and body_len >= _MIN_BODY_LENGTH

    # ── private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _build_url_for_id(pattern: str, id_value) -> str:
        """Replace {id} in a pattern with a concrete ID value."""
        return pattern.replace("{id}", str(id_value))

    @staticmethod
    def _ids_to_probe(info: Dict) -> List:
        """
        Build the set of IDs to test for a given pattern.

        Always includes IDs 1 through _FLOOR_RANGE (catches apps that
        only linked high IDs during the crawl).  For int patterns, also
        includes ±1 around every observed sample ID.  For uuid/slug
        patterns, only the floor range applies — we can't meaningfully
        enumerate adjacent values for those types.
        """
        ids: Set = set()

        id_type = info.get("id_type", "int")

        # Floor range — always probe these
        if id_type == "int":
            ids.update(range(1, _FLOOR_RANGE + 1))

            # Adjacent IDs around every observed sample
            for sid in info.get("sample_ids", []):
                if isinstance(sid, int):
                    if sid - 1 > 0:
                        ids.add(sid - 1)
                    ids.add(sid + 1)
                    ids.add(sid + 2)  # one extra forward for good measure

        # For uuid/slug: we can't enumerate adjacents, but we still probe
        # the floor range as integer IDs in case the app also accepts those.
        # (Many apps do — e.g. /users/1 and /users/abc-def both work.)
        else:
            ids.update(range(1, _FLOOR_RANGE + 1))

        return sorted(ids)

    async def _fetch_fingerprint(self, url: str) -> Optional[Tuple[int, int, str]]:
        """
        Fetch a URL and return (status, body_length, body_sha256).

        Returns None on network failure.  The hash lets us detect if two
        different IDs return the exact same page (common for "not found"
        error pages) without storing full bodies.
        """
        try:
            async with self.session.get(url) as response:
                body = await self._safe_read(response)
                body_hash = hashlib.sha256(body.encode()).hexdigest()
                return (response.status, len(body), body_hash)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"IDOR probe failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return None
