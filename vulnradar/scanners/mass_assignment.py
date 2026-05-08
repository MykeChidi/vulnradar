# vulnradar/scanners/mass_assignment.py

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

from ..utils.error_handler import NetworkError, get_global_error_handler
from . import payloads
from .contextual import ContextualScanner, EndpointContext

error_handler = get_global_error_handler()


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# Probe fields are imported from payloads module
# ─────────────────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────────────────
# BASELINE SENTINEL VALUES
#
# When we submit the baseline request (step 1), we fill every legitimate
# field with one of these sentinels depending on its type.  Using a
# distinctive sentinel makes it easy to spot in the response: if the server
# echoes "vulnradar_test" back, we know it processed our input.
# ─────────────────────────────────────────────────────────────────────────────

_SENTINEL_STRING = "vulnradar_test"
_SENTINEL_INT = 1
_SENTINEL_BOOL = False


# ─────────────────────────────────────────────────────────────────────────────
# WRITE METHODS — the verbs that can modify server state.  We only probe
# endpoints that accept at least one of these.
# ─────────────────────────────────────────────────────────────────────────────

_WRITE_METHODS = {"POST", "PUT", "PATCH"}


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────


class MassAssignmentScanner(ContextualScanner):
    """Scan for Mass Assignment vulnerabilities."""

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    # ── discovery ─────────────────────────────────────────────────────────

    async def discover(self, endpoints: List[str]) -> EndpointContext:
        """
        Three-step discovery:
          1. Classify crawled URLs by ID pattern (reuses ContextualScanner).
          2. Probe each pattern's base URL for its JSON response schema.
          3. Probe each endpoint for allowed HTTP methods.

        After this, self.context.schemas tells us what fields each endpoint
        legitimately exposes, and self.context.methods tells us which ones
        accept writes.  scan() uses both.
        """
        # Step 1: ID-pattern classification (pure string analysis, shared with IDOR)
        id_endpoints = self._classify_endpoints(endpoints)

        # Step 2: schema extraction — probe each unique base URL
        # (the URL with the ID segment stripped) for its JSON fields.
        schemas: Dict[str, List[str]] = {}
        base_urls_seen = set()

        for pattern, info in id_endpoints.items():
            # Derive the base URL (collection endpoint) from a pattern.
            # e.g. "https://host/api/users/{id}" → "https://host/api/users"
            base_url = pattern.replace("/{id}", "").rstrip("/")
            if base_url in base_urls_seen:
                continue
            base_urls_seen.add(base_url)

            schema = await self._probe_response_schema(base_url)
            if schema:
                schemas[base_url] = schema

            # Also probe the individual-object URL (with a sample ID)
            # because collection and single-object responses often differ.
            if info["sample_ids"]:
                sample_url = pattern.replace("{id}", str(info["sample_ids"][0]))
                obj_schema = await self._probe_response_schema(sample_url)
                if obj_schema:
                    schemas[sample_url] = obj_schema

        # Also probe endpoints that don't carry an ID but might accept POST
        # (e.g. /api/users for user creation).  These are endpoints whose
        # path doesn't match any ID pattern.
        for url in endpoints:
            if url in base_urls_seen:
                continue
            # Only bother if it looks like an API endpoint
            if not self._looks_like_api(url):
                continue
            schema = await self._probe_response_schema(url)
            if schema:
                schemas[url] = schema
                base_urls_seen.add(url)

        # Step 3: method discovery — probe every URL that has a schema.
        methods: Dict[str, List[str]] = {}
        for url in schemas:
            allowed = await self._probe_allowed_methods(url)
            if allowed:
                methods[url] = allowed

        self.context = EndpointContext(
            id_endpoints=id_endpoints,
            schemas=schemas,
            methods=methods,
        )
        return self.context

    # ── scan ──────────────────────────────────────────────────────────────

    async def scan(self, url: str) -> List[Dict]:
        """
        Test a single URL for mass assignment.

        Only acts on URLs that:
          (a) have a known schema in self.context.schemas, AND
          (b) accept at least one write method (POST/PUT/PATCH).

        For each such URL, runs the three-request baseline→inject→compare
        sequence for every probe field.
        """
        if not self.context:
            return []

        findings: List[Dict] = []

        # Find the best matching schema for this URL.
        # Exact match first, then try the base URL (strip trailing ID segment).
        target_url, schema = self._resolve_schema(url)
        if schema is None:
            return []

        # Check that this endpoint accepts at least one write method
        allowed_methods = self.context.methods.get(target_url, [])
        write_methods = _WRITE_METHODS & set(allowed_methods)
        if not write_methods:
            return []

        # Pick the best write method: PATCH > PUT > POST
        # PATCH is preferred because it's semantically "update existing object"
        # which is exactly what mass assignment targets.
        write_method = self._pick_write_method(write_methods)

        # Step 1: get the baseline response
        baseline_body = self._build_baseline_body(schema)
        baseline_result = await self._submit(target_url, write_method, baseline_body)
        if baseline_result is None:
            return []

        baseline_status, baseline_resp_body = baseline_result
        baseline_fields = self._extract_fields(baseline_resp_body)

        # Step 2 + 3: inject each probe field and compare
        for field_name, injected_value, severity, why in payloads.mass_assignment_probe_fields:
            # Skip probe fields that are already in the legitimate schema —
            # if the app already exposes "role", injecting "role" is not
            # mass assignment, it's just using the API normally.
            if field_name in schema:
                continue

            inject_body = dict(baseline_body)
            inject_body[field_name] = injected_value

            inject_result = await self._submit(target_url, write_method, inject_body)
            if inject_result is None:
                continue

            inject_status, inject_resp_body = inject_result
            inject_fields = self._extract_fields(inject_resp_body)

            # Compare
            accepted = self._field_was_accepted(
                field_name,
                injected_value,
                baseline_status,
                baseline_resp_body,
                baseline_fields,
                inject_status,
                inject_resp_body,
                inject_fields,
            )
            if not accepted:
                continue

            findings.append(
                {
                    "type": "Mass Assignment",
                    "endpoint": target_url,
                    "severity": severity,
                    "description": (
                        f"Mass assignment detected: field '{field_name}' was accepted "
                        f"and processed by the server. {why}."
                    ),
                    "evidence": (
                        f"{write_method} {target_url} — injected '{field_name}' with value "
                        f"{json.dumps(injected_value)}. "
                        f"Baseline status: {baseline_status}, inject status: {inject_status}. "
                        f"Server response indicates the field was processed: "
                        f"'{field_name}' found in response body or response changed."
                    ),
                    "remediation": (
                        f"Explicitly whitelist the fields that each endpoint is allowed to "
                        f"accept.  Do not bind request bodies directly to model objects.  "
                        f"Use a DTO (Data Transfer Object) or explicit field list on "
                        f"deserialization.  Remove or deny '{field_name}' from all "
                        f"write endpoints that should not expose it."
                    ),
                    "payload": json.dumps(
                        {
                            "target_url": target_url,
                            "write_method": write_method,
                            "field_name": field_name,
                            "injected_value": injected_value,
                            "schema": schema,
                        }
                    ),
                }
            )

        return findings

    # ── validation ────────────────────────────────────────────────────────

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-run the baseline→inject→compare sequence for the specific field
        that produced the original finding.  Confirm the field is still
        accepted.
        """
        try:
            meta = json.loads(payload)
            target_url = meta["target_url"]
            write_method = meta["write_method"]
            field_name = meta["field_name"]
            injected_value = meta["injected_value"]
            schema = meta["schema"]

            # Baseline
            baseline_body = self._build_baseline_body(schema)
            baseline_result = await self._submit(
                target_url, write_method, baseline_body
            )
            if baseline_result is None:
                return False
            baseline_status, baseline_resp_body = baseline_result
            baseline_fields = self._extract_fields(baseline_resp_body)

            # Inject
            inject_body = dict(baseline_body)
            inject_body[field_name] = injected_value
            inject_result = await self._submit(target_url, write_method, inject_body)
            if inject_result is None:
                return False
            inject_status, inject_resp_body = inject_result
            inject_fields = self._extract_fields(inject_resp_body)

            return self._field_was_accepted(
                field_name,
                injected_value,
                baseline_status,
                baseline_resp_body,
                baseline_fields,
                inject_status,
                inject_resp_body,
                inject_fields,
            )

        except (json.JSONDecodeError, KeyError):
            return bool(evidence)

    # ── private: discovery helpers ────────────────────────────────────────

    @staticmethod
    def _looks_like_api(url: str) -> bool:
        """
        Heuristic: does this URL look like a REST API endpoint?

        We only bother probing schema on URLs that are plausibly API
        endpoints.  Probing every crawled URL would be noisy and slow.
        """
        path = urlparse(url).path.lower()
        api_indicators = ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/json/")
        if any(ind in path for ind in api_indicators):
            return True
        # Also accept paths ending in a resource-like noun (no file extension)
        last_segment = path.rstrip("/").split("/")[-1] if path.rstrip("/") else ""
        if last_segment and "." not in last_segment and len(last_segment) > 2:
            return True
        return False

    # ── private: scan helpers ─────────────────────────────────────────────

    def _resolve_schema(self, url: str) -> Tuple[str, Optional[List[str]]]:
        """
        Find the best matching schema for a URL.

        Exact match first.  If not found, try stripping the last path
        segment (the ID) to get the collection URL.  Returns
        (matched_url, schema_list) or (url, None) if no schema is known.
        """
        if not self.context:
            return (url, None)

        # Exact match
        if url in self.context.schemas:
            return (url, self.context.schemas[url])

        # Strip trailing ID segment: /api/users/42 → /api/users
        parts = url.rstrip("/").rsplit("/", 1)
        if len(parts) == 2:
            base = parts[0]
            if base in self.context.schemas:
                return (base, self.context.schemas[base])

        return (url, None)

    @staticmethod
    def _pick_write_method(methods: set) -> str:
        """Pick the most appropriate write method.  PATCH > PUT > POST."""
        for m in ("PATCH", "PUT", "POST"):
            if m in methods:
                return m
        return "POST"  # fallback, should never reach here given the caller guard

    @staticmethod
    def _build_baseline_body(schema: List[str]) -> Dict[str, Any]:
        """
        Build a JSON body with every legitimate field filled with a sentinel.

        We use a single sentinel value for all fields because we don't know
        the expected types.  Most APIs will either accept the string or reject
        the whole request — either way, the baseline captures the server's
        behaviour for this exact set of fields.
        """
        return {field: _SENTINEL_STRING for field in schema}

    async def _submit(
        self, url: str, method: str, body: Dict[str, Any]
    ) -> Optional[Tuple[int, str]]:
        """
        Submit a JSON payload to the target.  Returns (status, response_body).

        Returns None on network failure.
        """
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                req_headers = {**self.headers, "Content-Type": "application/json"}
                async with session.request(
                    method, url, json=body, headers=req_headers
                ) as response:
                    resp_body = await self._safe_read(response)
                    return (response.status, resp_body)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"Mass-assignment probe failed for {url}: {str(e)}",
                    original_error=e,
                ),
                context={"url": url, "method": method},
            )
            return None

    # ── private: comparison logic ─────────────────────────────────────────

    @staticmethod
    def _extract_fields(body: str) -> Dict[str, Any]:
        """
        Parse a JSON response body into a flat field→value map.

        Returns an empty dict if the body isn't valid JSON or isn't a dict.
        If the body is a JSON array, inspects the first element.
        """
        try:
            data = json.loads(body)
            if isinstance(data, list):
                data = data[0] if data else {}
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, IndexError):
            pass
        return {}

    @staticmethod
    def _field_was_accepted(
        field_name: str,
        injected_value: Any,
        baseline_status: int,
        baseline_body: str,
        baseline_fields: Dict[str, Any],
        inject_status: int,
        inject_body: str,
        inject_fields: Dict[str, Any],
    ) -> bool:
        """
        Determine whether the injected field was accepted and processed.

        Three independent signals — any one is sufficient:

        Signal A — FIELD ECHO.
            The injected field name appears as a key in the inject response
            but NOT in the baseline response.  The server echoed it back,
            meaning it was stored or at least processed.

        Signal B — STATUS CHANGE.
            The inject response has a different status code from the baseline.
            Common pattern: baseline returns 200 (update), inject returns 201
            (created with the extra field).  Or baseline returns 400 (rejects
            unknown fields) but inject returns 200 — meaning the field was
            silently accepted when it shouldn't have been.

        Signal C — VALUE CHANGE on a sensitive field.
            A field that exists in BOTH responses changed value between baseline
            and inject.  This catches the case where injecting "role=admin"
            causes the response's "role" field to flip from "user" to "admin"
            — the field was in the schema all along, but the server let us
            override it via the extra field.
        """
        # Signal A: field echoed back
        if field_name in inject_fields and field_name not in baseline_fields:
            return True

        # Signal B: status changed
        if inject_status != baseline_status:
            # A status change is only meaningful if the inject response
            # indicates success (2xx).  A 400 or 500 on inject just means
            # the server rejected something — not a finding.
            if 200 <= inject_status < 300:
                return True

        # Signal C: value changed on a shared field
        # Only check fields that are in both responses — we're looking for
        # a *change* caused by the injection, not for new fields.
        shared_fields = set(baseline_fields.keys()) & set(inject_fields.keys())
        for shared in shared_fields:
            if baseline_fields[shared] != inject_fields[shared]:
                # A change on ANY shared field after injecting our probe
                # field means the injection had a side effect.
                return True

        return False
