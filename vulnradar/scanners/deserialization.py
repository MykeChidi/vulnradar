# vulnradar/scanners/deserialization.py

import base64
import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

from ..models.finding import Finding
from ..models.severity import Severity
from ..models.standards import get_standards
from ..utils.error_handler import (
    NetworkError,
    ScanError,
    get_global_error_handler,
)
from . import payloads
from .base import BaseScanner

error_handler = get_global_error_handler()


# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINT CONFIDENCE THRESHOLD
# A format must score at least this to have payloads sent against it.
# 0.5 means "one strong signal OR two weak signals."
# ─────────────────────────────────────────────────────────────────────────────
_CONFIDENCE_THRESHOLD = 0.5


# ─────────────────────────────────────────────────────────────────────────────
# FORMAT ENGINE BASE
# Each concrete engine knows: how to detect its format in a response,
# what payloads to build, how to submit them, and how to recognise a
# successful deserialisation in the server's reply.
# ─────────────────────────────────────────────────────────────────────────────


class _FormatEngine:
    """Abstract base for a single serialisation-format engine."""

    FORMAT_NAME: str = ""  # "java", "python", "php"

    # ── detection ─────────────────────────────────────────────────────────

    def score_headers(self, headers: Dict[str, str]) -> float:
        """Score based on response headers alone.  Range [0.0, 1.0]."""
        return 0.0

    def score_cookies(self, cookies: List[str]) -> float:
        """Score based on cookie values.  Range [0.0, 1.0]."""
        return 0.0

    def score_url(self, url: str) -> float:
        """Score based on the URL path / extension.  Range [0.0, 1.0]."""
        return 0.0

    def score_body(self, body: str, content_type: str) -> float:
        """Score based on response body content.  Range [0.0, 1.0]."""
        return 0.0

    def total_score(
        self,
        headers: Dict[str, str],
        cookies: List[str],
        url: str,
        body: str,
        content_type: str,
    ) -> float:
        """
        Aggregate all signals into one confidence score, clamped to [0, 1].

        Weights are chosen so that a single strong signal (e.g. an explicit
        Content-Type declaration) is enough to clear the threshold, but weak
        signals (e.g. a generic X-Powered-By) require corroboration.
        """
        score = (
            self.score_headers(headers) * 0.35
            + self.score_cookies(cookies) * 0.25
            + self.score_url(url) * 0.15
            + self.score_body(body, content_type) * 0.25
        )
        return min(max(score, 0.0), 1.0)

    # ── payload generation & submission ───────────────────────────────────

    def build_payloads(self) -> List[Dict]:
        """
        Return the list of payloads to try for this format.

        Each payload dict contains:
            name:         human-readable label for the finding
            data:         the raw bytes to send
            content_type: the Content-Type header to use on the request
            submit_as:    "body" | "cookie" | "parameter"
            cookie_name:  (only if submit_as == "cookie") which cookie to set
            param_name:   (only if submit_as == "parameter") which query/form param
        """
        return []

    # ── response analysis ─────────────────────────────────────────────────

    def indicates_deserialisation(
        self, status: int, body: str, headers: Dict[str, str]
    ) -> bool:
        """
        Did the response indicate the payload was actually deserialised?

        This is format-specific.  Java deserialisers return specific
        exception class names in stack traces.  Python pickle errors
        mention "pickle" or "Unpickler".  PHP unserialization errors
        reference specific magic methods.
        """
        return False


# ─────────────────────────────────────────────────────────────────────────────
# JAVA ENGINE
# ─────────────────────────────────────────────────────────────────────────────


class _JavaEngine(_FormatEngine):
    """
    Detects and probes Java serialization (java.io.ObjectOutputStream).

    Detection signals:
        • X-Powered-By containing "Java" or known Java app-server names
        • Content-Type: application/x-java-serialized-object
        • Cookies whose base64 decodes to the Java aced magic bytes (AC ED 00 05)
        • .ser file extensions in the URL
        • Error bodies mentioning java.io.* classes

    Payloads:
        We do NOT include live gadget chains (ysoserial) because shipping
        weaponised RCE payloads in a scanner is irresponsible.  Instead we
        send a minimal valid serialised object that will trigger the
        deserialiser to *process* it (proving deserialisation happens)
        without executing arbitrary code.  The finding tells the operator
        "deserialisation is reachable" — they use ysoserial manually if
        they need to prove RCE in a controlled pentest.
    """

    FORMAT_NAME = "java"

    def score_headers(self, headers: Dict[str, str]) -> float:
        xpb = headers.get("X-Powered-By", "").lower()
        ct = headers.get("Content-Type", "").lower()
        server = headers.get("Server", "").lower()

        score = 0.0
        # Explicit content-type declaration is a very strong signal
        if "x-java-serialized-object" in ct:
            score += 1.0
        # Runtime hints
        java_keywords = (
            "java",
            "tomcat",
            "jetty",
            "jboss",
            "websphere",
            "weblogic",
            "spring",
        )
        if any(kw in xpb for kw in java_keywords):
            score += 0.6
        if any(kw in server for kw in java_keywords):
            score += 0.4
        return min(score, 1.0)

    def score_cookies(self, cookies: List[str]) -> float:
        """Check if any cookie value base64-decodes to Java magic bytes."""
        for cookie_val in cookies:
            try:
                decoded = base64.b64decode(cookie_val)
                if decoded[:4] == payloads.deserialization_java_magic:
                    return 1.0  # unambiguous
            except Exception as e:
                error_handler.handle_error(
                    ScanError(f"Error checking cookie value: {e}")
                )
        return 0.0

    def score_url(self, url: str) -> float:
        path = urlparse(url).path.lower()
        if path.endswith(".ser"):
            return 0.8
        if "/deserialize" in path or "/readobject" in path:
            return 0.6
        return 0.0

    def score_body(self, body: str, content_type: str) -> float:
        lo = body.lower()
        # Stack traces naming Java serialization internals
        java_classes = (
            "java.io.objectinputstream",
            "java.io.objectoutputstream",
            "classnotfoundexception",
            "java.io.invalidclassexception",
        )
        if any(cls in lo for cls in java_classes):
            return 0.9
        return 0.0

    def build_payloads(self) -> List[Dict]:
        return [
            {
                "name": "Java TC_NULL probe",
                "data": payloads.deserialization_java_tc_null,
                "content_type": "application/x-java-serialized-object",
                "submit_as": "body",
            },
            {
                "name": "Java bogus-class probe",
                "data": payloads.deserialization_java_probe_class,
                "content_type": "application/x-java-serialized-object",
                "submit_as": "body",
            },
            {
                "name": "Java magic in cookie",
                "data": base64.b64encode(payloads.deserialization_java_tc_null),
                "content_type": None,  # not a body submission
                "submit_as": "cookie",
                "cookie_name": "session",
            },
        ]

    def indicates_deserialisation(
        self, status: int, body: str, headers: Dict[str, str]
    ) -> bool:
        lo = body.lower()
        # A ClassNotFoundException for our bogus class proves the server
        # attempted to deserialise the object.
        if "vulnradar.deserprobe" in lo:
            return True
        # Generic Java deserialisation error in response
        if "objectinputstream" in lo and ("exception" in lo or "error" in lo):
            return True
        # 500 with a Java stack trace after we sent serialised data
        if status == 500 and "java.io" in lo:
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# PYTHON ENGINE
# ─────────────────────────────────────────────────────────────────────────────


class _PythonEngine(_FormatEngine):
    """
    Detects and probes Python pickle deserialisation.

    Detection signals:
        • X-Powered-By / Server containing "Python", "Flask", "Django", "Gunicorn"
        • Cookies whose base64 decodes to valid pickle opcodes
        • .pickle / .pkl extensions in the URL
        • Error bodies mentioning pickle.* or Unpickler

    Payloads:
        Same philosophy as Java: we send probes that exercise the
        deserialiser without executing arbitrary code.  A pickle payload
        that reconstructs a simple benign object (e.g. an empty dict)
        proves deserialisation is reachable.  We also send a payload
        that references a non-existent module — if the error names that
        module, deserialisation is confirmed.
    """

    FORMAT_NAME = "python"

    def score_headers(self, headers: Dict[str, str]) -> float:
        xpb = headers.get("X-Powered-By", "").lower()
        server = headers.get("Server", "").lower()

        score = 0.0
        python_keywords = (
            "python",
            "flask",
            "django",
            "gunicorn",
            "uvicorn",
            "fastapi",
            "celery",
        )
        if any(kw in xpb for kw in python_keywords):
            score += 0.7
        if any(kw in server for kw in python_keywords):
            score += 0.5
        return min(score, 1.0)

    def score_cookies(self, cookies: List[str]) -> float:
        """
        Check if any cookie value base64-decodes to a valid pickle header.

        Pickle protocol 0 starts with printable ASCII opcodes (no magic
        number), so we look for protocol 2+ which starts with 0x80.
        Flask's default session cookie is base64(pickle(dict)) — the
        0x80 0x02 prefix is unambiguous.
        """
        for cookie_val in cookies:
            try:
                # Flask sessions may have a leading '.' — strip it
                clean = cookie_val.lstrip(".")
                decoded = base64.b64decode(clean)
                # Protocol 2+ header
                if (
                    len(decoded) >= 2
                    and decoded[0] == 0x80
                    and decoded[1] in (0x02, 0x03, 0x04, 0x05)
                ):
                    return 0.9
            except Exception as e:
                error_handler.handle_error(
                    ScanError(f"Error decoding cookie value: {e}"),
                )
        return 0.0

    def score_url(self, url: str) -> float:
        path = urlparse(url).path.lower()
        if path.endswith(".pickle") or path.endswith(".pkl"):
            return 0.8
        if "/unpickle" in path or "/deserialize" in path:
            return 0.5
        return 0.0

    def score_body(self, body: str, content_type: str) -> float:
        lo = body.lower()
        pickle_errors = ("unpickler", "pickle.", "pickle error", "unpickling error")
        if any(err in lo for err in pickle_errors):
            return 0.9
        return 0.0

    def build_payloads(self) -> List[Dict]:
        return [
            {
                "name": "Python pickle empty-dict probe",
                "data": payloads.deserialization_python_empty_dict,
                "content_type": "application/octet-stream",
                "submit_as": "body",
            },
            {
                "name": "Python pickle bogus-module probe",
                "data": payloads.deserialization_python_probe_module,
                "content_type": "application/octet-stream",
                "submit_as": "body",
            },
            {
                "name": "Python pickle in session cookie",
                "data": base64.b64encode(payloads.deserialization_python_empty_dict),
                "content_type": None,
                "submit_as": "cookie",
                "cookie_name": "session",
            },
        ]

    def indicates_deserialisation(
        self, status: int, body: str, headers: Dict[str, str]
    ) -> bool:
        lo = body.lower()
        # Our bogus module name echoed back in an ImportError proves pickle ran
        if "vulnradar_probe_module" in lo:
            return True
        # Generic pickle processing errors
        if "unpickl" in lo and (
            "error" in lo or "exception" in lo or "traceback" in lo
        ):
            return True
        if status == 500 and "pickle" in lo:
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# PHP ENGINE
# ─────────────────────────────────────────────────────────────────────────────


class _PHPEngine(_FormatEngine):
    """
    Detects and probes PHP serialisation (serialize() / unserialize()).

    Detection signals:
        • X-Powered-By containing "PHP"
        • Server containing "PHP" or known PHP app servers
        • Cookies whose values match PHP serialised-string syntax
        • .ser files in the URL
        • Error bodies mentioning __wakeup, __destruct, or unserialize

    Payloads:
        PHP's serialised format is plain ASCII, so payloads are human-readable.
        We send a minimal serialised object with a bogus class name.  If the
        server processes it (even returning an error that names the class),
        unserialisation is confirmed reachable.  We also inject via cookies —
        PHP apps frequently unserialise session cookies directly.
    """

    FORMAT_NAME = "php"

    # Regex-like check: PHP serialised strings start with a type char
    # followed by a colon.  Valid type chars: s, i, d, b, N, a, O, C

    def score_headers(self, headers: Dict[str, str]) -> float:
        xpb = headers.get("X-Powered-By", "").lower()
        server = headers.get("Server", "").lower()
        ct = headers.get("Content-Type", "").lower()

        score = 0.0
        if "php" in xpb:
            score += 0.8
        if "php" in server or "apache" in server:
            # Apache alone is weak; Apache + PHP is moderate
            if "php" in server:
                score += 0.7
            else:
                score += 0.2
        # Some PHP frameworks set this explicitly
        if "x-powered-by" in ct and "php" in ct:
            score += 0.5
        return min(score, 1.0)

    def score_cookies(self, cookies: List[str]) -> float:
        """Check if any cookie value looks like a PHP serialised structure."""
        for cookie_val in cookies:
            encoded = cookie_val.encode("utf-8", errors="replace")
            if any(
                encoded.startswith(prefix)
                for prefix in payloads.deserialization_php_serial_prefixes
            ):
                return 0.9
        return 0.0

    def score_url(self, url: str) -> float:
        path = urlparse(url).path.lower()
        if path.endswith(".ser"):
            return 0.5  # shared with Java; weaker signal for PHP alone
        if path.endswith(".php"):
            return 0.3  # confirms PHP runtime but not necessarily deserialisation
        if "/unserialize" in path:
            return 0.7
        return 0.0

    def score_body(self, body: str, content_type: str) -> float:
        lo = body.lower()
        php_errors = ("__wakeup", "__destruct", "unserialize()", "unserialization")
        if any(err in lo for err in php_errors):
            return 0.9
        # Generic PHP fatal error about serialised data
        if 'class "vulnradarprobe" not found' in lo:
            return 1.0
        return 0.0

    def build_payloads(self) -> List[Dict]:
        return [
            {
                "name": "PHP serialised bogus-class probe",
                "data": payloads.deserialization_php_probe_object,
                "content_type": "application/x-www-form-urlencoded",
                "submit_as": "parameter",
                "param_name": "data",
            },
            {
                "name": "PHP serialised array probe",
                "data": payloads.deserialization_php_probe_array,
                "content_type": "application/x-www-form-urlencoded",
                "submit_as": "parameter",
                "param_name": "data",
            },
            {
                "name": "PHP serialised object in cookie",
                "data": payloads.deserialization_php_probe_object,
                "content_type": None,
                "submit_as": "cookie",
                "cookie_name": "PHPSESSID",
            },
        ]

    def indicates_deserialisation(
        self, status: int, body: str, headers: Dict[str, str]
    ) -> bool:
        lo = body.lower()
        # Our bogus class name echoed back in an error proves unserialize ran
        if "vulnradarprobe" in lo:
            return True
        # PHP __wakeup / __destruct errors mean the object was instantiated
        if "__wakeup" in lo or "__destruct" in lo:
            return True
        # Generic unserialization error
        if "unserialize" in lo and ("error" in lo or "warning" in lo or "notice" in lo):
            return True
        return False


class _NodeEngine(_FormatEngine):
    """
    Detects and probes Node.js deserialization via node-serialize.

    Detection signals:
        • X-Powered-By / Server containing "Express", "Node", "Koa"
        • Cookies containing JSON-like serialized objects with _$$ND_FUNC$$_
        markers (node-serialize's function serialization)
        • .ser extensions in the URL
        • Error bodies mentioning node-serialize or unserialize()

    Payloads:
        node-serialize uses JSON with special markers for functions:
        {"a": 1, "b": "_$$ND_FUNC$$_function(){return 'test'}"}
        When unserialize() processes this, it evaluates the function.
        We send benign serialized objects to prove the deserializer runs,
        and objects with bogus property names that will echo back in errors
        if deserialization occurs.

    Important: we do NOT send RCE payloads. All payloads are benign
    objects or objects that reference non-existent properties. The
    operator can use actual node-serialize RCE payloads manually if
    they need to demonstrate exploitability in a controlled pentest.
    """

    FORMAT_NAME = "nodejs"

    def score_headers(self, headers: Dict[str, str]) -> float:
        xpb = headers.get("X-Powered-By", "").lower()
        server = headers.get("Server", "").lower()

        score = 0.0
        nodejs_keywords = (
            "express",
            "node",
            "koa",
            "hapi",
            "fastify",
            "nestjs",
            "next.js",
        )
        if any(kw in xpb for kw in nodejs_keywords):
            score += 0.7
        if any(kw in server for kw in nodejs_keywords):
            score += 0.5
        return min(score, 1.0)

    def score_cookies(self, cookies: List[str]) -> float:
        """
        Check if any cookie value looks like a node-serialize serialized object.

        node-serialize uses JSON with special function markers:
        _$$ND_FUNC$$_  — indicates a serialized function
        If we see this marker in a cookie, it's very likely node-serialize.
        """
        for cookie_val in cookies:
            # Check for node-serialize function marker
            if "_$$ND_FUNC$$_" in cookie_val:
                return 0.9
            # Also check if it's base64-encoded JSON-like content
            try:
                decoded = base64.b64decode(cookie_val)
                decoded_str = decoded.decode("utf-8", errors="ignore")
                if "_$$ND_FUNC$$_" in decoded_str:
                    return 0.9
                # Generic JSON object marker (less confident)
                if decoded_str.startswith("{") and decoded_str.endswith("}"):
                    return 0.3
            except Exception as e:
                error_handler.handle_error(
                    ScanError(f"Error decoding cookie value: {e}"),
                )
        return 0.0

    def score_url(self, url: str) -> float:
        path = urlparse(url).path.lower()
        if path.endswith(".ser") or "/serialize" in path or "/unserialize" in path:
            return 0.5
        if "/deserialize" in path:
            return 0.5
        return 0.0

    def score_body(self, body: str, content_type: str) -> float:
        lo = body.lower()
        nodejs_deser_errors = (
            "node-serialize",
            "unserialize()",
            "deserialize error",
            "serialization error",
            "json.parse",  # weak signal but relevant
        )
        if any(err in lo for err in nodejs_deser_errors):
            return 0.8
        return 0.0

    def build_payloads(self) -> List[Dict]:
        return [
            {
                "name": "Node.js benign object probe",
                "data": payloads.deserialization_nodejs_benign_object,
                "content_type": "application/json",
                "submit_as": "body",
            },
            {
                "name": "Node.js bogus-property probe",
                "data": payloads.deserialization_nodejs_probe_property,
                "content_type": "application/json",
                "submit_as": "body",
            },
            {
                "name": "Node.js serialized object in session cookie",
                "data": base64.b64encode(payloads.deserialization_nodejs_benign_object),
                "content_type": None,
                "submit_as": "cookie",
                "cookie_name": "connect.sid",
            },
        ]

    def indicates_deserialisation(
        self, status: int, body: str, headers: Dict[str, str]
    ) -> bool:
        lo = body.lower()
        # Our probe property names echoed back in an error proves deserialization ran
        if "vulnradar_nodejs_probe" in lo or "vulnradar_probe" in lo:
            return True
        # node-serialize specific error messages
        if "node-serialize" in lo:
            return True
        if "unserialize()" in lo and "error" in lo:
            return True
        # Generic deserialization error on 500
        if status == 500 and ("deserialize" in lo or "serialize" in lo):
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRY — single source of truth for which engines exist
# ─────────────────────────────────────────────────────────────────────────────

_ENGINES: List[_FormatEngine] = [
    _JavaEngine(),
    _PythonEngine(),
    _PHPEngine(),
    _NodeEngine(),
]


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────


class InsecureDeserializationScanner(BaseScanner):
    """
    Scan for insecure deserialisation across Java, Python, and PHP.

    Inherits BaseScanner directly — no session persistence or pre-crawl
    context is needed.  The two-phase fingerprint → payload discipline
    is enforced inside scan() for each URL.
    """

    def __init__(self, headers: Optional[Dict] = None, timeout: int = 10):
        super().__init__(headers=headers, timeout=timeout)

    async def scan(self, url: str) -> List[Finding]:
        """
        Two-phase scan of a single URL.

        Phase 1: fetch the URL, run every engine's scoring functions
                 against the response to build a confidence map.
        Phase 2: for every engine that cleared the threshold, submit
                 its payloads and check for deserialisation evidence.
        """
        findings: List[Finding] = []

        try:
            # ── Phase 1: fingerprint ──────────────────────────────────────
            response_data = await self._fetch_response_data(url)
            if response_data is None:
                return []

            headers, cookies, body, content_type, status = response_data
            confidence_map = self._fingerprint(
                headers, cookies, url, body, content_type
            )

            # ── Phase 2: format-gated payload submission ──────────────────
            for engine in _ENGINES:
                if confidence_map.get(engine.FORMAT_NAME, 0.0) < _CONFIDENCE_THRESHOLD:
                    continue  # format didn't clear the bar — skip entirely

                engine_findings = await self._probe_with_engine(url, engine, headers)
                findings.extend(engine_findings)

        except Exception as e:
            error_handler.handle_error(
                ScanError(
                    f"DeserializationScanner error on {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )

        return findings

    async def validate(self, url: str, payload: str, evidence: str) -> bool:
        """
        Re-submit the exact payload that produced the original finding.

        payload is JSON containing the engine name, the specific payload
        name, and the submission method.  We rebuild and re-send only
        that one payload — not the full library.
        """
        try:
            meta = json.loads(payload)
            engine_name = meta.get("engine")
            payload_name = meta.get("payload_name")
            submit_as = meta.get("submit_as")  # noqa

            # Find the engine
            engine = None
            for eng in _ENGINES:
                if eng.FORMAT_NAME == engine_name:
                    engine = eng
                    break
            if engine is None:
                return bool(evidence)  # unknown engine — trust original evidence

            # Find the specific payload
            target_payload = None
            for p in engine.build_payloads():
                if p["name"] == payload_name:
                    target_payload = p
                    break
            if target_payload is None:
                return bool(evidence)

            # Re-send it
            resp_status, resp_body, resp_headers = await self._submit_payload(
                url, target_payload
            )
            if resp_status is None:
                return False

            return engine.indicates_deserialisation(
                resp_status, resp_body, resp_headers
            )

        except (json.JSONDecodeError, KeyError):
            return bool(evidence)

    # ── internal: Phase 1 — fingerprinting ────────────────────────────────

    async def _fetch_response_data(
        self, url: str
    ) -> Optional[Tuple[Dict[str, str], List[str], str, str, int]]:
        """
        Fetch the URL and extract everything the fingerprinting phase needs.

        Returns (headers_dict, cookie_values_list, body_text, content_type, status)
        or None on network failure.
        """
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=self.timeout
            ) as session:
                async with session.get(url) as response:
                    headers = dict(response.headers)
                    body = await self._safe_read(response)
                    content_type = response.headers.get("Content-Type", "")
                    status = response.status

                    # Extract cookie values from Set-Cookie headers
                    # (aiohttp doesn't expose raw Set-Cookie as a simple list)
                    cookies: List[str] = []
                    for raw_cookie in response.headers.getall("Set-Cookie", []):
                        # Value is everything between the first = and the first ;
                        if "=" in raw_cookie:
                            value_part = (
                                raw_cookie.split("=", 1)[1].split(";")[0].strip()
                            )
                            cookies.append(value_part)

                    return (headers, cookies, body, content_type, status)

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(f"Fetch failed for {url}: {str(e)}", original_error=e),
                context={"url": url},
            )
            return None

    def _fingerprint(
        self,
        headers: Dict[str, str],
        cookies: List[str],
        url: str,
        body: str,
        content_type: str,
    ) -> Dict[str, float]:
        """
        Run every engine's scoring functions and return the confidence map.

        Pure computation — no network calls.  Each engine independently
        scores the same set of signals.  An engine's total_score() method
        weights the individual scores internally.
        """
        confidence: Dict[str, float] = {}
        for engine in _ENGINES:
            confidence[engine.FORMAT_NAME] = engine.total_score(
                headers, cookies, url, body, content_type
            )
        return confidence

    # ── internal: Phase 2 — payload submission ────────────────────────────

    async def _probe_with_engine(
        self,
        url: str,
        engine: _FormatEngine,
        original_headers: Dict[str, str],
    ) -> List[Finding]:
        """
        Submit every payload this engine has and collect findings.

        Each payload is submitted independently.  If the response shows
        evidence of deserialisation, a finding is recorded.
        """
        findings: List[Finding] = []

        for payload in engine.build_payloads():
            try:
                resp_status, resp_body, resp_headers = await self._submit_payload(
                    url, payload
                )
                if resp_status is None:
                    continue  # network failure on this payload — try the next

                if engine.indicates_deserialisation(
                    resp_status, resp_body, resp_headers
                ):
                    findings.append(
                        self._build_finding(
                            url, engine, payload, resp_status, resp_body
                        )
                    )

            except Exception as e:
                error_handler.handle_error(
                    ScanError(
                        f"Payload submission failed ({engine.FORMAT_NAME} / {payload['name']}): {str(e)}",
                        original_error=e,
                    ),
                    context={
                        "url": url,
                        "engine": engine.FORMAT_NAME,
                        "payload": payload["name"],
                    },
                )
                continue

        return findings

    async def _submit_payload(
        self, url: str, payload: Dict
    ) -> Tuple[Optional[int], str, Dict[str, str]]:
        """
        Send a single payload to the target.

        Dispatches based on payload["submit_as"]:
            "body"      → POST with the payload as the raw body
            "cookie"    → GET with the payload injected as a cookie value
            "parameter" → POST with the payload as a form parameter

        Returns (status, body_text, headers_dict).  status is None on failure.
        """
        try:
            submit_as = payload["submit_as"]
            data_raw = payload["data"]

            # Normalise data to bytes
            if isinstance(data_raw, str):
                data_bytes = data_raw.encode("utf-8")
            else:
                data_bytes = data_raw

            if submit_as == "body":
                ct = payload.get("content_type", "application/octet-stream")
                post_headers = {**self.headers, "Content-Type": ct}
                async with self.session.post(
                    url, data=data_bytes, headers=post_headers
                ) as resp:
                    body = await resp.text()
                    return (resp.status, body, dict(resp.headers))

            elif submit_as == "cookie":
                cookie_name = payload.get("cookie_name", "session")
                # data may be bytes (base64-encoded) — decode to str for cookie
                cookie_val = data_bytes.decode("ascii", errors="replace")
                cookie_header = {
                    **self.headers,
                    "Cookie": f"{cookie_name}={cookie_val}",
                }
                async with self.session.get(url, headers=cookie_header) as resp:
                    body = await resp.text()
                    return (resp.status, body, dict(resp.headers))

            elif submit_as == "parameter":
                param_name = payload.get("param_name", "data")
                # PHP payloads are ASCII text — send as form data
                form_data = {param_name: data_bytes.decode("utf-8", errors="replace")}
                async with self.session.post(url, data=form_data) as resp:
                    body = await resp.text()
                    return (resp.status, body, dict(resp.headers))

            else:
                return (None, "", {})

        except (aiohttp.ClientError, TimeoutError) as e:
            error_handler.handle_error(
                NetworkError(
                    f"Payload submission failed for {url}: {str(e)}", original_error=e
                ),
                context={"url": url},
            )
            return (None, "", {})

    # ── internal: finding builder ─────────────────────────────────────────

    @staticmethod
    def _build_finding(
        url: str,
        engine: _FormatEngine,
        payload: Dict,
        resp_status: int,
        resp_body: str,
    ) -> Finding:
        """
        Assemble a finding dict with exactly the keys core.py expects.

        The payload field is JSON so validate() can reconstruct which
        specific engine + payload produced this finding.
        """
        # Truncate the response body in evidence to avoid bloating the DB
        evidence_body = resp_body[:300] if len(resp_body) > 300 else resp_body

        return Finding(
            type="Insecure Deserialization",
            endpoint=url,
            severity=Severity.CRITICAL,
            description=(
                f"Insecure deserialisation detected ({engine.FORMAT_NAME.title()}): "
                f"{payload['name']} — server processed a crafted serialised object"
            ),
            evidence=(
                f"Submitted '{payload['name']}' via {payload['submit_as']} to {url}. "
                f"Server responded with status {resp_status}. "
                f"Response body contains deserialisation indicators:\n{evidence_body}"
            ),
            remediation=(
                f"Do not deserialise {engine.FORMAT_NAME.title()} data from untrusted sources. "
                f"If deserialisation is required, use a whitelist of allowed classes and "
                f"validate the input before processing. "
                f"For Java: use a custom ObjectInputStream that rejects unknown classes. "
                f"For Python: never use pickle on user-supplied data — use JSON instead. "
                f"For PHP: avoid unserialize() on user input — use json_decode() instead."
            ),
            payload=json.dumps(
                {
                    "engine": engine.FORMAT_NAME,
                    "payload_name": payload["name"],
                    "submit_as": payload["submit_as"],
                    "cookie_name": payload.get("cookie_name"),
                    "param_name": payload.get("param_name"),
                }
            ),
            **get_standards("Insecure Deserialization"),
        )
