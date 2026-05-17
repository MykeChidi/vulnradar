# vulnradar/utils/payload_filter.py

from __future__ import annotations

from typing import Dict, List


class PayloadFilter:
    """
    Filter payload lists based on technologies detected by ``TechDetector``.

    Args:
        technologies: The ``technologies`` dict from ``ScanContext``.  Keys
                      vary by detector but typically include ``"server"``,
                      ``"language"``, ``"framework"``, ``"database"``, and
                      ``"template_engine"``.
    """

    def __init__(self, technologies: Dict) -> None:
        self._tech_str = str(technologies).lower()

    # ── public: filter methods ────────────────────────────────────────────

    def filter_sqli(self, payloads: List[str]) -> List[str]:
        """
        Return payloads relevant to the detected database backend.

        If no database is detected the full list is returned so no coverage
        is silently dropped.
        """
        db = self._detect_db()

        if db == "mysql":
            return [
                p
                for p in payloads
                if any(
                    k in p
                    for k in (
                        "SLEEP",
                        "BENCHMARK",
                        "information_schema",
                        "mysql",
                        "0x",
                        "char(",
                    )
                )
            ]
        if db in ("postgresql", "postgres"):
            return [
                p
                for p in payloads
                if any(
                    k in p
                    for k in ("pg_sleep", "pg_catalog", "version()", "::text", "||")
                )
            ]
        if db == "mssql":
            return [
                p
                for p in payloads
                if any(
                    k in p
                    for k in (
                        "WAITFOR",
                        "xp_cmdshell",
                        "sysobjects",
                        "@@version",
                        "CAST(",
                    )
                )
            ]
        if db == "oracle":
            return [
                p
                for p in payloads
                if any(
                    k in p
                    for k in ("DBMS_PIPE", "ALL_TABLES", "dual", "ROWNUM", "UTL_HTTP")
                )
            ]

        # Unknown DB — keep everything so no coverage is silently dropped.
        return payloads

    def filter_ssti(self, payloads: List[str]) -> List[str]:
        """
        Return payloads for the detected template engine only.
        """
        engine = self._detect_template_engine()

        engine_markers: Dict[str, List[str]] = {
            "jinja2": ["{{", "{%"],
            "twig": ["{{", "{%"],
            "freemarker": ["${", "<#", "?"],
            "velocity": ["#set", "#if", "#foreach", "$!"],
            "erb": ["<%=", "<%"],
            "handlebars": ["{{", "{{#"],
            "smarty": ["{$", "{if"],
            "pebble": ["{{", "{%"],
            "mako": ["${", "<%"],
        }

        if engine and engine in engine_markers:
            markers = engine_markers[engine]
            return [p for p in payloads if any(p.startswith(m) for m in markers)]

        return payloads

    def filter_command_injection(self, payloads: List[str]) -> List[str]:
        """
        Return OS-specific payloads based on the detected server OS.

        Windows command payloads (`cmd /c`, `dir`) are skipped on Linux targets
        and vice versa.
        """
        os_hint = self._detect_os()

        if os_hint == "linux":
            return [
                p
                for p in payloads
                if not any(k in p for k in ("cmd /c", "dir ", "type ", "ipconfig"))
            ]
        if os_hint == "windows":
            return [
                p
                for p in payloads
                if not any(k in p for k in ("cat ", "ls ", "id ", "uname", "whoami &&"))
            ]

        return payloads

    def should_skip_scanner(
        self,
        option_key: str,
        has_forms: bool = False,
        has_file_params: bool = False,
        has_jwt: bool = False,
    ) -> bool:
        """
        Return ``True`` if a scanner can be safely skipped given what is known
        about the target.

        Args:
            option_key:      The registry key for the scanner (e.g.
                             ``"scan_csrf"``).
            has_forms:       Whether the crawler found HTML forms.
            has_file_params: Whether any parameter name looks file-related.
            has_jwt:         Whether a JWT token was found in the responses.
        """
        if option_key == "scan_csrf" and not has_forms:
            return True
        if option_key == "scan_file_inclusion" and not has_file_params:
            return True
        if option_key == "scan_jwt" and not has_jwt:
            return True

        return False

    # ── private: technology detection ────────────────────────────────────

    def _detect_db(self) -> str:
        """Infer the database backend from the technology string."""
        for db in (
            "mysql",
            "postgresql",
            "postgres",
            "mssql",
            "sqlite",
            "oracle",
            "mongodb",
            "mariadb",
        ):
            if db in self._tech_str:
                return db
        return ""

    def _detect_template_engine(self) -> str:
        """Infer the template engine from the technology string."""
        for engine in (
            "jinja2",
            "twig",
            "freemarker",
            "velocity",
            "erb",
            "handlebars",
            "smarty",
            "pebble",
            "mako",
        ):
            if engine in self._tech_str:
                return engine
        return ""

    def _detect_os(self) -> str:
        """Infer the server OS from the technology string."""
        if any(
            k in self._tech_str
            for k in ("linux", "ubuntu", "debian", "centos", "nginx", "apache")
        ):
            return "linux"
        if any(k in self._tech_str for k in ("windows", "iis", "asp.net")):
            return "windows"
        return ""
