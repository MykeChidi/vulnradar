# vulnradar/models/finding.py

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional

from .severity import Severity


@dataclass
class Finding:
    """
    Canonical data contract for all scanner output.

    Every scanner must return List[Finding].
    The reporter, database, and CLI summary all consume List[Finding].
    No raw dicts cross scanner boundaries.
    """

    # Identification
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""
    severity: Severity = Severity.MEDIUM

    # Location
    endpoint: str = ""
    parameter: Optional[str] = None
    method: str = "GET"

    # Evidence
    payload: Optional[str] = None
    evidence: str = ""
    description: str = ""
    remediation: str = ""

    # Standards mapping — populated by models/standards.py get_standards()
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None  # e.g. "CWE-89"
    owasp_category: Optional[str] = None  # e.g. "A03:2021 - Injection"

    # Metadata
    tags: list[str] = field(default_factory=list)
    scan_id: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSON output, DB storage, and report templates."""
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Deserialise from a plain dict (e.g. from cache or DB)."""
        d = d.copy()
        if "severity" in d and isinstance(d["severity"], str):
            d["severity"] = Severity.from_str(d["severity"])
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})
