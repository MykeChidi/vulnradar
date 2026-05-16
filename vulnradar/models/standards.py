# vulnradar/models/standards.py

from typing import Dict

# Maps finding type string → CWE, OWASP category, and CVSS base score.
# Used by every scanner when building a Finding via **get_standards("Type").
VULN_STANDARDS: Dict[str, Dict] = {
    "SQL Injection": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 9.8,
    },
    "Reflected XSS": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 6.1,
    },
    "Stored XSS": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 8.0,
    },
    "DOM XSS": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 6.1,
    },
    "XSS": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 6.1,
    },
    "CSRF": {
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_score": 6.5,
    },
    "SSRF": {
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021 - Server-Side Request Forgery",
        "cvss_score": 8.6,
    },
    "Path Traversal": {
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_score": 7.5,
    },
    "File Inclusion": {
        "cwe_id": "CWE-98",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 9.0,
    },
    "Command Injection": {
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 9.8,
    },
    "Security Misconfiguration": {
        "cwe_id": "CWE-16",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_score": 5.3,
    },
    "Broken Authentication": {
        "cwe_id": "CWE-287",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_score": 8.1,
    },
    "IDOR": {
        "cwe_id": "CWE-639",
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_score": 7.5,
    },
    "Mass Assignment": {
        "cwe_id": "CWE-915",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 7.3,
    },
    "API Security": {
        "cwe_id": "CWE-284",
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_score": 7.5,
    },
    "Insecure Deserialization": {
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "cvss_score": 9.8,
    },
    "LDAP Injection": {
        "cwe_id": "CWE-90",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 7.5,
    },
    "XXE": {
        "cwe_id": "CWE-611",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_score": 8.2,
    },
    "NoSQL Injection": {
        "cwe_id": "CWE-943",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 8.8,
    },
}
# Phase 2 — uncomment as new scanners are added:
""""Open Redirect": {
    "cwe_id": "CWE-601",
    "owasp_category": "A01:2021 - Broken Access Control",
    "cvss_score": 6.1,
},
"SSTI": {
    "cwe_id": "CWE-94",
    "owasp_category": "A03:2021 - Injection",
    "cvss_score": 9.8,
},
"CORS Misconfiguration": {
    "cwe_id": "CWE-942",
    "owasp_category": "A05:2021 - Security Misconfiguration",
    "cvss_score": 6.5,
},
"JWT Misconfiguration": {
    "cwe_id": "CWE-347",s
    "owasp_category": "A02:2021 - Cryptographic Failures",
    "cvss_score": 7.5,
},"""


def get_standards(vuln_type: str) -> Dict:
    """
    Return CWE, OWASP category, and CVSS score for a finding type.

    Returns an empty dict if the type is not in the table — never raises.
    """
    return VULN_STANDARDS.get(vuln_type, {})
