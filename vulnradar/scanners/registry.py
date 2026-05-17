# vulnradar/scanners/registry.py

# Central registry mapping CLI option keys to their scanner classes.
# To add a new scanner in v2.0: add one line here. Nothing else changes.

from typing import Dict, Type

from .api_security import APISecurityScanner
from .base import BaseScanner
from .broken_auth import BrokenAuthScanner
from .comm_injection import CommandInjectionScanner
from .cors import CORSScanner
from .csrf import CSRFScanner
from .deserialization import InsecureDeserializationScanner
from .file_inclusion import FileInclusionScanner
from .idor import IDORScanner
from .jwt_scanner import JWTScanner
from .ldap_injection import LDAPInjectionScanner
from .mass_assignment import MassAssignmentScanner
from .nosql import NoSQLInjectionScanner
from .open_redirect import OpenRedirectScanner
from .path_traversal import PathTraversalScanner
from .security_misconfig import SecurityMisconfigScanner
from .sqli import SQLInjectionScanner
from .ssrf import SSRFScanner
from .ssti import SSTIScanner
from .xss import XSSScanner
from .xxe import XXEScanner

# Maps the options dict key → scanner class.
# The key must exactly match the key used in cli.py's options dict.
SCANNER_REGISTRY: Dict[str, Type[BaseScanner]] = {
    "scan_sqli": SQLInjectionScanner,
    "scan_xss": XSSScanner,
    "scan_csrf": CSRFScanner,
    "scan_ssrf": SSRFScanner,
    "scan_path_traversal": PathTraversalScanner,
    "scan_file_inclusion": FileInclusionScanner,
    "scan_command_injection": CommandInjectionScanner,
    "scan_security_misconfig": SecurityMisconfigScanner,
    "scan_broken_auth": BrokenAuthScanner,
    "scan_idor": IDORScanner,
    "scan_mass_assignment": MassAssignmentScanner,
    "scan_api_security": APISecurityScanner,
    "scan_deserialization": InsecureDeserializationScanner,
    "scan_ldap_injection": LDAPInjectionScanner,
    "scan_xxe": XXEScanner,
    "scan_no_sql": NoSQLInjectionScanner,
    "scan_open_redirect": OpenRedirectScanner,
    "scan_ssti": SSTIScanner,
    "scan_cors": CORSScanner,
    "scan_jwt": JWTScanner,
}

# Maps the finding "type" string → the scanner class that validates it.
# Used by validate_findings() to look up the right validator
# ---------------------------------------------------------------------------
FINDING_TYPE_REGISTRY: Dict[str, Type[BaseScanner]] = {
    "SQL Injection": SQLInjectionScanner,
    "XSS": XSSScanner,
    "Reflected XSS": XSSScanner,
    "Stored XSS": XSSScanner,
    "DOM XSS": XSSScanner,
    "CSRF": CSRFScanner,
    "SSRF": SSRFScanner,
    "Path Traversal": PathTraversalScanner,
    "File Inclusion": FileInclusionScanner,
    "Command Injection": CommandInjectionScanner,
    "Security Misconfiguration": SecurityMisconfigScanner,
    "Broken Authentication": BrokenAuthScanner,
    "IDOR": IDORScanner,
    "Mass Assignment": MassAssignmentScanner,
    "API Security": APISecurityScanner,
    "Insecure Deserialization": InsecureDeserializationScanner,
    "LDAP Injection": LDAPInjectionScanner,
    "XXE": XXEScanner,
    "NoSQL Injection": NoSQLInjectionScanner,
    "Open Redirect": OpenRedirectScanner,
    "SSTI": SSTIScanner,
    "CORS Misconfiguration": CORSScanner,
    "JWT Misconfiguration": JWTScanner,
}
