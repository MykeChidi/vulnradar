import asyncio
import sys
import yaml
from pathlib import Path

import pytest


class FakeVulnRadar:
    def __init__(self, target_url, options):
        self.target_url = target_url
        self.options = options

    async def scan(self):
        return {
            'target': self.target_url,
            'vulnerabilities': [{'severity': 'High', 'type': 'XSS', 'endpoint': '/'}],
            'endpoints': ['/'],
            'scan_time': 'now'
        }


def test_multi_target_scan_and_summary(tmp_path, monkeypatch):
    """Verify MultiTargetScanner loads YAML, runs scans and generates summary."""
    # Create a simple YAML config with two targets (string and dict form)
    data = [
        "https://example.com",
        {"url": "https://api.example.com", "name": "API", "timeout": 5},
    ]

    cfg = tmp_path / "targets.yaml"
    cfg.write_text(yaml.safe_dump(data))

    # Patch the VulnRadar class used by multi_target to avoid network calls
    monkeypatch.setattr('vulnradar.multi_target.VulnRadar', FakeVulnRadar)

    from vulnradar.multi_target import MultiTargetScanner

    scanner = MultiTargetScanner(config_file=cfg, default_options={}, concurrent=False, rate_limit=0)

    results = asyncio.run(scanner.scan_all())

    assert len(results) == 2

    summary = scanner.generate_summary()
    assert summary['total_targets'] == 2
    assert summary['successful_scans'] == 2
    # One vulnerability per fake scan
    assert summary['total_vulnerabilities'] == 2
    assert summary['vulnerabilities_by_severity']['High'] == 2


def test_cli_cannot_specify_url_and_targets_file(monkeypatch):
    """Ensure CLI rejects using both URL and --targets-file together."""
    # Simulate argv containing both a URL and a targets file
    monkeypatch.setattr(sys, 'argv', ['vulnradar', 'https://example.com', '--targets-file', 'file.yaml'])

    from vulnradar import cli

    with pytest.raises(SystemExit):
        cli.parse_arguments()
