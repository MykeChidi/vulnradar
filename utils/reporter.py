# vulnscan/utils/reporter.py - JSON, HTML or PDF Scan Report

import json
from pathlib import Path

import pandas as pd
from jinja2 import Environment, FileSystemLoader
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

class Report:
    """Data holder for all scan results."""
    def __init__(self, *, target, scan_time, vulnerabilities, reconnaissance, endpoints, technologies):
        self.target = target
        self.scan_time = scan_time
        self.vulnerabilities = vulnerabilities
        self.reconnaissance = reconnaissance
        self.endpoints = endpoints
        self.technologies = technologies

class ReportGenerator:
    """Generate HTML, PDF, JSON, and Excel reports from a Report object."""
    def __init__(self, *, title: str, output_dir: Path):
        self.title = title
        self.output_dir = Path(output_dir)
        self.templates = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates")
        )

    def generate_html_report(self, report: Report) -> str:
        tpl = self.templates.get_template("report.html.j2")
        html = tpl.render(
            title=self.title,
            target=report.target,
            scan_time=report.scan_time,
            vulnerabilities=report.vulnerabilities,
            reconnaissance=report.reconnaissance,
            endpoints=report.endpoints,
            technologies=report.technologies
        )
        path = self.output_dir / f"{report.target.replace('://','_')}.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(path)

    def generate_pdf_report(self, report: Report) -> str:
        path = self.output_dir / f"{report.target.replace('://','_')}.pdf"
        doc = SimpleDocTemplate(str(path), pagesize=letter)
        data = [["Type", "Endpoint", "Severity", "Description"]]
        for v in report.vulnerabilities:
            data.append([v["type"], v["endpoint"], v["severity"], v["description"]])
        table = Table(data, repeatRows=1)
        style = TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
            ("GRID", (0,0), (-1,-1), 0.5, colors.black),
        ])
        table.setStyle(style)
        doc.build([table])
        return str(path)

    def generate_json_report(self, report: Report) -> str:
        obj = {
            "target": report.target,
            "scan_time": report.scan_time,
            "vulnerabilities": report.vulnerabilities,
            "reconnaissance": report.reconnaissance,
            "endpoints": report.endpoints,
            "technologies": report.technologies
        }
        path = self.output_dir / f"{report.target.replace('://','_')}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        return str(path)

    def generate_excel_report(self, report: Report) -> str:
        df = pd.DataFrame(report.vulnerabilities)
        path = self.output_dir / f"{report.target.replace('://','_')}.xlsx"
        df.to_excel(path, index=False)
        return str(path)
