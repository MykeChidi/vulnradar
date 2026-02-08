# vulnradar/utils/reporter.py - JSON, HTML or PDF Scan Report

import json
from pathlib import Path

import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from .error_handler import get_global_error_handler, handle_errors, ResourceError

error_handler = get_global_error_handler()

class Report:
    """Data holder for all scan results."""
    def __init__(self, *, target, scan_time, vulnerabilities=None, reconnaissance=None, 
                 endpoints=None, technologies=None, is_recon_only=False):
        self.target = target
        self.scan_time = scan_time
        self.vulnerabilities = vulnerabilities or []
        self.reconnaissance = reconnaissance or {}
        self.endpoints = endpoints or set()
        self.technologies = technologies or {}
        self.is_recon_only = is_recon_only

class ReportGenerator:
    """Generate HTML, PDF, JSON, and Excel reports from a Report object."""
    def __init__(self, *, title: str, output_dir: Path):
        self.title = title
        self.output_dir = Path(output_dir)
        self.templates = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            autoescape=select_autoescape(["html", "xml"])
        )

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to generate HTML report",
        return_on_error=None
    )
    def generate_html_report(self, report: Report) -> str:
        """Generate HTML report, with different templates for recon-only vs vulnerability scans."""
        # Choose template based on report type
        if report.is_recon_only:
            try:
                tpl = self.templates.get_template("recon_report.html.j2")
            except:
                # Fallback to standard report template if recon template doesn't exist
                tpl = self.templates.get_template("report.html.j2")
        else:
            tpl = self.templates.get_template("report.html.j2")
        
        html = tpl.render(
            title=self.title,
            target=report.target,
            scan_time=report.scan_time,
            vulnerabilities=report.vulnerabilities,
            reconnaissance=report.reconnaissance,
            endpoints=report.endpoints,
            technologies=report.technologies,
            is_recon_only=report.is_recon_only
        )
        path = self.output_dir / f"{report.target.replace('://','_')}.html"
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
        except Exception as e:
            error_handler.handle_error(
                ResourceError(f"Failed to write HTML report: {str(e)}", original_error=e),
                context={"target": report.target, "path": str(path)}
            )
            raise
        return str(path)

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to generate PDF report",
        return_on_error=None
    )
    def generate_pdf_report(self, report: Report) -> str:
        """Generate PDF report, handling recon-only and vulnerability scan data."""
        path = self.output_dir / f"{report.target.replace('://','_')}.pdf"
        doc = SimpleDocTemplate(str(path), pagesize=letter)
        
        if report.is_recon_only:
            # For recon-only reports, format reconnaissance data
            data = [["Category", "Key", "Value"]]
            for category, details in report.reconnaissance.items():
                if isinstance(details, dict):
                    for key, value in details.items():
                        data.append([str(category), str(key), str(value)[:50]])
                else:
                    data.append([str(category), "-", str(details)[:50]])
        else:
            # For vulnerability scans, format vulnerability data
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

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to generate JSON report",
        return_on_error=None
    )
    def generate_json_report(self, report: Report) -> str:
        """Generate JSON report, organizing data based on report type."""
        if report.is_recon_only:
            obj = {
                "report_type": "reconnaissance",
                "target": report.target,
                "scan_time": report.scan_time,
                "reconnaissance": report.reconnaissance,
            }
        else:
            obj = {
                "report_type": "vulnerability_scan",
                "target": report.target,
                "scan_time": report.scan_time,
                "vulnerabilities": report.vulnerabilities,
                "reconnaissance": report.reconnaissance,
                "endpoints": list(report.endpoints),
                "technologies": report.technologies
            }
        
        path = self.output_dir / f"{report.target.replace('://','_')}.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, indent=2)
        except Exception as e:
            error_handler.handle_error(
                ResourceError(f"Failed to write JSON report: {str(e)}", original_error=e),
                context={"target": report.target, "path": str(path)}
            )
            raise
        return str(path)

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to generate Excel report",
        return_on_error=None
    )
    def generate_excel_report(self, report: Report) -> str:
        """Generate Excel report, handling both recon-only and vulnerability data."""
        if report.is_recon_only:
            # For recon-only, flatten the reconnaissance dictionary into a DataFrame
            recon_data = []
            for category, details in report.reconnaissance.items():
                if isinstance(details, dict):
                    for key, value in details.items():
                        recon_data.append({
                            "Category": category,
                            "Key": key,
                            "Value": str(value)
                        })
                else:
                    recon_data.append({
                        "Category": category,
                        "Key": "-",
                        "Value": str(details)
                    })
            df = pd.DataFrame(recon_data)
        else:
            # For vulnerability scans, use vulnerability data
            df = pd.DataFrame(report.vulnerabilities)
        
        path = self.output_dir / f"{report.target.replace('://','_')}.xlsx"
        try:
            df.to_excel(path, index=False)
        except Exception as e:
            error_handler.handle_error(
                ResourceError(f"Failed to write Excel report: {str(e)}", original_error=e),
                context={"target": report.target, "path": str(path)}
            )
            raise
        return str(path)
