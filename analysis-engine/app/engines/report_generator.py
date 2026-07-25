"""
SUDARSHAN — Report Generator
=============================
Generates a standalone HTML report (without Jinja2 dependency) from the
collected JSON artifacts of a run.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any
from string import Template

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sudarshan Enterprise Report - $package_name</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
        h1, h2 { color: #569cd6; border-bottom: 1px solid #333; padding-bottom: 5px; }
        .card { background: #252526; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #007acc; }
        .critical { border-left-color: #f44336; }
        .high { border-left-color: #ff9800; }
        .medium { border-left-color: #ffeb3b; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #333; }
        th { background-color: #2d2d2d; }
        pre { background: #1e1e1e; padding: 10px; overflow-x: auto; border-radius: 3px; }
        .badge { padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }
        .badge-critical { background: #f44336; color: white; }
    </style>
</head>
<body>
    <h1>Sudarshan Investigation Report</h1>
    
    <div class="card $risk_level">
        <h2>Executive Summary</h2>
        <p><strong>Target:</strong> $package_name</p>
        <p><strong>Device:</strong> $device</p>
        <p><strong>BFCI Score:</strong> <span style="font-size: 1.2em; font-weight: bold;">$bfci</span></p>
        <p><strong>Duration:</strong> $duration s</p>
    </div>

    <div class="card">
        <h2>MITRE ATT&CK Matrix</h2>
        $mitre_html
    </div>
    
    <div class="card">
        <h2>Intelligence & IOCs</h2>
        $iocs_html
    </div>

    <div class="card">
        <h2>Anti-Analysis Detections</h2>
        $anti_analysis_html
    </div>

    <div class="card">
        <h2>Dynamic Evidence</h2>
        $evidence_html
    </div>

</body>
</html>
"""

class ReportGenerator:
    def __init__(self, apk_dir: Path, package_name: str, base_result: Dict[str, Any]):
        self.apk_dir = Path(apk_dir)
        self.package_name = package_name
        self.result = base_result

    def _load_json(self, filename: str) -> Any:
        path = self.apk_dir / filename
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"[ReportGen] Failed to load {filename}: {e}")
        return None

    def _generate_mitre_html(self, mitre_data: Dict) -> str:
        if not mitre_data or "techniques" not in mitre_data:
            return "<p>No MITRE techniques mapped.</p>"
            
        html = "<table><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Context</th></tr>"
        for tech in mitre_data["techniques"]:
            html += f"<tr><td>{tech.get('techniqueID')}</td><td>{tech.get('techniqueName')}</td><td>{tech.get('tactic')}</td><td>{tech.get('comment', '')}</td></tr>"
        html += "</table>"
        return html

    def _generate_iocs_html(self, iocs: Dict) -> str:
        if not iocs:
            return "<p>No IOCs collected.</p>"
            
        html = ""
        for key, vals in iocs.items():
            if key != "total_count" and vals:
                html += f"<h3>{key.upper()}</h3><ul>"
                for v in vals:
                    html += f"<li>{v}</li>"
                html += "</ul>"
        return html

    def _generate_evidence_html(self, evidence: Dict) -> str:
        if not evidence or "records" not in evidence:
            return "<p>No evidence collected.</p>"
            
        html = "<table><tr><th>Severity</th><th>API</th><th>Description</th></tr>"
        for rec in evidence["records"]:
            sev = rec.get("severity", "MED")
            badge = f'<span class="badge badge-critical">{sev}</span>' if sev in ("CRITICAL","HIGH") else sev
            html += f"<tr><td>{badge}</td><td>{rec.get('api')}</td><td>{rec.get('description')}</td></tr>"
        html += "</table>"
        return html

    def render(self, output_path: Path) -> bool:
        """Generates the HTML report."""
        try:
            # Load artifacts
            mitre_data = self._load_json("mitre.json")
            iocs_data = self._load_json("iocs.json")
            anti_analysis = self._load_json("anti_analysis.json")
            evidence_data = self._load_json("evidence.json")
            
            bfci = self.result.get("bfci", 0.0)
            risk_class = "critical" if bfci > 50 else ("high" if bfci > 30 else "medium")
            
            anti_html = "<p>No anti-analysis techniques detected.</p>"
            if anti_analysis:
                anti_html = "<ul>"
                for aa in anti_analysis:
                    anti_html += f"<li><strong>{aa.get('technique')}</strong>: {aa.get('description')}</li>"
                anti_html += "</ul>"

            # Prepare template data
            data = {
                "package_name": self.package_name,
                "device": self.result.get("device", "Unknown"),
                "bfci": f"{bfci:.1f}",
                "duration": self.result.get("duration_seconds", 0),
                "risk_level": risk_class,
                "mitre_html": self._generate_mitre_html(mitre_data),
                "iocs_html": self._generate_iocs_html(iocs_data),
                "anti_analysis_html": anti_html,
                "evidence_html": self._generate_evidence_html(evidence_data)
            }
            
            template = Template(HTML_TEMPLATE)
            rendered = template.safe_substitute(data)
            
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(rendered)
                
            logger.info(f"[ReportGen] Generated report → {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"[ReportGen] Report generation failed: {e}")
            return False
