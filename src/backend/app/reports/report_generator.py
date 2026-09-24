import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates HTML reports from malware analysis data.
    """

    def __init__(self):
        # Color palettes
        self.risk_colors = {
            "LOW": "#28a745",
            "MEDIUM": "#ffc107",
            "HIGH": "#fd7e14",
            "CRITICAL": "#dc3545"
        }

    def _generate_css(self) -> str:
        """Returns embedded CSS for the HTML report."""
        return """
        <style>
            :root {
                --primary: #1a1a2e;
                --text-color: #333;
                --bg-color: #fff;
                --border-color: #e0e0e0;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                color: var(--text-color);
                background-color: var(--bg-color);
                line-height: 1.6;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: var(--primary);
                color: white;
                padding: 20px;
                text-align: center;
                border-radius: 8px 8px 0 0;
            }
            .header h1 { margin: 0 0 10px 0; }
            .header p { margin: 0; font-size: 0.9em; opacity: 0.8; }
            .section {
                background: white;
                border: 1px solid var(--border-color);
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 0 0 8px 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            h2 {
                color: var(--primary);
                border-bottom: 2px solid var(--primary);
                padding-bottom: 5px;
                margin-top: 0;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 15px;
            }
            th, td {
                padding: 10px;
                border: 1px solid var(--border-color);
                text-align: left;
            }
            th { background-color: #f8f9fa; }
            tr:nth-child(even) { background-color: #f8f9fa; }
            .badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 4px;
                color: white;
                font-weight: bold;
                font-size: 0.9em;
            }
            .badge-malicious { background-color: #dc3545; }
            .badge-benign { background-color: #28a745; }
            .shap-bar-container {
                width: 100%;
                background-color: #f0f0f0;
                border-radius: 4px;
                overflow: hidden;
                position: relative;
                height: 20px;
                display: flex;
            }
            .shap-axis {
                width: 1px;
                background: #333;
                position: absolute;
                left: 50%;
                height: 100%;
                z-index: 2;
            }
            .shap-bar {
                height: 100%;
                position: absolute;
                top: 0;
                z-index: 1;
            }
            .shap-bar.positive { background-color: #dc3545; left: 50%; }
            .shap-bar.negative { background-color: #0d6efd; right: 50%; }
            .disclaimer {
                font-size: 0.85em;
                color: #666;
                text-align: center;
                margin-top: 40px;
                padding: 20px;
                border-top: 1px solid var(--border-color);
            }
            @media print {
                body { background-color: white; }
                .container { box-shadow: none; max-width: 100%; }
                .section { box-shadow: none; border: 1px solid #ccc; page-break-inside: avoid; }
            }
        </style>
        """

    def generate_report(self, analysis_data: Dict[str, Any]) -> str:
        """
        Generates a complete HTML report string from analysis data.
        
        Args:
            analysis_data: Dictionary containing all analysis results.
            
        Returns:
            str: The HTML content of the report.
        """
        logger.info(f"Generating HTML report for analysis {analysis_data.get('analysis_id')}")
        
        # Safely extract data
        file_info = analysis_data.get("file_info", {})
        prediction = analysis_data.get("prediction", {})
        risk_data = analysis_data.get("risk_assessment", {})
        static_features = analysis_data.get("static_features", {})
        explanation = analysis_data.get("explanation", {})
        threat_intel = analysis_data.get("threat_intelligence")
        
        css = self._generate_css()
        
        # Risk assessment breakdown
        risk_score = risk_data.get("total_score", 0)
        risk_level = risk_data.get("risk_level", "UNKNOWN")
        risk_color = self.risk_colors.get(risk_level.upper(), "#6c757d")
        
        # Prediction
        pred_label = prediction.get("prediction", "UNKNOWN").upper()
        pred_badge_class = "badge-malicious" if pred_label == "MALICIOUS" else "badge-benign"
        pred_conf = prediction.get("confidence", 0.0) * 100
        
        # Breakdown HTML
        breakdown_html = ""
        breakdown = risk_data.get("breakdown", {})
        for component, scores in breakdown.items():
            breakdown_html += f"<tr><td>{component.replace('_', ' ').title()}</td>"
            breakdown_html += f"<td>{scores.get('score', 0):.1f} / {scores.get('max', 0):.1f}</td></tr>"

        # Factors HTML
        factors = risk_data.get("contributing_factors", [])
        factors_html = "<ul>" + "".join(f"<li>{f}</li>" for f in factors) + "</ul>" if factors else "<p>None identified.</p>"
        
        # SHAP HTML
        shap_html = ""
        if explanation and explanation.get("shap_values"):
            shap_values = explanation.get("shap_values", [])
            max_val = max([abs(v) for _, v in shap_values]) if shap_values else 1.0
            if max_val == 0: max_val = 1.0 # Prevent division by zero
            
            shap_html += """<table>
                <thead><tr><th>Feature</th><th>Contribution Value</th><th>Impact</th></tr></thead><tbody>"""
                
            for feature, value in shap_values[:15]:  # Show top 15
                direction = "positive" if value > 0 else "negative"
                width = min(abs(value) / max_val * 50, 50)  # Max 50% width from center
                
                shap_html += f"""
                <tr>
                    <td>{feature}</td>
                    <td>{value:.4f}</td>
                    <td>
                        <div class="shap-bar-container">
                            <div class="shap-axis"></div>
                            <div class="shap-bar {direction}" style="width: {width}%;"></div>
                        </div>
                    </td>
                </tr>
                """
            shap_html += "</tbody></table>"
        else:
            shap_html = "<p>Explainability data not available.</p>"

        # Threat Intel HTML
        ti_html = ""
        if threat_intel:
            provider = threat_intel.get("provider", "Unknown")
            detections = threat_intel.get("malicious_detections", 0)
            total = threat_intel.get("total_engines", 0)
            family = threat_intel.get("malware_family", "Unknown")
            ti_html = f"""
                <p><strong>Provider:</strong> {provider}</p>
                <p><strong>Detections:</strong> {detections} / {total}</p>
                <p><strong>Malware Family:</strong> {family}</p>
            """
        else:
            ti_html = "<p>Threat intelligence data not available for this analysis.</p>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XMalGuard Analysis Report</title>
    {css}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XMalGuard Analysis Report</h1>
            <p>Analysis ID: {analysis_data.get('analysis_id', 'N/A')}</p>
            <p>Date: {analysis_data.get('timestamp', 'N/A')}</p>
        </div>
        
        <div class="section">
            <h2>File Information</h2>
            <table>
                <tbody>
                    <tr><th>Filename</th><td>{analysis_data.get('filename', 'N/A')}</td></tr>
                    <tr><th>File Size</th><td>{file_info.get('file_size', 'N/A')} bytes</td></tr>
                    <tr><th>SHA-256</th><td>{file_info.get('hashes', {}).get('sha256', 'N/A')}</td></tr>
                    <tr><th>SHA-1</th><td>{file_info.get('hashes', {}).get('sha1', 'N/A')}</td></tr>
                    <tr><th>MD5</th><td>{file_info.get('hashes', {}).get('md5', 'N/A')}</td></tr>
                    <tr><th>Architecture</th><td>{file_info.get('architecture', 'N/A')}</td></tr>
                    <tr><th>Subsystem</th><td>{file_info.get('subsystem', 'N/A')}</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Malware Prediction</h2>
            <p>
                <span class="badge {pred_badge_class}">{pred_label}</span>
                <strong style="margin-left: 15px;">Confidence:</strong> {pred_conf:.2f}%
            </p>
            <p>Malicious Probability: {prediction.get('malicious_probability', 0.0) * 100:.2f}% | Benign Probability: {prediction.get('benign_probability', 0.0) * 100:.2f}%</p>
        </div>

        <div class="section">
            <h2>Risk Assessment</h2>
            <p>
                <strong>Risk Score:</strong> {risk_score:.1f} / 100 
                <span class="badge" style="background-color: {risk_color}; margin-left: 10px;">{risk_level} RISK</span>
            </p>
            <h3>Score Breakdown</h3>
            <table>
                <thead><tr><th>Component</th><th>Score</th></tr></thead>
                <tbody>{breakdown_html}</tbody>
            </table>
            <h3>Contributing Factors</h3>
            {factors_html}
            <h3>Recommendation</h3>
            <p>{risk_data.get('recommendation', 'N/A')}</p>
        </div>

        <div class="section">
            <h2>Explainable AI (SHAP Contributions)</h2>
            <p>Features driving the machine learning model's prediction. Red bars (positive) push towards malicious, blue bars (negative) push towards benign.</p>
            {shap_html}
        </div>

        <div class="section">
            <h2>Threat Intelligence</h2>
            {ti_html}
        </div>

        <div class="disclaimer">
            This report is generated by XMalGuard for educational and research purposes. Results should be validated through additional analysis. This tool performs static analysis only and does not execute files.
        </div>
    </div>
</body>
</html>
        """
        return html_content
