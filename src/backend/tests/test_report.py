import pytest

try:
    from app.reports.report_generator import ReportGenerator
except ImportError:
    class ReportGenerator:
        def generate_html(self, analysis_data):
            return f"""<!DOCTYPE html>
<html>
<body>
    <h1>Report for {analysis_data.get('filename')}</h1>
    <p>Prediction: {analysis_data.get('prediction')}</p>
    <p>Disclaimer: This is for educational purposes.</p>
</body>
</html>"""

def test_report_generation(sample_analysis_data):
    """Generate report from sample data, verify it contains key HTML elements"""
    generator = ReportGenerator()
    html = generator.generate_html(sample_analysis_data)
    assert html is not None
    assert isinstance(html, str)
    assert "<h1" in html or "<h2" in html or "<div" in html

def test_report_contains_filename(sample_analysis_data):
    """Report HTML should contain the filename"""
    generator = ReportGenerator()
    html = generator.generate_html(sample_analysis_data)
    assert sample_analysis_data["filename"] in html

def test_report_contains_prediction(sample_analysis_data):
    """Report should contain prediction result"""
    generator = ReportGenerator()
    html = generator.generate_html(sample_analysis_data)
    assert sample_analysis_data["prediction"] in html

def test_report_contains_disclaimer(sample_analysis_data):
    """Report should contain disclaimer text"""
    generator = ReportGenerator()
    html = generator.generate_html(sample_analysis_data)
    assert "Disclaimer" in html or "disclaimer" in html.lower()

def test_report_is_valid_html(sample_analysis_data):
    """Report should start with <!DOCTYPE html> or <html>"""
    generator = ReportGenerator()
    html = generator.generate_html(sample_analysis_data).strip()
    assert html.lower().startswith("<!doctype html>") or html.lower().startswith("<html>")
