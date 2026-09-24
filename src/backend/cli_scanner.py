import os
import sys
import argparse
from datetime import datetime

# Add the current directory to the path so we can import the app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.features.pe_extractor import PEFeatureExtractor
from app.models.predict import MalwarePredictor
from app.explainability.shap_explainer import ShapExplainer
from app.risk.risk_scorer import RiskScorer

def generate_html_report(directory, results, output_file="system_scan_report.html"):
    """Generate a summary HTML report of the directory scan."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>XMalGuard System Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
            h1, h2 {{ color: #1a1a2e; }}
            .summary {{ display: flex; gap: 20px; margin-bottom: 20px; }}
            .card {{ padding: 15px; background: white; border-radius: 8px; border: 1px solid #ddd; flex: 1; text-align: center; }}
            .card.malicious {{ color: #dc3545; border-color: #dc3545; background: #fff0f0; }}
            .card.benign {{ color: #28a745; border-color: #28a745; background: #f0fff0; }}
            table {{ width: 100%; border-collapse: collapse; background: white; font-size: 0.9em; }}
            th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
            th {{ background: #1a1a2e; color: white; }}
            .row-malicious {{ background: #fff0f0; }}
            .row-benign {{ background: #f0fff0; }}
            .badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; font-weight: bold; }}
            .bg-red {{ background: #dc3545; }}
            .bg-green {{ background: #28a745; }}
            .expl {{ font-size: 0.85em; color: #555; }}
            .pos-expl {{ color: #dc3545; font-weight: bold; }}
            .neg-expl {{ color: #28a745; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>XMalGuard System Directory Scan</h1>
        <p><strong>Target Directory:</strong> {directory}</p>
        <p><strong>Scan Completed:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <div class="card">
                <h2>{len(results)}</h2>
                <p>Total Executables Scanned</p>
            </div>
            <div class="card malicious">
                <h2>{sum(1 for r in results if r['prediction'] == 'MALICIOUS')}</h2>
                <p>Malicious Threats Detected</p>
            </div>
            <div class="card benign">
                <h2>{sum(1 for r in results if r['prediction'] == 'BENIGN')}</h2>
                <p>Safe / Benign Files</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Prediction</th>
                    <th>Risk</th>
                    <th>Top Malicious Indicator (SHAP)</th>
                    <th>Top Benign Indicator (SHAP)</th>
                </tr>
            </thead>
            <tbody>
    """

    for r in results:
        row_class = "row-malicious" if r['prediction'] == 'MALICIOUS' else "row-benign"
        badge_class = "bg-red" if r['prediction'] == 'MALICIOUS' else "bg-green"
        html += f"""
                <tr class="{row_class}">
                    <td>
                        <strong>{r['filename']}</strong><br/>
                        <span style="font-size:0.75em; color:#777;">{r['filepath']}</span>
                    </td>
                    <td>
                        <span class="badge {badge_class}">{r['prediction']}</span><br/>
                        <span style="font-size:0.8em;">Conf: {r['confidence'] * 100:.1f}%</span>
                    </td>
                    <td>{r['risk_level']}</td>
                    <td class="pos-expl">{r['top_malicious']}</td>
                    <td class="neg-expl">{r['top_benign']}</td>
                </tr>
        """
        
    html += """
            </tbody>
        </table>
    </body>
    </html>
    """
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    return output_file

def scan_directory(directory):
    if not os.path.exists(directory):
        print(f"Error: Directory '{directory}' does not exist.")
        return

    print("Loading AI Models and XAI Explainers...")
    
    # NEW ARCHITECTURE PATHS
    m_path = os.path.join(os.getcwd(), "backend", "app", "models", "final_model.joblib")
    s_path = os.path.join(os.getcwd(), "backend", "app", "models", "scaler.joblib")
    f_path = os.path.join(os.getcwd(), "backend", "app", "models", "feature_names.json")
    
    predictor = MalwarePredictor(
        model_path=m_path,
        scaler_path=s_path,
        feature_names_path=f_path
    )
    if not predictor.is_loaded():
        print("Error: Models not loaded. Please run the training pipeline first.")
        return

    explainer = ShapExplainer(model_path=m_path, scaler_path=s_path, feature_names_path=f_path)
    scorer = RiskScorer()

    files_to_scan = []
    print(f"Searching for .exe and .dll files in {directory}...")
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.lower().endswith(('.exe', '.dll')):
                files_to_scan.append(os.path.join(root, f))

    if not files_to_scan:
        print("No PE files (.exe, .dll) found in the specified directory.")
        return

    print(f"\nFound {len(files_to_scan)} executable files. Starting static analysis scan...\n")
    
    results = []
    extractor = PEFeatureExtractor()
    for idx, filepath in enumerate(files_to_scan):
        try:
            # 1. Extract static features silently (no execution)
            extracted = extractor.extract_features(filepath)
            ml_features = extracted['ml_features']
            
            # 2. ML Prediction
            pred = predictor.predict(ml_features)
            
            # 3. Security Risk Scoring
            risk = scorer.calculate_risk_score(pred['malicious_probability'], ml_features)
            
            # 4. Explain (SHAP AI)
            exp = explainer.explain(ml_features)
            
            top_malicious = "None"
            top_benign = "None"
            
            if exp and 'shap_values' in exp:
                shap_vals = exp['shap_values'] # list of {'feature': name, 'value': val}
                if shap_vals:
                    # Positive values push towards Malicious
                    pos_vals = [x for x in shap_vals if x['value'] > 0]
                    # Negative values push towards Benign
                    neg_vals = [x for x in shap_vals if x['value'] < 0]
                    
                    if pos_vals:
                        pos_vals.sort(key=lambda x: x['value'], reverse=True)
                        top_malicious = f"{pos_vals[0]['feature']} (+{pos_vals[0]['value']:.2f})"
                        
                    if neg_vals:
                        neg_vals.sort(key=lambda x: x['value'])
                        top_benign = f"{neg_vals[0]['feature']} ({neg_vals[0]['value']:.2f})"

            is_mal = (pred.get('prediction') == 'malicious')
            res = {
                'filepath': filepath,
                'filename': os.path.basename(filepath),
                'prediction': 'MALICIOUS' if is_mal else 'BENIGN',
                'confidence': pred['confidence'],
                'risk_level': risk['risk_level'],
                'top_malicious': top_malicious,
                'top_benign': top_benign
            }
            results.append(res)
            
            # Progress print
            indicator = "[MALWARE]" if is_mal else "[SAFE]"
            print(f"[{idx+1}/{len(files_to_scan)}] {indicator} {res['prediction']:9} - {res['filename']}")
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[{idx+1}/{len(files_to_scan)}] [ERROR] reading {os.path.basename(filepath)}: {e}")

    print("\nScan complete!")
    report_path = os.path.join(os.getcwd(), "system_scan_report.html")
    generate_html_report(directory, results, report_path)
    print(f"Detailed Security Report saved to: {report_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XMalGuard Bulk System Scanner")
    parser.add_argument("directory", help="The directory path to scan for PE files")
    args = parser.parse_args()
    
    scan_directory(args.directory)
