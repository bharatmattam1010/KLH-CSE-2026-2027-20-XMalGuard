import sys, os
sys.path.append(os.path.abspath('backend'))
from app.features.pe_extractor import PEFeatureExtractor
from app.models.predict import MalwarePredictor
from app.risk.risk_scorer import RiskScorer
import json

extractor = PEFeatureExtractor()
features = extractor.extract_features('test_samples/simulated_malware.exe')
ml_feats = features['ml_features']

predictor = MalwarePredictor(r"backend\models\final_model.joblib", r"backend\models\scaler.joblib", r"backend\models\feature_names.json")
pred = predictor.predict(ml_feats)

scorer = RiskScorer()
risk = scorer.calculate_risk_score(pred['malicious_probability'], ml_feats, None)
print(json.dumps(risk, indent=2))
