import sys
import os

sys.path.append(os.path.abspath('backend'))

from app.features.pe_extractor import PEFeatureExtractor
from app.models.predict import MalwarePredictor

try:
    predictor = MalwarePredictor(
        model_path=r"models\final_model.joblib",
        scaler_path=r"models\scaler.joblib",
        feature_names_path=r"models\feature_names.json"
    )
    
    extractor = PEFeatureExtractor()
    
    for f in ["test_samples/benign_calculator.exe", "test_samples/simulated_malware.exe"]:
        print(f"\nEvaluating: {f}")
        try:
            features = extractor.extract_features(f)
            pred = predictor.predict(features['ml_features'])
            print(f"Verdict: {pred['prediction']}")
            print(f"Confidence: {pred['confidence']*100:.2f}%")
        except Exception as ex:
            print(f"Error parsing file: {ex}")
except Exception as e:
    print(f"Init Error: {e}")
