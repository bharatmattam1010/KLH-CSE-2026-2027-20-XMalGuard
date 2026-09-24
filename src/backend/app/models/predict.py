import os
import json
import logging
import joblib
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MalwarePredictor:
    """Service class for predicting malware from PE features."""
    
    def __init__(self, model_path: str, scaler_path: str, feature_names_path: str):
        self.model = None
        self.scaler = None
        self.feature_names = []
        self._load_artifacts(model_path, scaler_path, feature_names_path)

    def _load_artifacts(self, model_path: str, scaler_path: str, feature_names_path: str):
        try:
            if not all(os.path.exists(p) for p in [model_path, scaler_path, feature_names_path]):
                logging.warning("Prediction artifacts not found. Model not loaded.")
                return
                
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            
            with open(feature_names_path, 'r') as f:
                self.feature_names = json.load(f)
                
            logging.info("Malware predictor loaded successfully.")
        except Exception as e:
            logging.error(f"Failed to load models: {e}")

    def is_loaded(self) -> bool:
        """Check if the model and scaler are loaded and ready."""
        return self.model is not None and self.scaler is not None and len(self.feature_names) > 0

    def predict(self, features: dict) -> dict:
        """
        Predict whether a PE file is malicious based on its features.
        Missing features will be filled with 0.
        """
        if not self.is_loaded():
            raise RuntimeError("Model is not loaded.")
            
        # Align features with expected feature names
        ordered_features = []
        for feat in self.feature_names:
            ordered_features.append(features.get(feat, 0.0))
            
        # Convert to numpy array and shape for sklearn
        X = np.array(ordered_features).reshape(1, -1)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict
        pred = self.model.predict(X_scaled)[0]
        
        # Get probabilities if available
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_scaled)[0]
            prob_0 = float(probs[0])
            prob_1 = float(probs[1])
        else:
            prob_0 = 1.0 if pred == 0 else 0.0
            prob_1 = 1.0 if pred == 1 else 0.0
            
        confidence = max(prob_0, prob_1)
        
        return {
            "prediction": "malicious" if pred == 0 else "benign",
            "confidence": confidence,
            "malicious_probability": prob_0,
            "benign_probability": prob_1
        }
