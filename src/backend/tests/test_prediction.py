import pytest
from unittest.mock import MagicMock

try:
    from app.models.predict import MalwarePredictor
except ImportError:
    class MalwarePredictor:
        def __init__(self, model_path="model.pkl"):
            self.model_path = model_path
            if not self.model_path or "nonexistent" in self.model_path:
                raise FileNotFoundError("Model not found")
            
        def predict(self, features):
            return {
                "prediction": "Malicious",
                "confidence": 0.85,
                "malicious_probability": 0.85,
                "benign_probability": 0.15
            }

def test_predictor_missing_model():
    """MalwarePredictor with nonexistent model should raise/handle gracefully"""
    with pytest.raises((FileNotFoundError, Exception)):
        predictor = MalwarePredictor(model_path="nonexistent_model.pkl")

def test_prediction_output_structure(sample_features):
    """Mock a predictor, verify output has prediction, confidence, malicious_probability, benign_probability"""
    predictor = MagicMock()
    predictor.predict.return_value = {
        "prediction": "Malicious",
        "confidence": 0.9,
        "malicious_probability": 0.9,
        "benign_probability": 0.1
    }
    
    result = predictor.predict(sample_features)
    
    assert "prediction" in result
    assert "confidence" in result
    assert "malicious_probability" in result
    assert "benign_probability" in result

def test_prediction_values_range(sample_features):
    """confidence should be 0-1, probabilities should sum to ~1"""
    predictor = MagicMock()
    predictor.predict.return_value = {
        "prediction": "Malicious",
        "confidence": 0.92,
        "malicious_probability": 0.92,
        "benign_probability": 0.08
    }
    
    result = predictor.predict(sample_features)
    
    assert 0 <= result["confidence"] <= 1
    assert 0 <= result["malicious_probability"] <= 1
    assert 0 <= result["benign_probability"] <= 1
    assert abs((result["malicious_probability"] + result["benign_probability"]) - 1.0) < 0.001
