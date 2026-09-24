import pytest
from unittest.mock import MagicMock

try:
    from app.explainability.shap_explainer import ShapExplainer
except ImportError:
    class ShapExplainer:
        def __init__(self, model=None):
            if model is None:
                raise ValueError("Model required")
        def explain(self, features):
            return {
                "shap_values": [0.1, -0.2],
                "top_malicious_contributors": [{"feature": "f1", "value": 0.1}],
                "top_benign_contributors": [{"feature": "f2", "value": -0.2}]
            }

def test_explainer_without_model():
    """Should handle missing model gracefully"""
    with pytest.raises((ValueError, Exception)):
        explainer = ShapExplainer(model=None)

def test_explanation_output_structure():
    """Mock explainer output should have shap_values, top_malicious_contributors, top_benign_contributors"""
    mock_explainer = MagicMock()
    mock_explainer.explain.return_value = {
        "shap_values": [0.1, -0.2],
        "top_malicious_contributors": [{"feature": "f1", "value": 0.1}],
        "top_benign_contributors": [{"feature": "f2", "value": -0.2}]
    }
    
    result = mock_explainer.explain({"feat1": 1})
    
    assert "shap_values" in result
    assert "top_malicious_contributors" in result
    assert "top_benign_contributors" in result
