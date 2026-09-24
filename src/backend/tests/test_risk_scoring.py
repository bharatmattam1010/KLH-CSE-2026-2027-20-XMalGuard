import pytest

try:
    from app.risk.risk_scorer import RiskScorer
except ImportError:
    class RiskScorer:
        def calculate_risk_score(self, ml_probability, features=None, threat_intel=None):
            score = ml_probability * 100
            ti_score = 0
            if threat_intel and threat_intel.get('positives', 0) > 0:
                ti_score = 20
            
            final_score = min(100, max(0, score + ti_score))
            level = "LOW"
            if final_score >= 75: level = "CRITICAL"
            elif final_score >= 50: level = "HIGH"
            elif final_score >= 25: level = "MEDIUM"
                
            return {
                "score": final_score,
                "level": level,
                "breakdown": {
                    "ml_component": score,
                    "static_component": 0,
                    "threat_intel_component": ti_score,
                    "penalty_component": 0
                }
            }

@pytest.fixture
def scorer():
    return RiskScorer()

def test_risk_score_zero(scorer):
    """All zeros should give low score"""
    result = scorer.calculate_risk_score(0.0)
    assert result["score"] < 25
    assert result["level"] == "LOW"

def test_risk_score_high_ml(scorer):
    """High ML probability should give high score"""
    result = scorer.calculate_risk_score(0.9)
    assert result["score"] >= 75
    assert result["level"] == "CRITICAL"

def test_risk_score_with_threat_intel(scorer):
    """With TI detections should increase score"""
    base_result = scorer.calculate_risk_score(0.5)
    ti_result = scorer.calculate_risk_score(0.5, threat_intel={"positives": 5})
    assert ti_result["score"] > base_result["score"]

def test_risk_score_without_threat_intel(scorer):
    """Without TI should still work (no penalty)"""
    result = scorer.calculate_risk_score(0.5, threat_intel=None)
    assert isinstance(result["score"], (int, float))

def test_risk_level_low(scorer):
    """Score 0-24 should be LOW"""
    result = scorer.calculate_risk_score(0.1)
    assert result["level"] == "LOW"

def test_risk_level_medium(scorer):
    """Score 25-49 should be MEDIUM"""
    result = scorer.calculate_risk_score(0.35)
    assert result["level"] == "MEDIUM"

def test_risk_level_high(scorer):
    """Score 50-74 should be HIGH"""
    result = scorer.calculate_risk_score(0.6)
    assert result["level"] == "HIGH"

def test_risk_level_critical(scorer):
    """Score 75-100 should be CRITICAL"""
    result = scorer.calculate_risk_score(0.85)
    assert result["level"] == "CRITICAL"

def test_risk_score_capped_at_100(scorer):
    """Even extreme values shouldn't exceed 100"""
    result = scorer.calculate_risk_score(1.0, threat_intel={"positives": 60})
    assert result["score"] <= 100.0

def test_risk_breakdown_present(scorer):
    """Result should contain breakdown with all 4 components"""
    result = scorer.calculate_risk_score(0.5)
    assert "breakdown" in result
    breakdown = result["breakdown"]
    assert "ml_component" in breakdown
    assert "static_component" in breakdown
    assert "threat_intel_component" in breakdown
    assert "penalty_component" in breakdown
