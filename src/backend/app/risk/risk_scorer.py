import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class RiskScorer:
    """Calculates risk scores based on ML, static features, and threat intel."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the risk scorer with configurable weights and thresholds."""
        config = config or {}
        self.weights = config.get('weights', {
            'ml_score': 50,
            'static_indicators': 20,
            'threat_intel': 20,
            'other_indicators': 10
        })
        self.thresholds = config.get('thresholds', {
            'low_max': 24,
            'medium_max': 49,
            'high_max': 74
        })

    def _get_risk_level(self, score: float) -> str:
        """Map composite risk score to risk level."""
        if score <= self.thresholds['low_max']:
            return 'LOW'
        elif score <= self.thresholds['medium_max']:
            return 'MEDIUM'
        elif score <= self.thresholds['high_max']:
            return 'HIGH'
        else:
            return 'CRITICAL'

    def _get_recommendation(self, level: str) -> str:
        """Return recommendation based on risk level."""
        if level == 'LOW':
            return 'File appears to be low risk. Standard monitoring recommended.'
        elif level == 'MEDIUM':
            return 'File shows some suspicious characteristics. Further analysis recommended.'
        elif level == 'HIGH':
            return 'File shows significant indicators of malicious behavior. Detailed investigation recommended.'
        else:
            return 'File shows strong indicators of malicious behavior. Immediate investigation and containment recommended.'

    def calculate_risk_score(self, ml_probability: float, features: Dict[str, Any], threat_intel: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Calculate composite risk score.
        
        Args:
            ml_probability: Probability float returned by the ML model
            features: Dictionary containing extracted static features
            threat_intel: Threat intelligence data dictionary
            
        Returns:
            Dictionary with the detailed composite risk score.
        """
        try:
            # ML Score
            ml_score = min(ml_probability * self.weights['ml_score'], self.weights['ml_score'])
            
            # Static Indicators
            high_entropy = min((features.get('file_entropy', 0.0) / 8.0) * 5, 5.0)
            suspicious_imports = min(features.get('suspicious_import_count', 0) * 1.5, 5.0)
            has_packing = features.get('has_upx_signature', 0) * 3.0
            section_anomalies = min(features.get('high_entropy_sections', 0) * 2.0, 4.0)
            suspicious_strings = min(features.get('suspicious_string_count', 0), 3.0)
            static_score_raw = high_entropy + suspicious_imports + has_packing + section_anomalies + suspicious_strings
            static_score = min(static_score_raw, self.weights['static_indicators'])

            # Threat Intel
            ti_score = 0.0
            if threat_intel and threat_intel.get('available'):
                detection_rate = threat_intel.get('detection_rate', 0.0)
                ti_score = min(detection_rate * self.weights['threat_intel'], self.weights['threat_intel'])

            # Other Indicators
            network_imports = features.get('has_network_imports', 0) * 3.0
            crypto_imports = features.get('has_crypto_imports', 0) * 2.0
            process_imports = features.get('has_process_imports', 0) * 3.0
            debug_imports = features.get('has_debug_imports', 0) * 2.0
            other_score_raw = network_imports + crypto_imports + process_imports + debug_imports
            other_score = min(other_score_raw, self.weights['other_indicators'])

            # Total Calculation
            total_score = min(ml_score + static_score + ti_score + other_score, 100.0)
            
            # --- CYBER HEURISTIC ESCALATION ---
            # If a file is packed (UPX) AND has extremely high entropy (> 7.5),
            # this is a classic malware obfuscation technique. Escalate risk score.
            if features.get('has_upx_signature', 0) > 0 and features.get('file_entropy', 0.0) > 7.5:
                total_score = max(total_score, 76.0)

            risk_level = self._get_risk_level(total_score)
            
            # Contributing factors list
            contributing_factors = []
            if total_score >= 76.0 and features.get('has_upx_signature', 0) > 0:
                contributing_factors.append("Classic malware obfuscation detected (UPX + High Entropy)")
            if ml_score > (self.weights['ml_score'] / 2):
                contributing_factors.append("High machine learning threat probability")
            if ti_score > 0:
                contributing_factors.append("Detected by threat intelligence engines")
            if high_entropy > 3:
                contributing_factors.append("High file entropy (potential packing/encryption)")
            if suspicious_imports > 3:
                contributing_factors.append("Suspicious API imports detected")
            if has_packing > 0:
                contributing_factors.append("Known packer signature detected")
            if network_imports > 0 or crypto_imports > 0 or process_imports > 0 or debug_imports > 0:
                contributing_factors.append("Suspicious functional capabilities (network, crypto, etc.)")

            return {
                'total_score': float(total_score),
                'risk_level': risk_level,
                'breakdown': {
                    'ml_score': {'score': float(ml_score), 'max': self.weights['ml_score'], 'description': 'Machine Learning Probability Score'},
                    'static_indicators': {'score': float(static_score), 'max': self.weights['static_indicators'], 'description': 'Static PE Analysis Anomalies'},
                    'threat_intel': {'score': float(ti_score), 'max': self.weights['threat_intel'], 'description': 'Threat Intelligence Detections'},
                    'other_indicators': {'score': float(other_score), 'max': self.weights['other_indicators'], 'description': 'Suspicious Functional Capabilities'}
                },
                'contributing_factors': contributing_factors,
                'recommendation': self._get_recommendation(risk_level)
            }
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return {
                'total_score': 0.0,
                'risk_level': 'LOW',
                'breakdown': {},
                'contributing_factors': [],
                'recommendation': 'Error calculating risk score.',
                'error': str(e)
            }
