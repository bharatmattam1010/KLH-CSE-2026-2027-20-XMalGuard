from typing import Dict, Any
from .base_provider import ThreatIntelProvider

class MockThreatIntelProvider(ThreatIntelProvider):
    """Mock threat intelligence provider for development and demonstrations."""

    def __init__(self):
        """Initialize the mock provider with some known test hashes."""
        self.mock_data = {
            # SIMULATED MALWARE TEST FILE
            "47d0d60a5a6c5e7f841eed0dd13cd8fb0105095f4d1ce4272d666e944d09e7e4": {
                'available': True,
                'provider': 'MockThreatIntel (Demo)',
                'is_mock': True,
                'disclaimer': 'This is simulated threat intelligence data for demonstration purposes only.',
                'detections': 68,
                'total_engines': 71,
                'detection_rate': 0.957,
                'malware_family': 'Ransom.WannaCry.Gen',
                'malware_category': 'ransomware',
                'reputation_score': -100,
                'last_analysis_date': '2024-03-15T09:12:00Z',
                'engine_results': [
                    {"engine": "MockAV1", "detected": True, "result": "Ransom.WannaCry"},
                    {"engine": "MockAV2", "detected": True, "result": "Win32/Filecoder"}
                ],
                'tags': ['ransomware', 'packed', 'upx', 'malicious'],
                'error': None
            },
            # BENIGN CALCULATOR TEST FILE
            "621ba3934afc45c35a4ee16386f4da30119f39fa243e8dc8fef3491a76f829d8": {
                'available': True,
                'provider': 'MockThreatIntel (Demo)',
                'is_mock': True,
                'disclaimer': 'This is simulated threat intelligence data for demonstration purposes only.',
                'detections': 0,
                'total_engines': 71,
                'detection_rate': 0.0,
                'malware_family': 'None',
                'malware_category': 'clean',
                'reputation_score': 100,
                'last_analysis_date': '2024-02-10T12:00:00Z',
                'engine_results': [],
                'tags': ['clean', 'trusted', 'microsoft'],
                'error': None
            },
            # Dummy hash for demonstration - high detection
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
                'available': True,
                'provider': 'MockThreatIntel (Demo)',
                'is_mock': True,
                'disclaimer': 'This is simulated threat intelligence data for demonstration purposes only. It does not represent real malware analysis results.',
                'detections': 45,
                'total_engines': 70,
                'detection_rate': 0.643,
                'malware_family': 'Trojan.GenericKD',
                'malware_category': 'trojan',
                'reputation_score': -85,
                'last_analysis_date': '2024-01-15T10:30:00Z',
                'engine_results': [
                    {"engine": "MockAV1", "detected": True, "result": "Trojan.GenericKD"},
                    {"engine": "MockAV2", "detected": True, "result": "Win32/Trojan"}
                ],
                'tags': ['trojan', 'packed', 'suspicious-entropy'],
                'error': None
            },
            # Low detection example
            "8d14b4344cd35b80a256ab8d0d5bba8f074ef999bb333423cb118a804ce19a6b": {
                'available': True,
                'provider': 'MockThreatIntel (Demo)',
                'is_mock': True,
                'disclaimer': 'This is simulated threat intelligence data for demonstration purposes only. It does not represent real malware analysis results.',
                'detections': 2,
                'total_engines': 70,
                'detection_rate': 0.028,
                'malware_family': 'Adware.Win32',
                'malware_category': 'adware',
                'reputation_score': -5,
                'last_analysis_date': '2024-02-10T12:00:00Z',
                'engine_results': [
                    {"engine": "MockAV1", "detected": False, "result": None},
                    {"engine": "MockAV3", "detected": True, "result": "Adware.Win32"}
                ],
                'tags': ['adware', 'pup'],
                'error': None
            }
        }

    def lookup(self, file_hash: str, hash_type: str = 'sha256') -> Dict[str, Any]:
        """Look up a file hash in the mock data or generate a deterministic mock report."""
        import random
        
        # Check hardcoded first
        result = self.mock_data.get(file_hash.lower())
        if result:
            return result
            
        # Generate deterministic mock data for ANY other hash so the UI always has data to show
        # Seed random with the hash string so the same file always gets the same mock TI result
        try:
            random.seed(int(file_hash[:8], 16))
        except:
            random.seed(file_hash)
            
        is_malicious_mock = random.random() > 0.7  # 30% chance to be flagged in mock intel
        detections = random.randint(10, 55) if is_malicious_mock else 0
        total = 70
        
        return {
            'available': True,
            'provider': 'MockThreatIntel (Demo)',
            'is_mock': True,
            'disclaimer': 'This is simulated threat intelligence data for demonstration purposes only.',
            'detections': detections,
            'total_engines': total,
            'detection_rate': detections / total,
            'malware_family': 'Trojan.Generic' if is_malicious_mock else 'Unknown',
            'malware_category': 'trojan' if is_malicious_mock else 'clean',
            'reputation_score': -80 if is_malicious_mock else 100,
            'last_analysis_date': '2024-03-20T10:30:00Z',
            'engine_results': [],
            'tags': ['trojan', 'suspicious'] if is_malicious_mock else ['clean'],
            'error': None
        }

    def is_available(self) -> bool:
        """Check if the provider is available."""
        return True
