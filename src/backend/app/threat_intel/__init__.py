from .base_provider import ThreatIntelProvider

def get_threat_intel_provider() -> ThreatIntelProvider:
    """Factory function to get the appropriate threat intel provider."""
    try:
        from ..config import get_settings
        settings = get_settings()
        vt_api_key = getattr(settings, 'VT_API_KEY', None)
    except ImportError:
        vt_api_key = None

    if vt_api_key:
        from .virustotal_provider import VirusTotalProvider
        return VirusTotalProvider(vt_api_key)
    else:
        from .mock_provider import MockThreatIntelProvider
        return MockThreatIntelProvider()
