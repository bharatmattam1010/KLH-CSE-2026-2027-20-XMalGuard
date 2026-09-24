import httpx
import logging
from typing import Dict, Any
from .base_provider import ThreatIntelProvider

logger = logging.getLogger(__name__)

class VirusTotalProvider(ThreatIntelProvider):
    """Threat intelligence provider using the VirusTotal API v3."""

    def __init__(self, api_key: str):
        """Initialize the VirusTotal provider with an API key."""
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'

    def is_available(self) -> bool:
        """Check if the provider is configured and available."""
        return bool(self.api_key)

    def lookup(self, file_hash: str, hash_type: str = 'sha256') -> Dict[str, Any]:
        """Look up a file hash in VirusTotal."""
        if not self.is_available():
            return {
                'available': False,
                'provider': self.get_provider_name(),
                'error': 'API key not configured.'
            }

        url = f"{self.base_url}/files/{file_hash}"
        headers = {
            "x-apikey": self.api_key
        }

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(url, headers=headers)
                
                if response.status_code == 404:
                    return {
                        'available': False,
                        'provider': self.get_provider_name(),
                        'error': 'File hash not found in VirusTotal.'
                    }
                elif response.status_code == 429:
                    return {
                        'available': False,
                        'provider': self.get_provider_name(),
                        'error': 'Rate limit exceeded.'
                    }
                elif response.status_code == 401:
                    return {
                        'available': False,
                        'provider': self.get_provider_name(),
                        'error': 'Invalid API key.'
                    }
                
                response.raise_for_status()
                data = response.json().get('data', {}).get('attributes', {})
                
                stats = data.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                undetected = stats.get('undetected', 0)
                harmless = stats.get('harmless', 0)
                suspicious = stats.get('suspicious', 0)
                timeout = stats.get('timeout', 0)
                
                total_engines = malicious + undetected + harmless + suspicious + timeout
                detections = malicious + suspicious
                detection_rate = detections / total_engines if total_engines > 0 else 0.0
                
                pop_threat_class = data.get('popular_threat_classification', {})
                malware_family = pop_threat_class.get('popular_threat_category', [{}])[0].get('value') if pop_threat_class.get('popular_threat_category') else None
                malware_category = pop_threat_class.get('suggested_threat_label')
                reputation_score = data.get('reputation', None)
                last_analysis_date = str(data.get('last_analysis_date', ''))
                
                analysis_results = data.get('last_analysis_results', {})
                engine_results = []
                for engine, result in list(analysis_results.items())[:10]:
                    engine_results.append({
                        "engine": engine,
                        "detected": result.get('category') in ['malicious', 'suspicious'],
                        "result": result.get('result')
                    })

                tags = data.get('tags', [])
                
                return {
                    'available': True,
                    'provider': self.get_provider_name(),
                    'detections': detections,
                    'total_engines': total_engines,
                    'detection_rate': float(detection_rate),
                    'malware_family': malware_family,
                    'malware_category': malware_category,
                    'reputation_score': reputation_score,
                    'last_analysis_date': last_analysis_date,
                    'engine_results': engine_results,
                    'tags': tags,
                    'error': None
                }

        except httpx.RequestError as e:
            logger.error(f"HTTP Request failed: {e}")
            return {
                'available': False,
                'provider': self.get_provider_name(),
                'error': f'HTTP request error: {str(e)}'
            }
        except Exception as e:
            logger.error(f"Error analyzing VirusTotal response: {e}")
            return {
                'available': False,
                'provider': self.get_provider_name(),
                'error': f'An unexpected error occurred: {str(e)}'
            }
