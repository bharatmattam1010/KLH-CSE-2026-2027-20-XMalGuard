from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""
    
    @abstractmethod
    def lookup(self, file_hash: str, hash_type: str = 'sha256') -> Dict[str, Any]:
        """Look up a file hash in the threat intelligence source.
        
        Args:
            file_hash: The hash value to look up.
            hash_type: Type of hash ('md5', 'sha1', 'sha256').
            
        Returns:
            dict with keys:
            - available: bool (whether TI data was found)
            - provider: str (name of the provider)
            - detections: int (number of engines detecting as malicious)
            - total_engines: int (total number of engines)
            - detection_rate: float (detections/total_engines)
            - malware_family: str or None
            - malware_category: str or None  
            - reputation_score: int or None
            - last_analysis_date: str or None
            - engine_results: list[dict] (individual engine results, limited)
            - tags: list[str]
            - error: str or None
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is configured and available."""
        pass
    
    def get_provider_name(self) -> str:
        """Return the provider name."""
        return self.__class__.__name__
