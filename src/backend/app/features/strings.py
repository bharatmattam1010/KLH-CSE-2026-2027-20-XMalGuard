import re
import logging
import os

logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = {
    'hack', 'exploit', 'payload', 'shellcode', 'inject', 'keylog',
    'rootkit', 'backdoor', 'trojan', 'ransom', 'encrypt', 'decrypt',
    'password', 'credential', 'bitcoin', 'wallet', 'miner', 'botnet',
    'c2', 'command', 'control', 'exfiltrate'
}

def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """
    Extracts printable ASCII strings from raw bytes.
    
    Args:
        data (bytes): The raw data to extract strings from.
        min_length (int): Minimum length of strings to extract.
        
    Returns:
        list[str]: Extracted strings.
    """
    if not data:
        return []
    
    pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
    matches = re.findall(pattern, data)
    return [match.decode('ascii', 'ignore') for match in matches]

def analyze_strings(file_path: str) -> dict:
    """
    Extracts and analyzes strings from a file.
    
    Args:
        file_path (str): The absolute path to the file.
        
    Returns:
        dict: A dictionary containing string analysis features.
    """
    features = {
        'printable_string_count': 0,
        'avg_string_length': 0.0,
        'suspicious_string_count': 0,
        'url_count': 0,
        'suspicious_strings_found': []
    }
    
    if not os.path.exists(file_path):
        logger.error(f"File not found for string analysis: {file_path}")
        return features
        
    try:
        # Read max 10MB to limit memory
        max_bytes = 10 * 1024 * 1024
        file_size = os.path.getsize(file_path)
        bytes_to_read = min(file_size, max_bytes)
        
        with open(file_path, 'rb') as f:
            data = f.read(bytes_to_read)
            
        strings = extract_strings(data)
        
        if not strings:
            return features
            
        features['printable_string_count'] = len(strings)
        features['avg_string_length'] = sum(len(s) for s in strings) / len(strings)
        
        suspicious_found = []
        url_pattern = re.compile(r'https?://', re.IGNORECASE)
        
        for s in strings:
            s_lower = s.lower()
            if url_pattern.search(s_lower):
                features['url_count'] += 1
                
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in s_lower:
                    features['suspicious_string_count'] += 1
                    suspicious_found.append(s)
                    break # avoid counting same string multiple times for different keywords
                    
        # Limit to first 20 for display
        features['suspicious_strings_found'] = suspicious_found[:20]
        
    except Exception as e:
        logger.error(f"Error analyzing strings for {file_path}: {e}")
        
    return features
