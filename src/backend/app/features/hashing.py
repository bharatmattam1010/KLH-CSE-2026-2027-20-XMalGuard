import hashlib
import logging
import os

logger = logging.getLogger(__name__)

def calculate_hashes(file_path: str) -> dict:
    """
    Calculates MD5, SHA-1, and SHA-256 hashes for a given file.
    
    Args:
        file_path (str): Absolute path to the file.
        
    Returns:
        dict: A dictionary containing 'md5', 'sha1', and 'sha256' string hashes.
    """
    hashes = {
        'md5': '',
        'sha1': '',
        'sha256': ''
    }
    
    if not os.path.exists(file_path):
        logger.error(f"File not found for hashing: {file_path}")
        return hashes

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            # Read in chunks of 8192 bytes for memory efficiency
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                
        hashes['md5'] = md5_hash.hexdigest().lower()
        hashes['sha1'] = sha1_hash.hexdigest().lower()
        hashes['sha256'] = sha256_hash.hexdigest().lower()
        
    except Exception as e:
        logger.error(f"Error calculating hashes for {file_path}: {e}")
        
    return hashes
