import math
import logging
import os

logger = logging.getLogger(__name__)

def calculate_entropy(data: bytes) -> float:
    """
    Calculates the Shannon entropy of raw bytes.
    
    Args:
        data (bytes): The raw data to analyze.
        
    Returns:
        float: The calculated entropy (between 0.0 and 8.0). Returns 0.0 for empty data.
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    
    # Calculate byte frequencies
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
        
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def calculate_file_entropy(file_path: str) -> float:
    """
    Reads a file and calculates its Shannon entropy.
    
    Args:
        file_path (str): The absolute path to the file.
        
    Returns:
        float: The calculated entropy.
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return 0.0
            
        with open(file_path, 'rb') as f:
            data = f.read()
        return calculate_entropy(data)
    except Exception as e:
        logger.error(f"Error calculating file entropy for {file_path}: {e}")
        return 0.0
