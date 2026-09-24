import logging
from .entropy import calculate_entropy

logger = logging.getLogger(__name__)

# Characteristic flags
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

def analyze_sections(pe) -> dict:
    """
    Analyzes PE sections to extract features.
    
    Args:
        pe (pefile.PE): A parsed pefile.PE object.
        
    Returns:
        dict: A dictionary containing section analysis features.
    """
    features = {
        'number_of_sections': 0,
        'section_mean_entropy': 0.0,
        'section_max_entropy': 0.0,
        'section_min_entropy': 0.0,
        'section_mean_virtual_size': 0.0,
        'section_mean_raw_size': 0.0,
        'executable_sections': 0,
        'writable_sections': 0,
        'high_entropy_sections': 0,
        'virtual_raw_size_ratio': 0.0,
        'section_details': []
    }
    
    if not hasattr(pe, 'sections') or not pe.sections:
        return features
        
    try:
        num_sections = len(pe.sections)
        features['number_of_sections'] = num_sections
        
        entropies = []
        virtual_sizes = []
        raw_sizes = []
        
        for section in pe.sections:
            name = section.Name.decode('utf-8', 'ignore').rstrip('\\x00')
            entropy = calculate_entropy(section.get_data())
            vsize = section.Misc_VirtualSize
            rsize = section.SizeOfRawData
            chars = section.Characteristics
            
            entropies.append(entropy)
            virtual_sizes.append(vsize)
            raw_sizes.append(rsize)
            
            if chars & IMAGE_SCN_MEM_EXECUTE:
                features['executable_sections'] += 1
            if chars & IMAGE_SCN_MEM_WRITE:
                features['writable_sections'] += 1
            if entropy > 6.5:
                features['high_entropy_sections'] += 1
                
            features['section_details'].append({
                'name': name,
                'virtual_size': vsize,
                'raw_size': rsize,
                'entropy': entropy,
                'characteristics': chars
            })
            
        if entropies:
            features['section_mean_entropy'] = sum(entropies) / num_sections
            features['section_max_entropy'] = max(entropies)
            features['section_min_entropy'] = min(entropies)
            
        if virtual_sizes:
            mean_vsize = sum(virtual_sizes) / num_sections
            features['section_mean_virtual_size'] = mean_vsize
        else:
            mean_vsize = 0.0
            
        if raw_sizes:
            mean_rsize = sum(raw_sizes) / num_sections
            features['section_mean_raw_size'] = mean_rsize
        else:
            mean_rsize = 0.0
            
        if mean_rsize > 0:
            features['virtual_raw_size_ratio'] = mean_vsize / mean_rsize
        else:
            features['virtual_raw_size_ratio'] = 0.0
            
    except Exception as e:
        logger.error(f"Error analyzing sections: {e}")
        
    return features
