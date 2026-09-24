import logging
import os
import pefile

from .entropy import calculate_file_entropy
from .hashing import calculate_hashes
from .imports import analyze_imports
from .sections import analyze_sections
from .strings import analyze_strings

logger = logging.getLogger(__name__)

class PEFeatureExtractor:
    """
    Orchestrator class for extracting static ML features from PE files.
    """

    def extract_features(self, file_path: str) -> dict:
        """
        Parses a PE file and extracts all ML features and display information.
        
        Args:
            file_path (str): The absolute path to the PE file.
            
        Returns:
            dict: Combined dictionary of ml_features, display_info, and raw feature metrics.
            
        Raises:
            ValueError: If the PE file is invalid or cannot be parsed.
        """
        if not os.path.exists(file_path):
            raise ValueError(f"File not found: {file_path}")
            
        file_size = os.path.getsize(file_path)
        
        try:
            # Using fast_load=True is generally safer for malware, but we need directories loaded.
            pe = pefile.PE(file_path, fast_load=False)
        except pefile.PEFormatError as e:
            raise ValueError(f"Invalid PE file: {e}")
        except Exception as e:
            raise ValueError(f"Error parsing PE file: {e}")
            
        # 1. Base / File Information
        filename = os.path.basename(file_path)
        file_entropy = calculate_file_entropy(file_path)
        hashes = calculate_hashes(file_path)
        
        # 2. Extract specific PE Headers
        try:
            machine_type = pe.FILE_HEADER.Machine
            number_of_sections_header = pe.FILE_HEADER.NumberOfSections
            timestamp = pe.FILE_HEADER.TimeDateStamp
            characteristics = pe.FILE_HEADER.Characteristics
            
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
            size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        except AttributeError as e:
            logger.error(f"Missing header attribute: {e}")
            # Fallback defaults for malformed headers
            machine_type = 0
            number_of_sections_header = 0
            timestamp = 0
            characteristics = 0
            entry_point = 0
            image_base = 0
            subsystem = 0
            dll_characteristics = 0
            size_of_image = 0
            size_of_headers = 0

        # Exports
        num_exports = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            
        # UPX check
        has_upx_signature = 0
        if hasattr(pe, 'sections'):
            for section in pe.sections:
                try:
                    name = section.Name.decode('utf-8', 'ignore')
                    if name.startswith('UPX'):
                        has_upx_signature = 1
                        break
                except Exception:
                    pass

        # 3. Call Sub-Extractors
        sections_info = analyze_sections(pe)
        imports_info = analyze_imports(pe)
        strings_info = analyze_strings(file_path)
        
        # Clean up PE parser memory
        pe.close()

        # 4. Construct Output
        ml_features = {
            'machine_type': machine_type,
            'number_of_sections': number_of_sections_header,
            'timestamp': timestamp,
            'characteristics': characteristics,
            'entry_point': entry_point,
            'image_base': image_base,
            'subsystem': subsystem,
            'dll_characteristics': dll_characteristics,
            'size_of_image': size_of_image,
            'size_of_headers': size_of_headers,
            'section_mean_entropy': sections_info.get('section_mean_entropy', 0.0),
            'section_max_entropy': sections_info.get('section_max_entropy', 0.0),
            'section_min_entropy': sections_info.get('section_min_entropy', 0.0),
            'section_mean_virtual_size': sections_info.get('section_mean_virtual_size', 0.0),
            'section_mean_raw_size': sections_info.get('section_mean_raw_size', 0.0),
            'executable_sections': sections_info.get('executable_sections', 0),
            'writable_sections': sections_info.get('writable_sections', 0),
            'high_entropy_sections': sections_info.get('high_entropy_sections', 0),
            'virtual_raw_size_ratio': sections_info.get('virtual_raw_size_ratio', 0.0),
            'num_imported_dlls': imports_info.get('num_imported_dlls', 0),
            'num_imported_functions': imports_info.get('num_imported_functions', 0),
            'suspicious_import_count': imports_info.get('suspicious_import_count', 0),
            'has_debug_imports': imports_info.get('has_debug_imports', 0),
            'has_network_imports': imports_info.get('has_network_imports', 0),
            'has_crypto_imports': imports_info.get('has_crypto_imports', 0),
            'has_process_imports': imports_info.get('has_process_imports', 0),
            'has_registry_imports': imports_info.get('has_registry_imports', 0),
            'num_exports': num_exports,
            'file_size': file_size,
            'file_entropy': file_entropy,
            'printable_string_count': strings_info.get('printable_string_count', 0),
            'avg_string_length': strings_info.get('avg_string_length', 0.0),
            'suspicious_string_count': strings_info.get('suspicious_string_count', 0),
            'url_count': strings_info.get('url_count', 0),
            'has_upx_signature': has_upx_signature
        }

        display_info = {
            'filename': filename,
            'file_size': file_size,
            'hashes': hashes,
            'section_details': sections_info.get('section_details', []),
            'imported_dlls': imports_info.get('imported_dlls', []),
            'suspicious_apis_found': imports_info.get('suspicious_apis_found', []),
            'suspicious_strings_found': strings_info.get('suspicious_strings_found', [])
        }

        result = {
            'ml_features': ml_features,
            'display_info': display_info,
            'filename': filename,
            'file_size': file_size
        }
        # Flat integration
        result.update(ml_features)
        result.update(display_info)
        
        return result

    @staticmethod
    def get_ml_feature_names() -> list[str]:
        """
        Returns the ordered list of 35 feature names required for the ML model.
        
        Returns:
            list[str]: Ordered feature names.
        """
        return [
            'machine_type', 'number_of_sections', 'timestamp', 'characteristics',
            'entry_point', 'image_base', 'subsystem', 'dll_characteristics',
            'size_of_image', 'size_of_headers', 'section_mean_entropy',
            'section_max_entropy', 'section_min_entropy', 'section_mean_virtual_size',
            'section_mean_raw_size', 'executable_sections', 'writable_sections',
            'high_entropy_sections', 'virtual_raw_size_ratio', 'num_imported_dlls',
            'num_imported_functions', 'suspicious_import_count', 'has_debug_imports',
            'has_network_imports', 'has_crypto_imports', 'has_process_imports',
            'has_registry_imports', 'num_exports', 'file_size', 'file_entropy',
            'printable_string_count', 'avg_string_length', 'suspicious_string_count',
            'url_count', 'has_upx_signature'
        ]
