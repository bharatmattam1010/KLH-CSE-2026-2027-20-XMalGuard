import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ExplanationFormatter:
    """
    Formatter to convert raw SHAP values and model outputs into human-readable explanations.
    """
    
    # Mapping of feature names to human-readable descriptions
    FEATURE_DESCRIPTIONS = {
        'section_mean_entropy': 'Average entropy across PE sections (higher values suggest packed/encrypted content)',
        'suspicious_import_count': 'Number of Windows API imports commonly associated with potentially malicious behavior',
        'has_upx_signature': 'Presence of UPX packer signatures in section names',
        'file_entropy': 'Overall file entropy (randomness measure)',
        'SizeOfCode': 'Size of the code section in the executable',
        'SizeOfInitializedData': 'Size of the initialized data section',
        'SizeOfUninitializedData': 'Size of the uninitialized data section',
        'AddressOfEntryPoint': 'Memory address where the program begins execution',
        'BaseOfCode': 'Base address of the code section',
        'ImageBase': 'Preferred load address of the executable in memory',
        'SectionAlignment': 'Alignment of sections in memory',
        'FileAlignment': 'Alignment of sections in the file',
        'MajorOperatingSystemVersion': 'Minimum required major OS version',
        'MinorOperatingSystemVersion': 'Minimum required minor OS version',
        'MajorImageVersion': 'Major version number of the image',
        'MinorImageVersion': 'Minor version number of the image',
        'MajorSubsystemVersion': 'Major version of the required subsystem',
        'MinorSubsystemVersion': 'Minor version of the required subsystem',
        'SizeOfImage': 'Total size of the loaded image in memory',
        'SizeOfHeaders': 'Size of all PE headers combined',
        'CheckSum': 'PE checksum value (often 0 or invalid in malware)',
        'Subsystem': 'Target subsystem (e.g., Windows GUI, Windows CUI)',
        'DllCharacteristics': 'Flags indicating DLL properties and security features (e.g., ASLR, DEP)',
        'SizeOfStackReserve': 'Size of the stack reserved for the process',
        'SizeOfStackCommit': 'Size of the stack initially committed',
        'SizeOfHeapReserve': 'Size of the local heap space reserved',
        'SizeOfHeapCommit': 'Size of the local heap space committed',
        'LoaderFlags': 'Obsolete flags, usually 0 (non-zero is highly suspicious)',
        'NumberOfRvaAndSizes': 'Number of data directory entries',
        'SectionsNb': 'Number of sections in the PE file',
        'SectionsMeanEntropy': 'Mean entropy of all sections',
        'SectionsMinEntropy': 'Minimum entropy among all sections',
        'SectionsMaxEntropy': 'Maximum entropy among all sections',
        'SectionsMeanRawsize': 'Mean raw size of all sections',
        'SectionsMinRawsize': 'Minimum raw size among all sections',
        'SectionMaxRawsize': 'Maximum raw size among all sections',
        'SectionsMeanVirtualsize': 'Mean virtual size of all sections',
        'SectionsMinVirtualsize': 'Minimum virtual size among all sections',
        'SectionMaxVirtualsize': 'Maximum virtual size among all sections',
        'ImportsNbDLL': 'Number of imported DLLs',
        'ImportsNb': 'Total number of imported functions',
        'ImportsNbOrdinal': 'Number of imports by ordinal instead of name',
        'ExportNb': 'Number of exported functions',
        'ResourcesNb': 'Number of resources (icons, dialogs, etc.)',
        'ResourcesMeanEntropy': 'Mean entropy of resources',
        'ResourcesMinEntropy': 'Minimum entropy among resources',
        'ResourcesMaxEntropy': 'Maximum entropy among resources',
        'ResourcesMeanSize': 'Mean size of resources',
        'ResourcesMinSize': 'Minimum size among resources',
        'ResourcesMaxSize': 'Maximum size among resources',
        'LoadConfigurationSize': 'Size of the load configuration structure',
        'VersionInformationSize': 'Size of version information resource'
    }

    def __init__(self):
        """Initialize the formatter."""
        pass

    def format_explanation(self, shap_result: Dict[str, Any], prediction: str, confidence: float) -> Dict[str, Any]:
        """
        Format SHAP result into a human-readable explanation structure.

        Args:
            shap_result: The raw output from ShapExplainer.explain().
            prediction: The string prediction label (e.g., 'MALICIOUS', 'BENIGN').
            confidence: Float confidence score between 0.0 and 1.0 (or 0-100).

        Returns:
            Dictionary with formatted explanation fields.
        """
        # Normalize confidence to percentage
        if confidence <= 1.0:
            conf_percent = confidence * 100
        else:
            conf_percent = confidence
            
        try:
            # 1. Summary
            summary = (f"The model classified this file as {prediction.upper()} "
                       f"with {conf_percent:.1f}% confidence. "
                       f"The following features contributed most to this prediction:")
            
            # 2. Confidence Interpretation
            if conf_percent >= 90:
                confidence_interpretation = "Very high confidence"
            elif conf_percent >= 75:
                confidence_interpretation = "High confidence"
            elif conf_percent >= 60:
                confidence_interpretation = "Moderate confidence"
            else:
                confidence_interpretation = "Low confidence — consider additional analysis"

            # 3. Top Features Table
            top_features_table = []
            
            # Extract top 10 features from shap_result
            if 'shap_values' in shap_result:
                # Top 5 positive and Top 5 negative or just top 10 absolute
                # We'll use the pre-sorted top 10 absolute from shap_values
                sorted_vals = sorted(shap_result['shap_values'], key=lambda x: abs(x['value']), reverse=True)[:10]
                
                for item in sorted_vals:
                    feature = item['feature']
                    val = item['value']
                    
                    if val > 0:
                        direction = "toward malicious"
                    elif val < 0:
                        direction = "toward benign"
                    else:
                        direction = "neutral"
                        
                    desc = self.FEATURE_DESCRIPTIONS.get(feature, "Feature description not available.")
                    
                    top_features_table.append({
                        "feature": feature,
                        "contribution": float(val),
                        "direction": direction,
                        "description": desc
                    })

            # 4. Disclaimer
            disclaimer = (
                "Note: These features contributed to the model's statistical prediction. "
                "A high contribution does not prove malicious intent — it indicates the feature "
                "influenced the model's decision. Manual analysis is recommended for confirmation."
            )

            return {
                "summary": summary,
                "top_features_table": top_features_table,
                "feature_descriptions": self.FEATURE_DESCRIPTIONS,
                "disclaimer": disclaimer,
                "confidence_interpretation": confidence_interpretation
            }
            
        except Exception as e:
            logger.error(f"Error formatting explanation: {e}")
            return {
                "summary": f"Failed to format explanation: {str(e)}",
                "top_features_table": [],
                "feature_descriptions": self.FEATURE_DESCRIPTIONS,
                "disclaimer": "Explanation formatting failed.",
                "confidence_interpretation": "Unknown confidence"
            }
