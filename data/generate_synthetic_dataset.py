import os
import logging
import numpy as np
import pandas as pd

# SYNTHETIC DATASET — FOR DEVELOPMENT AND TESTING ONLY
# This dataset contains synthetic PE feature vectors. It does NOT contain real malware data.

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

FEATURE_COLUMNS = [
    "machine_type", "number_of_sections", "timestamp", "characteristics", "entry_point", 
    "image_base", "subsystem", "dll_characteristics", "size_of_image", "size_of_headers", 
    "section_mean_entropy", "section_max_entropy", "section_min_entropy", "section_mean_virtual_size", 
    "section_mean_raw_size", "executable_sections", "writable_sections", "high_entropy_sections", 
    "virtual_raw_size_ratio", "num_imported_dlls", "num_imported_functions", "suspicious_import_count", 
    "has_debug_imports", "has_network_imports", "has_crypto_imports", "has_process_imports", 
    "has_registry_imports", "num_exports", "file_size", "file_entropy", "printable_string_count", 
    "avg_string_length", "suspicious_string_count", "url_count", "has_upx_signature"
]

def generate_synthetic_data(n_samples: int, seed: int = 42) -> pd.DataFrame:
    """Generate a synthetic PE feature dataset for development and testing."""
    np.random.seed(seed)
    
    n_benign = int(n_samples * 0.6) # 3000
    n_malicious = n_samples - n_benign # 2000
    
    data = []
    
    # Benign samples (Label = 0)
    for _ in range(n_benign):
        row = {
            "machine_type": np.random.choice([332, 34404]), # x86 or x64
            "number_of_sections": int(np.random.normal(5, 1)),
            "timestamp": int(np.random.uniform(1e9, 1.7e9)),
            "characteristics": int(np.random.uniform(258, 33167)),
            "entry_point": int(np.random.uniform(4096, 500000)),
            "image_base": int(np.random.choice([4194304, 536870912])),
            "subsystem": np.random.choice([2, 3]), # GUI or CUI
            "dll_characteristics": int(np.random.uniform(0, 33000)),
            "size_of_image": int(np.random.uniform(50000, 2000000)),
            "size_of_headers": 1024,
            "section_mean_entropy": np.random.normal(4.5, 0.5),
            "section_max_entropy": np.random.normal(5.5, 0.5),
            "section_min_entropy": np.random.normal(1.0, 0.5),
            "section_mean_virtual_size": np.random.normal(50000, 10000),
            "section_mean_raw_size": np.random.normal(50000, 10000),
            "executable_sections": int(np.random.normal(1, 0.5)),
            "writable_sections": int(np.random.normal(1, 0.5)),
            "high_entropy_sections": int(np.random.normal(0.5, 0.5)),
            "virtual_raw_size_ratio": np.random.normal(1.0, 0.1),
            "num_imported_dlls": int(np.random.normal(5, 2)),
            "num_imported_functions": int(np.random.normal(100, 50)),
            "suspicious_import_count": int(np.abs(np.random.normal(1, 1))),
            "has_debug_imports": int(np.random.rand() > 0.9),
            "has_network_imports": int(np.random.rand() > 0.5),
            "has_crypto_imports": int(np.random.rand() > 0.8),
            "has_process_imports": int(np.random.rand() > 0.7),
            "has_registry_imports": int(np.random.rand() > 0.6),
            "num_exports": int(np.abs(np.random.normal(2, 5))),
            "file_size": int(np.random.normal(1000000, 500000)),
            "file_entropy": np.random.normal(4.5, 0.5),
            "printable_string_count": int(np.random.normal(1000, 200)),
            "avg_string_length": np.random.normal(15, 5),
            "suspicious_string_count": int(np.abs(np.random.normal(0.5, 1))),
            "url_count": int(np.abs(np.random.normal(1, 1))),
            "has_upx_signature": int(np.random.rand() > 0.95),
            "label": 0
        }
        data.append(row)
        
    # Malicious samples (Label = 1)
    for _ in range(n_malicious):
        row = {
            "machine_type": np.random.choice([332, 34404]),
            "number_of_sections": int(np.random.normal(4, 1.5)),
            "timestamp": int(np.random.uniform(0, 1.7e9)), # often spoofed
            "characteristics": int(np.random.uniform(258, 33167)),
            "entry_point": int(np.random.uniform(4096, 1000000)),
            "image_base": int(np.random.choice([4194304, 268435456])),
            "subsystem": np.random.choice([2, 3]),
            "dll_characteristics": int(np.random.uniform(0, 33000)),
            "size_of_image": int(np.random.uniform(50000, 5000000)),
            "size_of_headers": 1024,
            "section_mean_entropy": np.random.normal(6.5, 0.8), # higher entropy
            "section_max_entropy": np.random.normal(7.5, 0.4),
            "section_min_entropy": np.random.normal(2.0, 1.0),
            "section_mean_virtual_size": np.random.normal(100000, 50000),
            "section_mean_raw_size": np.random.normal(60000, 30000),
            "executable_sections": int(np.random.normal(1.5, 0.8)),
            "writable_sections": int(np.random.normal(2.5, 1.0)), # higher writable sections
            "high_entropy_sections": int(np.random.normal(2, 1)),
            "virtual_raw_size_ratio": np.random.normal(1.5, 0.5), # higher virtual size ratio
            "num_imported_dlls": int(np.random.normal(3, 2)),
            "num_imported_functions": int(np.random.normal(50, 40)),
            "suspicious_import_count": int(np.abs(np.random.normal(5, 2))), # more suspicious imports
            "has_debug_imports": int(np.random.rand() > 0.6),
            "has_network_imports": int(np.random.rand() > 0.3),
            "has_crypto_imports": int(np.random.rand() > 0.4),
            "has_process_imports": int(np.random.rand() > 0.2),
            "has_registry_imports": int(np.random.rand() > 0.2),
            "num_exports": int(np.abs(np.random.normal(0, 2))),
            "file_size": int(np.random.normal(800000, 400000)),
            "file_entropy": np.random.normal(6.8, 0.7), # higher overall entropy
            "printable_string_count": int(np.random.normal(500, 300)),
            "avg_string_length": np.random.normal(25, 10),
            "suspicious_string_count": int(np.abs(np.random.normal(3, 1.5))), # more suspicious strings
            "url_count": int(np.abs(np.random.normal(3, 2))),
            "has_upx_signature": int(np.random.rand() > 0.5), # UPX packing common
            "label": 1
        }
        data.append(row)
        
    df = pd.DataFrame(data)
    
    # Clip specific values to ensure validity
    df['number_of_sections'] = df['number_of_sections'].clip(lower=1).astype(int)
    for col in df.columns:
        if 'count' in col or 'num_' in col or col.startswith('has_'):
            df[col] = df[col].clip(lower=0).astype(int)
    
    # Shuffle dataset
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    
    return df

if __name__ == '__main__':
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    OUTPUT_PATH = os.path.join(OUTPUT_DIR, "synthetic_dataset.csv")
    
    logging.info("Generating 5000 synthetic PE feature samples...")
    df = generate_synthetic_data(5000)
    
    df.to_csv(OUTPUT_PATH, index=False)
    
    logging.info(f"Dataset generated and saved to {OUTPUT_PATH}")
    logging.info(f"Shape: {df.shape}")
    logging.info(f"Label distribution:\n{df['label'].value_counts()}")
    logging.info("Summary Statistics for numerical features:")
    logging.info(f"\n{df.describe().T[['mean', 'std', 'min', 'max']]}")
