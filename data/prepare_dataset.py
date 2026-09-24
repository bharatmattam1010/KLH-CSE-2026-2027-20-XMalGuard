import os
import argparse
import logging
import json
import pandas as pd
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

REQUIRED_COLUMNS = [
    "machine_type", "number_of_sections", "timestamp", "characteristics", "entry_point", 
    "image_base", "subsystem", "dll_characteristics", "size_of_image", "size_of_headers", 
    "section_mean_entropy", "section_max_entropy", "section_min_entropy", "section_mean_virtual_size", 
    "section_mean_raw_size", "executable_sections", "writable_sections", "high_entropy_sections", 
    "virtual_raw_size_ratio", "num_imported_dlls", "num_imported_functions", "suspicious_import_count", 
    "has_debug_imports", "has_network_imports", "has_crypto_imports", "has_process_imports", 
    "has_registry_imports", "num_exports", "file_size", "file_entropy", "printable_string_count", 
    "avg_string_length", "suspicious_string_count", "url_count", "has_upx_signature", "label"
]

def prepare_dataset(input_csv: str, output_dir: str):
    """Load, validate, clean, and split the dataset."""
    logging.info(f"Loading dataset from {input_csv}...")
    try:
        df = pd.read_csv(input_csv)
    except Exception as e:
        logging.error(f"Failed to load CSV: {e}")
        return

    # Validate columns
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_cols:
        logging.error(f"Dataset is missing required columns: {missing_cols}")
        return
        
    logging.info(f"Initial shape: {df.shape}")
    logging.info(f"Initial label distribution:\n{df['label'].value_counts()}")
    
    # Handle missing values
    # Drop rows with > 50% missing values
    threshold = int(0.5 * len(df.columns))
    df = df.dropna(thresh=threshold)
    
    # Fill remaining missing with median
    df = df.fillna(df.median())
    
    # Remove duplicates
    df = df.drop_duplicates()
    logging.info(f"Shape after cleaning: {df.shape}")
    
    X = df.drop(columns=['label'])
    y = df['label']
    
    # Stratified split: 70% train, 15% val, 15% test
    # First split into 70% train and 30% temp
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    
    # Split temp into 50% val and 50% test (15% overall each)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Save splits
    train_df = pd.concat([X_train, y_train], axis=1)
    val_df = pd.concat([X_val, y_val], axis=1)
    test_df = pd.concat([X_test, y_test], axis=1)
    
    train_df.to_csv(os.path.join(output_dir, "train.csv"), index=False)
    val_df.to_csv(os.path.join(output_dir, "val.csv"), index=False)
    test_df.to_csv(os.path.join(output_dir, "test.csv"), index=False)
    
    # Split Info
    split_info = {
        "train": {"size": len(train_df), "label_0": int((y_train == 0).sum()), "label_1": int((y_train == 1).sum())},
        "val": {"size": len(val_df), "label_0": int((y_val == 0).sum()), "label_1": int((y_val == 1).sum())},
        "test": {"size": len(test_df), "label_0": int((y_test == 0).sum()), "label_1": int((y_test == 1).sum())}
    }
    
    with open(os.path.join(output_dir, "split_info.json"), "w") as f:
        json.dump(split_info, f, indent=4)
        
    logging.info("Dataset split successfully.")
    logging.info(f"Train size: {len(train_df)}")
    logging.info(f"Validation size: {len(val_df)}")
    logging.info(f"Test size: {len(test_df)}")
    logging.info(f"Splits saved to {output_dir}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Prepare dataset for XMalGuard")
    parser.add_argument("--input", type=str, default="data/synthetic_dataset.csv", help="Path to input CSV file")
    
    args = parser.parse_args()
    
    # Compute relative base dir
    base_dir = os.path.join(os.path.dirname(__file__), "..")
    input_path = args.input if os.path.isabs(args.input) else os.path.join(base_dir, args.input)
    out_dir = os.path.join(base_dir, "data", "processed")
    
    prepare_dataset(input_path, out_dir)
