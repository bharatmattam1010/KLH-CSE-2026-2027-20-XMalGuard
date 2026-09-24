import requests
import tarfile
import os
import sys

url = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
filename = "ember_dataset_2018.tar.bz2"
extract_dir = "EMBER2018_Dataset"

print("Starting download of EMBER 2018 dataset (1.6 GB)...")
try:
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(filename, 'wb') as f:
            downloaded = 0
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                # Print progress every ~100MB to avoid log spam
                if downloaded % (1024 * 1024 * 100) < 8192:
                    print(f"Downloaded: {downloaded / (1024*1024):.0f} MB")
                    
    print("\nDownload complete! Extracting the .tar.bz2 archive (this may take a few minutes)...")
    with tarfile.open(filename, "r:bz2") as tar:
        tar.extractall(path=extract_dir)
        
    print(f"Extraction complete! The dataset files (.jsonl) are now located in the {extract_dir} folder.")
    
    # Cleanup the 1.6GB archive
    os.remove(filename)
    print("Cleaned up the compressed archive.")
    
except Exception as e:
    print(f"An error occurred: {e}")
