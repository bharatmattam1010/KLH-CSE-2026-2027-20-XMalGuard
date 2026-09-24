import os
import subprocess

print("Downloading Datasets (Note: Requires Git LFS for HuggingFace)...")

# 1. EMBER 2024 HuggingFace
if not os.path.exists("EMBER2024_Dataset"):
    print("Attempting to clone EMBER2024 from HuggingFace...")
    try:
        subprocess.run(["git", "clone", "https://huggingface.co/datasets/Snaskti/EMBER2024", "EMBER2024_Dataset"])
    except Exception as e:
        print(f"Error cloning HuggingFace repo: {e}")

# 2. EMBER 2017/2018 (Zenodo alternative)
# The official Sorel-20M / Zenodo records are massive and require the official download scripts.
print("\nIMPORTANT: To download the massive Zenodo records (e.g. Sorel-20M or EMBER-2017),")
print("you must use the official scripts provided in the ember_2018_github_repo.zip you already downloaded.")
print("\nIf checkout failed during git clone, please ensure you have 'git lfs' installed on your system.")
