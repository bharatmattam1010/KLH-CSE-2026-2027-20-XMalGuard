import os
import shutil
import zipfile

# Source files
src_benign = "test_samples/benign_calculator.exe"
src_malware = "test_samples/simulated_malware.exe"

# Target directory
target_dir = "ember_test_dataset"
os.makedirs(target_dir, exist_ok=True)

# Generate 50 benign and 50 malicious files to simulate a dataset batch
print("Generating 100 sample executables for the dataset zip...")
for i in range(1, 51):
    shutil.copy(src_benign, os.path.join(target_dir, f"sample_benign_{i}.exe"))
    shutil.copy(src_malware, os.path.join(target_dir, f"sample_malware_{i}.exe"))

# Zip them up
zip_filename = "ember_dataset.zip"
print(f"Compressing into {zip_filename}...")
with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, _, files in os.walk(target_dir):
        for file in files:
            zipf.write(os.path.join(root, file), arcname=file)

# Cleanup
shutil.rmtree(target_dir)
print(f"Dataset successfully created at: {os.path.abspath(zip_filename)}")
