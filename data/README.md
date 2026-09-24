# XMalGuard Dataset Guidelines

This directory holds the raw, processed, and synthetic datasets utilized for training and validating the machine learning models in XMalGuard.

---

## 1. Safety & Ethical Notice

> **CRITICAL SAFETY REMINDER**:
> - Never execute or run live malware binaries.
> - All PE file feature extraction in XMalGuard is **STATIC ONLY**.
> - Datasets should strictly consist of pre-extracted numerical/categorical feature vectors, hashes, and labels—never weaponized payloads.

---

## 2. Dataset Requirements

XMalGuard accepts feature datasets in CSV format containing labeled static Portable Executable (PE) features.

### Expected Target Variable
- `label`: Binary classification target integer
  - `0`: Benign executable
  - `1`: Malicious executable

### Expected Feature Categories
A typical PE feature vector consists of:
- **General File Characteristics**:
  - `file_size`: Total size in bytes.
  - `virtual_size`: Sum of virtual sizes across sections.
  - `has_debug`: Flag indicating presence of debug directory (0 or 1).
  - `has_relocations`: Flag indicating relocation table presence.
  - `has_resources`: Flag indicating resource section presence.
  - `has_signature`: Flag indicating digital certificate presence.
  - `entropy`: Whole-file Shannon entropy (0.0 to 8.0).
- **Header Information**:
  - `machine`: Target architecture machine type code (e.g. `0x014c` for x86, `0x8664` for x64).
  - `number_of_sections`: Count of PE sections.
  - `timestamp`: Compilation timestamp from the COFF header.
  - `characteristics`: COFF file characteristics bitmask.
  - `subsystem`: Target subsystem ID (e.g. GUI, CUI).
  - `dll_characteristics`: DLL characteristics flags.
- **Section Attributes**:
  - Max section entropy, min section entropy, mean section entropy.
  - Size and permissions of executable sections (`.text`, `.data`, `.rsrc`, etc.).
  - Suspicious section naming flags or packed section indicators.
- **Import & Export Metrics**:
  - Total number of imported DLLs (`imported_dll_count`).
  - Total number of imported functions (`imported_symbol_count`).
  - Known suspicious API call counts (e.g., memory injection, anti-debugging, process hollowing APIs like `VirtualAllocEx`, `CreateRemoteThread`, `WriteProcessMemory`, `IsDebuggerPresent`).

---

## 3. Supported Data Sources

### A. EMBER (Endgame Malware BEnchmark for Research)
- The [EMBER dataset](https://github.com/endgameinc/ember) contains features extracted from hundreds of thousands of benign and malicious Windows PE binaries.
- Extracted features can be converted or filtered to the tabular format required by XMalGuard.

### B. Custom Extracted PE Datasets
- Using `pefile` to parse your own repository of benign system binaries (e.g. from clean Windows installations) and labeled malware samples.
- Feature extraction pipelines within `backend/app/features/` can parse raw files into tabular representations.

### C. Synthetic Dataset Generation (Development & Testing)
- For initial prototyping, integration testing, and CI/CD pipelines without requiring access to real malware corpora, use:
  ```bash
  python generate_synthetic_dataset.py
  ```
- This script generates a statistically representative CSV (`data/synthetic_pe_dataset.csv`) modeling typical benign and malware distributions (e.g., higher entropy and suspicious API imports for malicious samples, valid signatures and debug data for benign samples).
