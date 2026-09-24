import pytest
import os
import pefile
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

# Assuming app is in the Python path
try:
    from app.main import app
except ImportError:
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from app.main import app

@pytest.fixture
def sample_pe_bytes():
    """Create minimal valid PE bytes for testing."""
    # A tiny valid DOS header + PE header is required. We'll use a known minimal PE byte sequence or just build a basic one.
    # For simplicity, returning a minimal DOS stub and PE header signature
    # This is a highly truncated valid-ish PE structure for parsing tests
    pe_data = bytearray(b"MZ" + b"\x00"*58)
    pe_data.extend(b"\x80\x00\x00\x00") # Pointer to PE header (offset 0x80)
    pe_data.extend(b"\x00" * (0x80 - len(pe_data))) # Padding
    pe_data.extend(b"PE\x00\x00") # PE signature
    # Machine (2 bytes), NumberOfSections (2 bytes), TimeDateStamp (4 bytes), PointerToSymbolTable (4 bytes), NumberOfSymbols (4 bytes), SizeOfOptionalHeader (2 bytes), Characteristics (2 bytes)
    pe_data.extend(b"\x4c\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x02\x01")
    # Optional header magic (2 bytes)
    pe_data.extend(b"\x0b\x01")
    pe_data.extend(b"\x00" * 222) # Rest of optional header
    return bytes(pe_data)

@pytest.fixture
def tmp_pe_file(tmp_path, sample_pe_bytes):
    """Write sample_pe_bytes to a temp file, yield path, cleanup"""
    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(sample_pe_bytes)
    yield pe_file

@pytest.fixture
def sample_features():
    """Return a dict with 35 ML features filled with reasonable test values."""
    return {
        'Machine': 332,
        'SizeOfOptionalHeader': 224,
        'Characteristics': 258,
        'MajorLinkerVersion': 14,
        'MinorLinkerVersion': 0,
        'SizeOfCode': 1024,
        'SizeOfInitializedData': 2048,
        'SizeOfUninitializedData': 0,
        'AddressOfEntryPoint': 4096,
        'BaseOfCode': 4096,
        'BaseOfData': 8192,
        'ImageBase': 4194304,
        'SectionAlignment': 4096,
        'FileAlignment': 512,
        'MajorOperatingSystemVersion': 6,
        'MinorOperatingSystemVersion': 0,
        'MajorImageVersion': 0,
        'MinorImageVersion': 0,
        'MajorSubsystemVersion': 6,
        'MinorSubsystemVersion': 0,
        'SizeOfImage': 12288,
        'SizeOfHeaders': 1024,
        'CheckSum': 0,
        'Subsystem': 2,
        'DllCharacteristics': 33088,
        'SizeOfStackReserve': 1048576,
        'SizeOfStackCommit': 4096,
        'SizeOfHeapReserve': 1048576,
        'SizeOfHeapCommit': 4096,
        'LoaderFlags': 0,
        'NumberOfRvaAndSizes': 16,
        'SectionsNb': 3,
        'SectionsMeanEntropy': 3.5,
        'SectionsMinEntropy': 0.0,
        'SectionsMaxEntropy': 6.5
    }

@pytest.fixture
def sample_analysis_data(sample_features):
    """Return a complete analysis result dict for testing report generation."""
    return {
        "filename": "suspicious.exe",
        "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
        "hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_size": 10240,
        "prediction": "Malicious",
        "confidence": 0.95,
        "malicious_probability": 0.95,
        "benign_probability": 0.05,
        "risk_score": 85.0,
        "risk_level": "CRITICAL",
        "features": sample_features,
        "threat_intel": {
            "available": True,
            "positives": 5,
            "total": 60,
            "is_mock": True
        }
    }

@pytest.fixture
def test_client():
    """Create a FastAPI TestClient."""
    return TestClient(app)

@pytest.fixture
def db_session():
    """Create an in-memory SQLite test database."""
    # Since we don't have the actual DB implementation, mock or return a basic connection string/session
    yield MagicMock()
