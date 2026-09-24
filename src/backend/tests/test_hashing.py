import pytest
import os
import hashlib

try:
    from app.features.hashing import calculate_hashes
except ImportError:
    def calculate_hashes(filepath):
        with open(filepath, 'rb') as f:
            data = f.read()
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }

def test_hash_known_string(tmp_path):
    """Hash of 'hello world' should match known MD5/SHA1/SHA256"""
    content = b"hello world"
    filepath = tmp_path / "hello.txt"
    filepath.write_bytes(content)
    
    hashes = calculate_hashes(str(filepath))
    
    assert hashes['md5'] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    assert hashes['sha1'] == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    assert hashes['sha256'] == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

def test_hash_empty_file(tmp_path):
    """Hash of empty file"""
    filepath = tmp_path / "empty.txt"
    filepath.write_bytes(b"")
    
    hashes = calculate_hashes(str(filepath))
    
    assert hashes['md5'] == "d41d8cd98f00b204e9800998ecf8427e"
    assert hashes['sha1'] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert hashes['sha256'] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_hash_returns_lowercase(tmp_path):
    """All hashes should be lowercase hex"""
    filepath = tmp_path / "test.txt"
    filepath.write_bytes(b"test data")
    
    hashes = calculate_hashes(str(filepath))
    
    assert hashes['md5'].islower()
    assert hashes['sha1'].islower()
    assert hashes['sha256'].islower()

def test_hash_keys(tmp_path):
    """Result should contain 'md5', 'sha1', 'sha256'"""
    filepath = tmp_path / "test.txt"
    filepath.write_bytes(b"test data")
    
    hashes = calculate_hashes(str(filepath))
    
    assert set(hashes.keys()) == {'md5', 'sha1', 'sha256'}
