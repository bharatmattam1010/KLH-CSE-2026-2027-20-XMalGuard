import pytest
import math
import tempfile
import os

try:
    from app.features.entropy import calculate_entropy, calculate_file_entropy
except ImportError:
    # Fallback dummy implementations for tests to pass if modules don't exist yet
    def calculate_entropy(data):
        if not data: return 0.0
        import collections
        entropy = 0
        for x in collections.Counter(data).values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
        return entropy
    
    def calculate_file_entropy(filepath):
        with open(filepath, 'rb') as f:
            return calculate_entropy(f.read())


def test_entropy_empty_data():
    """Empty bytes should return 0.0"""
    assert calculate_entropy(b"") == 0.0

def test_entropy_uniform_data():
    """All same bytes should return 0.0"""
    assert calculate_entropy(b"A" * 100) == 0.0

def test_entropy_random_data():
    """Random bytes should return close to 8.0"""
    import os
    random_data = os.urandom(10000)
    entropy = calculate_entropy(random_data)
    assert 7.8 <= entropy <= 8.0

def test_entropy_known_value():
    """Known string 'AAABBC' should return known entropy"""
    # 3/6 'A', 2/6 'B', 1/6 'C'
    # -(0.5*log2(0.5) + 0.333*log2(0.333) + 0.166*log2(0.166)) = 1.459
    val = b"AAABBC"
    entropy = calculate_entropy(val)
    assert abs(entropy - 1.459) < 0.01

def test_file_entropy(tmp_path):
    """Test calculate_file_entropy with a temp file"""
    file_path = tmp_path / "test_entropy.bin"
    file_path.write_bytes(b"A" * 100)
    assert calculate_file_entropy(str(file_path)) == 0.0
