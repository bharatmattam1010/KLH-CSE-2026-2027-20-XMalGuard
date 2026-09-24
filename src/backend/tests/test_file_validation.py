import pytest

# Dummy functions representing typical file validation logic in the app
def sanitize_filename(filename: str) -> str:
    import os
    import re
    # Remove path traversal
    filename = os.path.basename(filename)
    # Replace special chars
    filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)
    # Truncate to 255
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255 - len(ext)] + ext
    return filename

def is_allowed_extension(filename: str) -> bool:
    allowed = {'.exe', '.dll', '.sys'}
    import os
    _, ext = os.path.splitext(filename.lower())
    return ext in allowed


def test_sanitize_filename_path_traversal():
    """'../../../etc/passwd' should be sanitized"""
    result = sanitize_filename("../../../etc/passwd")
    assert result == "passwd"
    assert "/" not in result
    assert "\\" not in result

def test_sanitize_filename_special_chars():
    """Special chars should be replaced"""
    result = sanitize_filename("file@name#.exe")
    assert "@" not in result
    assert "#" not in result
    assert result == "file_name_.exe"

def test_sanitize_filename_length():
    """Long filenames should be truncated to 255"""
    long_name = "a" * 300 + ".exe"
    result = sanitize_filename(long_name)
    assert len(result) <= 255
    assert result.endswith(".exe")

def test_allowed_extensions():
    """.exe and .dll should be allowed"""
    assert is_allowed_extension("malware.exe") is True
    assert is_allowed_extension("library.dll") is True
    assert is_allowed_extension("driver.sys") is True

def test_rejected_extensions():
    """.txt, .py, .js should be rejected"""
    assert is_allowed_extension("readme.txt") is False
    assert is_allowed_extension("script.py") is False
    assert is_allowed_extension("payload.js") is False
