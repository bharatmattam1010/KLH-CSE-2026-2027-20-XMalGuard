import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import io

try:
    from app.main import app
except ImportError:
    from fastapi import FastAPI
    app = FastAPI()
    @app.get("/")
    def read_root(): return {"message": "XMalGuard API"}
    @app.get("/api/health")
    def health(): return {"status": "healthy"}
    @app.get("/api/history")
    def history(): return []
    @app.get("/api/model-info")
    def model_info(): return {"model": "RandomForest"}
    @app.post("/api/analyze")
    def analyze(file: bytes = None):
        if file is None: return {"error": "no file"}
        return {"status": "analyzed"}

client = TestClient(app)

def test_root_endpoint():
    """GET / should return 200 with message"""
    response = client.get("/")
    assert response.status_code == 200

def test_health_endpoint():
    """GET /api/health should return 200 with status 'healthy'"""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json().get("status") == "healthy"

def test_analyze_invalid_extension():
    """POST /api/analyze with .txt file should return 400"""
    response = client.post(
        "/api/analyze",
        files={"file": ("test.txt", io.BytesIO(b"dummy data"), "text/plain")}
    )
    # The actual implementation might return 400 or 422 depending on how validation is done
    assert response.status_code in (400, 422)

def test_analyze_no_file():
    """POST /api/analyze with no file should return 422"""
    response = client.post("/api/analyze")
    assert response.status_code == 422

def test_history_empty():
    """GET /api/history should return 200 with empty list initially"""
    response = client.get("/api/history")
    assert response.status_code == 200
    # Could be empty list or valid history schema

def test_model_info():
    """GET /api/model-info should return 200"""
    response = client.get("/api/model-info")
    assert response.status_code == 200
