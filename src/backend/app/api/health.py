import json
import os
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["System"])

@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """
    System health check endpoint.
    """
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "disconnected"

    # Check if model file exists
    # Assuming models/ directory is at the project root or relative to app
    # For now, we will just check a common path or return 'unknown'
    model_loaded = False
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.path.dirname(curr_dir), "models", "final_model.joblib"),
        os.path.abspath(os.path.join(curr_dir, "../../../models/final_model.joblib")),
        os.path.abspath(os.path.join(curr_dir, "../../models/final_model.joblib")),
    ]
    for p in candidates:
        if os.path.exists(p):
            model_loaded = True
            break
        
    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "model_loaded": model_loaded,
        "database": db_status
    }

@router.get("/model-info")
def model_info():
    """
    Retrieve model information from metadata.
    """
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.abspath(os.path.join(curr_dir, "../../../models/training_metadata.json")),
        os.path.join(os.path.dirname(curr_dir), "models", "training_metadata.json"),
        os.path.abspath(os.path.join(curr_dir, "../../models/training_metadata.json")),
    ]
    metadata_path = next((p for p in candidates if os.path.exists(p)), candidates[0])
    
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            return metadata
        except Exception as e:
            logger.error(f"Failed to read model metadata: {e}")
            return {"available": False, "message": "Error reading model metadata."}
            
    return {"available": False, "message": "No trained model found. Run training pipeline first."}
