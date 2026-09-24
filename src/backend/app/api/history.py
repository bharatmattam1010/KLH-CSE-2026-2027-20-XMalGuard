import json
import logging
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models_db import AnalysisRecord

logger = logging.getLogger(__name__)

router = APIRouter(tags=["History"])

@router.get("/history")
def get_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Retrieve paginated list of past analysis records.
    """
    records = db.query(AnalysisRecord)\
        .order_by(desc(AnalysisRecord.timestamp))\
        .offset(skip)\
        .limit(limit)\
        .all()
        
    result = []
    for record in records:
        result.append({
            "id": record.id,
            "filename": record.filename,
            "sha256": record.sha256,
            "timestamp": record.timestamp.isoformat() if record.timestamp else None,
            "prediction": record.prediction,
            "confidence": record.confidence,
            "risk_score": record.risk_score,
            "risk_level": record.risk_level
        })
    return result

@router.get("/analysis/{analysis_id}")
def get_analysis(analysis_id: str, db: Session = Depends(get_db)):
    """
    Retrieve full details of a specific analysis record by ID.
    """
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")
        
    # Parse JSON fields back to dicts
    features = json.loads(record.features_json) if record.features_json else {}
    shap_data = json.loads(record.shap_json) if record.shap_json else None
    threat_intel = json.loads(record.threat_intel_json) if record.threat_intel_json else None
    
    return {
        "analysis_id": record.id,
        "filename": record.filename,
        "timestamp": record.timestamp.isoformat() if record.timestamp else None,
        "file_info": features.get("file_info", {"sha256": record.sha256, "size": record.file_size}),
        "prediction": {
            "prediction": record.prediction,
            "confidence": record.confidence
        },
        "risk_assessment": {
            "score": record.risk_score,
            "level": record.risk_level
        },
        "static_features": features.get("ml_features", {}),
        "explanation": shap_data,
        "threat_intelligence": threat_intel
    }

@router.delete("/analysis/{analysis_id}")
def delete_analysis(analysis_id: str, db: Session = Depends(get_db)):
    """
    Delete a specific analysis record.
    """
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")
        
    db.delete(record)
    db.commit()
    
    return {"message": "Analysis deleted", "id": analysis_id}
