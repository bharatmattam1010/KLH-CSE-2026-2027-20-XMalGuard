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
        pred_str = (record.prediction or "unknown").lower()
        is_mal = (pred_str == "malicious")
        conf = float(record.confidence or 0.0)
        
        result.append({
            "id": record.id,
            "filename": record.filename,
            "sha256": record.sha256,
            "created_at": record.timestamp.isoformat() if record.timestamp else None,
            "timestamp": record.timestamp.isoformat() if record.timestamp else None,
            "file_info": {
                "filename": record.filename,
                "hashes": {"sha256": record.sha256}
            },
            "prediction": {
                "prediction": "malicious" if is_mal else "benign",
                "is_malicious": is_mal,
                "confidence": conf
            },
            "confidence": conf,
            "risk_assessment": {
                "score": float(record.risk_score or 0.0),
                "level": record.risk_level or ("CRITICAL" if is_mal else "LOW")
            },
            "risk_score": float(record.risk_score or 0.0),
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
    
    pred_str = (record.prediction or "unknown").lower()
    is_mal = (pred_str == "malicious")
    conf = float(record.confidence or 0.0)
    mal_prob = conf if is_mal else (1.0 - conf)
    ben_prob = (1.0 - conf) if is_mal else conf
    
    return {
        "analysis_id": record.id,
        "id": record.id,
        "filename": record.filename,
        "timestamp": record.timestamp.isoformat() if record.timestamp else None,
        "created_at": record.timestamp.isoformat() if record.timestamp else None,
        "file_info": features.get("file_info", {
            "filename": record.filename,
            "hashes": {"sha256": record.sha256},
            "sha256": record.sha256,
            "file_size": record.file_size
        }),
        "prediction": {
            "prediction": "malicious" if is_mal else "benign",
            "is_malicious": is_mal,
            "confidence": conf,
            "malicious_probability": mal_prob,
            "benign_probability": ben_prob,
            "probabilities": {
                "malicious": mal_prob,
                "benign": ben_prob
            }
        },
        "risk_assessment": {
            "score": float(record.risk_score or 0.0),
            "total_score": float(record.risk_score or 0.0),
            "level": record.risk_level or ("CRITICAL" if is_mal else "LOW"),
            "risk_level": record.risk_level or ("CRITICAL" if is_mal else "LOW"),
            "breakdown": {},
            "contributing_factors": []
        },
        "static_features": features.get("ml_features", features),
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
