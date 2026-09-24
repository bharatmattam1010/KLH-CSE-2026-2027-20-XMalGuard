import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models_db import AnalysisRecord
from ..reports.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Reports"])
report_generator = ReportGenerator()

@router.get("/report/{analysis_id}", response_class=HTMLResponse)
def get_report(
    analysis_id: str,
    format: str = Query("html", description="Report format (default: html)"),
    db: Session = Depends(get_db)
):
    """
    Generate and download a comprehensive report for a specific analysis.
    
    Args:
        analysis_id: The unique identifier of the analysis.
        format: The desired report format. Currently only 'html' is supported.
        db: Database session dependency.
        
    Returns:
        HTMLResponse containing the generated report with Content-Disposition header.
    """
    logger.info(f"Report requested for analysis ID: {analysis_id} in {format} format")
    
    if format.lower() != "html":
        raise HTTPException(status_code=400, detail="Only 'html' format is currently supported.")
        
    record = db.query(AnalysisRecord).filter(AnalysisRecord.analysis_id == analysis_id).first()
    
    if not record:
        logger.warning(f"Analysis record {analysis_id} not found for report generation.")
        raise HTTPException(status_code=404, detail="Analysis record not found")
        
    try:
        # Reconstruct analysis_data dictionary from DB record
        analysis_data = {
            "analysis_id": record.analysis_id,
            "filename": record.filename,
            "timestamp": record.created_at.isoformat() if record.created_at else "Unknown",
            "file_info": record.file_info or {},
            "prediction": {
                "prediction": record.prediction,
                "confidence": record.confidence,
                "malicious_probability": record.malicious_probability,
                "benign_probability": record.benign_probability
            },
            "risk_assessment": record.risk_assessment or {},
            "static_features": record.static_features or {},
            "explanation": record.explanation or {},
            "threat_intelligence": record.threat_intelligence
        }
        
        # Generate the HTML report
        html_content = report_generator.generate_report(analysis_data)
        
        # Format the filename
        short_id = analysis_id[:8] if analysis_id else "unknown"
        filename = f"xmalguard_report_{short_id}.html"
        
        return HTMLResponse(
            content=html_content,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        logger.error(f"Error generating report for {analysis_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during report generation")
