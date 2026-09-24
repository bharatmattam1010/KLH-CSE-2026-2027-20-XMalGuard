"""Database models for XMalGuard analysis records.

Defines the SQLAlchemy ORM models representing malware analysis results,
extracted static features, explainability metrics, and threat intelligence.
"""

from datetime import datetime
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import Column, DateTime, Float, Integer, String, Text

from app.database import Base


class AnalysisRecord(Base):
    """Represents a persisted static analysis result for an analyzed binary."""

    __tablename__ = "analysis_records"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
        doc="Unique identifier for the analysis record (UUID).",
    )
    filename = Column(
        String(255),
        nullable=False,
        doc="Original filename of the analyzed file.",
    )
    sha256 = Column(
        String(64),
        nullable=False,
        index=True,
        doc="SHA-256 hash of the analyzed binary.",
    )
    file_size = Column(
        Integer,
        nullable=False,
        doc="File size in bytes.",
    )
    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
        doc="UTC timestamp when the analysis was performed.",
    )
    prediction = Column(
        String(32),
        nullable=False,
        doc="Classification prediction: 'benign' or 'malicious'.",
    )
    confidence = Column(
        Float,
        nullable=False,
        doc="Prediction probability / model confidence score (0.0 - 1.0).",
    )
    risk_score = Column(
        Float,
        nullable=False,
        doc="Composite risk score (0 - 100).",
    )
    risk_level = Column(
        String(32),
        nullable=False,
        doc="Risk level category (e.g. Low, Medium, High, Critical).",
    )
    features_json = Column(
        Text,
        nullable=False,
        doc="JSON-encoded dictionary of extracted static PE features.",
    )
    shap_json = Column(
        Text,
        nullable=True,
        doc="JSON-encoded dictionary of SHAP feature importance values.",
    )
    threat_intel_json = Column(
        Text,
        nullable=True,
        doc="JSON-encoded threat intelligence enrichment results (e.g., VirusTotal).",
    )

    def __repr__(self) -> str:
        """Return developer-friendly string representation of the record."""
        return (
            f"<AnalysisRecord(id={self.id!r}, "
            f"filename={self.filename!r}, "
            f"prediction={self.prediction!r}, "
            f"risk_score={self.risk_score!r})>"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the database record into a Python dictionary.

        Returns:
            Dict[str, Any]: Key-value representation of the analysis record.
        """
        return {
            "id": self.id,
            "filename": self.filename,
            "sha256": self.sha256,
            "file_size": self.file_size,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "prediction": self.prediction,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "features_json": self.features_json,
            "shap_json": self.shap_json,
            "threat_intel_json": self.threat_intel_json,
        }
