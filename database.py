# ============================================================
#  AURA :: Database Layer
#  SQLite + SQLAlchemy
# ============================================================

from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import uuid

# ── Setup ─────────────────────────────────────────────────
DATABASE_URL = "sqlite:///./aura.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ── Models ─────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username      = Column(String, unique=True, index=True, nullable=False)
    email         = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name     = Column(String, default="")
    role          = Column(String, default="analyst")   # admin / analyst / viewer
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=datetime.utcnow)
    scans         = relationship("Scan", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"
    id              = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(String, ForeignKey("users.id"), nullable=True)
    scan_type       = Column(String, nullable=False)   # IMAGE / VIDEO / TEXT
    threat_level    = Column(String, nullable=False)   # SAFE / CAUTION / DANGER / CRITICAL
    threat_level_num= Column(Integer, default=0)
    summary         = Column(Text, default="")
    recommendation  = Column(Text, default="")
    object_count    = Column(Integer, default=0)
    danger_count    = Column(Integer, default=0)
    safe_count      = Column(Integer, default=0)
    avg_confidence  = Column(Float, default=0.0)
    processing_ms   = Column(Integer, default=0)
    session_id      = Column(String, default="")
    created_at      = Column(DateTime, default=datetime.utcnow)
    user            = relationship("User", back_populates="scans")
    detections      = relationship("Detection", back_populates="scan", cascade="all, delete-orphan")


class Detection(Base):
    __tablename__ = "detections"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id     = Column(String, ForeignKey("scans.id"), nullable=False)
    label       = Column(String, nullable=False)
    confidence  = Column(Float, default=0.0)
    threat      = Column(String, default="SAFE")
    category    = Column(String, default="unknown")
    priority    = Column(Integer, default=1)
    rationale   = Column(Text, default="")
    bbox_x      = Column(Integer, default=0)
    bbox_y      = Column(Integer, default=0)
    bbox_w      = Column(Integer, default=0)
    bbox_h      = Column(Integer, default=0)
    scan        = relationship("Scan", back_populates="detections")


# ── Init ──────────────────────────────────────────────────
def init_db():
    Base.metadata.create_all(bind=engine)
    print("[AURA-DB] Database initialized: aura.db")


# ── Dependency ────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Helper: Save scan to DB ───────────────────────────────
def save_scan(db, report: dict, scan_type: str, user_id: str = None) -> Scan:
    scan = Scan(
        user_id         = user_id,
        scan_type       = scan_type,
        threat_level    = report.get("overallThreat", "CLEAR"),
        threat_level_num= report.get("overallThreatLevel", 0),
        summary         = report.get("summary", ""),
        recommendation  = report.get("recommendation", ""),
        object_count    = len(report.get("objects", [])),
        danger_count    = report.get("dangerCount", 0),
        safe_count      = report.get("safeCount", 0),
        avg_confidence  = report.get("averageConfidence", 0.0),
        processing_ms   = report.get("processingTimeMs", 0),
        session_id      = report.get("frameId", "")[:20],
    )
    db.add(scan)
    db.flush()

    # Save detections
    for obj in report.get("objects", []):
        bbox = obj.get("bbox", {})
        det = Detection(
            scan_id    = scan.id,
            label      = obj.get("label", ""),
            confidence = obj.get("confidence", 0.0),
            threat     = obj.get("threat", "SAFE"),
            category   = obj.get("category", "unknown"),
            priority   = obj.get("priority", 1),
            rationale  = obj.get("rationale", ""),
            bbox_x     = bbox.get("x", 0),
            bbox_y     = bbox.get("y", 0),
            bbox_w     = bbox.get("w", 0),
            bbox_h     = bbox.get("h", 0),
        )
        db.add(det)

    db.commit()
    db.refresh(scan)
    return scan