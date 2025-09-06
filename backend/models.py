# backend/models.py

from __future__ import annotations

from datetime import datetime
import enum
from typing import Dict, List, Optional

from sqlalchemy import (
    Integer, String, Text, Enum, ForeignKey, Float, DateTime, Index
)
from sqlalchemy.orm import relationship, Mapped, mapped_column

# SQLite-first JSON column; stores as TEXT if JSON1 absent (fine for dev)
from sqlalchemy.dialects.sqlite import JSON

# Support both package and flat execution
try:
    from .db import Base
except ImportError:
    from db import Base


class JobPhase(str, enum.Enum):
    discovery = "discovery"
    planning = "planning"
    executing = "executing"
    triage = "triage"
    done = "done"
    error = "error"
    cancelled = "cancelled"


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    method: Mapped[str] = mapped_column(String(10), index=True)
    url: Mapped[str] = mapped_column(Text, index=True)
    # e.g. {"query": ["q"], "form": ["username"], "json": ["email"]}
    param_locs: Mapped[Dict[str, List[str]]] = mapped_column(JSON, default=dict)
    auth_ctx_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_endpoints_method_url", "method", "url"),
    )

    # Optional backref from TestCase if needed:
    # test_cases: Mapped[List["TestCase"]] = relationship("TestCase", back_populates="endpoint")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    phase: Mapped[JobPhase] = mapped_column(Enum(JobPhase, native_enum=False), default=JobPhase.discovery)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    target: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class TestCase(Base):
    __tablename__ = "test_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(String(36), index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"))
    param: Mapped[str] = mapped_column(String(128))
    # e.g., "xss_attr", "xss_js", "sqli_boolean", "sqli_error"
    family: Mapped[str] = mapped_column(String(64))
    # versioned payload identifier
    payload_id: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    endpoint = relationship("Endpoint")  # add back_populates if you want bidirectional links


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(String(36), index=True)
    test_case_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("test_cases.id", ondelete="SET NULL"), nullable=True
    )
    # Request/response metadata blobs
    request_meta: Mapped[dict] = mapped_column(JSON)   # method, url, headers, body_hash, param, marker
    response_meta: Mapped[dict] = mapped_column(JSON)  # status, len, elapsed_ms, hash, content_sample
    # Detection signals: reflections, regex hits, timing, dialog flags, etc.
    signals: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    # label in {"sqli","xss","benign",...}
    label: Mapped[str] = mapped_column(String(32), default="benign")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_evidence_job_label", "job_id", "label"),
    )
