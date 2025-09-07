#!/usr/bin/env python3
"""
Evidence schema and writer for vulnerability assessment results
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import os
import uuid
from datetime import datetime

from .targets import Target
from .probes.engine import ProbeResult
from .cvss import CVSSVector
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .injector import InjectionResult

class CVSSInfo(BaseModel):
    """CVSS scoring information"""
    vector: str
    score: float
    assumptions: List[str] = Field(default_factory=list)

class EvidenceRow(BaseModel):
    """Evidence row for vulnerability findings - normalized schema"""
    id: str
    job_id: str
    url: str
    method: str
    in_: str = Field(alias="in")  # "query", "form", "json", "header"
    param: str
    payload: Optional[str] = None
    family: str  # "xss", "sqli", "redirect", etc.
    result_type: str  # "confirmed", "suspected", "tested_negative"
    status_code: Optional[int] = None
    reflection_context: Optional[str] = None  # null|"raw"|"html"|"attr"|"js"
    sql_error_excerpt: Optional[str] = None
    req_headers: Optional[Dict[str, str]] = None
    req_body: Optional[str] = None
    resp_headers: Optional[Dict[str, str]] = None
    resp_body_snippet: Optional[str] = None  # max 2KB
    dom_snapshot_path: Optional[str] = None
    cvss: CVSSInfo
    why: List[str] = Field(default_factory=list)
    timestamp: str
    
    @classmethod
    def from_probe_confirm(cls, target: Target, family: str, probe: ProbeResult) -> 'EvidenceRow':
        """Create evidence row from probe confirmation"""
        # Extract probe-specific evidence
        reflection_context = None
        sql_error_excerpt = None
        
        if hasattr(probe, 'xss_context'):
            reflection_context = probe.xss_context
        if hasattr(probe, 'sql_error_excerpt'):
            sql_error_excerpt = probe.sql_error_excerpt
        
        return cls(
            id=str(uuid.uuid4()),
            job_id="",  # Will be set by caller
            url=target.url,
            method=target.method,
            **{'in': target.param_in},  # Use the alias
            param=target.param,
            payload=None,
            family=family,
            result_type="confirmed",
            status_code=target.status,
            reflection_context=reflection_context,
            sql_error_excerpt=sql_error_excerpt,
            req_headers=None,
            req_body=None,
            resp_headers=None,
            resp_body_snippet=None,
            dom_snapshot_path=None,
            cvss=CVSSInfo(vector="", score=0.0, assumptions=[]),  # Will be set by caller
            why=["probe_confirmed"],
            timestamp=datetime.utcnow().isoformat()
        )
    
    @classmethod
    def from_injection(cls, target: Target, family: str, probe: ProbeResult, rec: Dict[str, Any], inj: 'InjectionResult') -> 'EvidenceRow':
        """Create evidence row from injection result"""
        return cls(
            id=str(uuid.uuid4()),
            job_id="",  # Will be set by caller
            url=target.url,
            method=target.method,
            **{'in': target.param_in},  # Use the alias
            param=target.param,
            payload=rec.get("payload", ""),
            family=family,
            result_type="confirmed",
            status_code=inj.status,
            reflection_context=None,
            sql_error_excerpt=None,
            req_headers=None,  # Could be extracted from target if needed
            req_body=None,
            resp_headers={"location": inj.redirect_location} if inj.redirect_location else None,
            resp_body_snippet=inj.response_snippet,
            dom_snapshot_path=None,
            cvss=CVSSInfo(vector="", score=0.0, assumptions=[]),  # Will be set by caller
            why=inj.why + ["ml_ranked", "inject_confirmed"],
            timestamp=datetime.utcnow().isoformat()
        )
    
    @classmethod
    def from_confirmed(cls, target: Target, family: str, probe: ProbeResult, cvss_data: Dict[str, Any], job_id: str, payload: Optional[str] = None) -> 'EvidenceRow':
        """Create evidence row from confirmed vulnerability"""
        # Extract probe-specific evidence
        reflection_context = None
        sql_error_excerpt = None
        
        if hasattr(probe, 'xss_context'):
            reflection_context = probe.xss_context
        if hasattr(probe, 'sql_error_excerpt'):
            sql_error_excerpt = probe.sql_error_excerpt
        
        # Create CVSS info from the new data format
        cvss_info = CVSSInfo(
            vector=cvss_data["vector"],
            score=cvss_data["score"],
            assumptions=cvss_data["assumptions"]
        )
        
        return cls(
            id=str(uuid.uuid4()),
            job_id=job_id,
            url=target.url,
            method=target.method,
            **{'in': target.param_in},  # Use the alias
            param=target.param,
            payload=payload,
            family=family,
            result_type="confirmed",
            status_code=target.status,
            reflection_context=reflection_context,
            sql_error_excerpt=sql_error_excerpt,
            req_headers=None,  # TODO: Capture request headers
            req_body=None,  # TODO: Capture request body
            resp_headers=None,  # TODO: Capture response headers
            resp_body_snippet=None,  # TODO: Capture response snippet (max 2KB)
            dom_snapshot_path=None,  # TODO: Capture DOM snapshot
            cvss=cvss_info,
            why=["probe_confirmed"],
            timestamp=datetime.utcnow().isoformat()
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return self.dict(by_alias=True)

def write_evidence(job_id: str, evidence_row: EvidenceRow) -> str:
    """
    Write evidence row and return the file path.
    
    Args:
        job_id: Job ID for the evidence
        evidence_row: Evidence row to write
        
    Returns:
        Path to the evidence file
    """
    # Set the job_id on the evidence row
    evidence_row.job_id = job_id
    
    # Create evidence directory if it doesn't exist
    evidence_dir = os.path.join("data", "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    
    # Write to job-specific file
    evidence_file = os.path.join(evidence_dir, f"{job_id}.jsonl")
    
    with open(evidence_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(evidence_row.to_dict()) + "\n")
    
    print(f"📝 Evidence written: {evidence_file}")
    return evidence_file

def write_evidence_row(row: EvidenceRow, data_dir: str = "data") -> None:
    """
    Write evidence row to JSONL file.
    
    Args:
        row: Evidence row to write
        data_dir: Base data directory
    """
    # Create evidence directory if it doesn't exist
    evidence_dir = os.path.join(data_dir, "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    
    # Write to job-specific file
    evidence_file = os.path.join(evidence_dir, f"{row.job_id}.jsonl")
    
    with open(evidence_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(row.to_dict()) + "\n")
    
    print(f"📝 Evidence written: {evidence_file}")

def read_evidence_rows(job_id: str, data_dir: str = "data") -> List[EvidenceRow]:
    """
    Read evidence rows from JSONL file.
    
    Args:
        job_id: Job ID to read evidence for
        data_dir: Base data directory
        
    Returns:
        List of evidence rows
    """
    evidence_file = os.path.join(data_dir, "evidence", f"{job_id}.jsonl")
    
    if not os.path.exists(evidence_file):
        return []
    
    rows = []
    with open(evidence_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                # Use model_validate to handle the alias properly
                rows.append(EvidenceRow.model_validate(data))
    
    return rows

def aggregate_evidence(job_id: str, data_dir: str = "data") -> Dict[str, Any]:
    """
    Aggregate evidence for a job.
    
    Args:
        job_id: Job ID to aggregate evidence for
        data_dir: Base data directory
        
    Returns:
        Aggregated statistics and findings
    """
    rows = read_evidence_rows(job_id, data_dir)
    
    if not rows:
        return {
            "targets_total": 0,
            "positive": 0,
            "abstain": 0,
            "not_applicable": 0,
            "suspected": 0,
            "findings": []
        }
    
    # Count by result type
    counts = {
        "targets_total": len(rows),
        "positive": sum(1 for r in rows if r.result_type == "confirmed"),
        "abstain": 0,  # Not stored in evidence
        "not_applicable": 0,  # Not stored in evidence
        "suspected": sum(1 for r in rows if r.result_type == "suspected")
    }
    
    # Extract findings with CVSS and proof
    findings = []
    for row in rows:
        if row.result_type == "confirmed":
            # Extract path from URL
            from urllib.parse import urlparse
            parsed_url = urlparse(row.url)
            path = parsed_url.path or "/"
            
            findings.append({
                "url": row.url,
                "path": path,
                "method": row.method,
                "param": row.param,
                "in_": row.in_,
                "family": row.family,
                "cvss": {
                    "vector": row.cvss.vector,
                    "score": row.cvss.score,
                    "assumptions": row.cvss.assumptions
                },
                "why": row.why,
                "reflection_context": row.reflection_context,
                "sql_error_excerpt": row.sql_error_excerpt,
                "dom_snapshot_path": row.dom_snapshot_path,
                "timestamp": row.timestamp
            })
    
    return {
        **counts,
        "findings": findings
    }
