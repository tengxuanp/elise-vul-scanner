"""
End-to-End Smoke Tests - FastAPI TestClient tests for API contract.
"""
import pytest
import json
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock

from backend.main import app
from backend.app_state import DATA_DIR

client = TestClient(app)

class TestCrawlAPI:
    """Test crawl API contract."""
    
    def test_crawl_missing_target_url(self):
        """Test crawl API rejects request without target_url."""
        response = client.post("/api/crawl", json={
            "job_id": "test-job",
            "target_url": ""
        })
        assert response.status_code == 422
    
    def test_crawl_invalid_url(self):
        """Test crawl API rejects invalid URL."""
        response = client.post("/api/crawl", json={
            "job_id": "test-job",
            "target_url": "not-a-url"
        })
        assert response.status_code == 422
    
    @patch('backend.modules.playwright_crawler.crawl_site')
    def test_crawl_success(self, mock_crawl):
        """Test successful crawl returns correct contract."""
        # Mock crawler response
        mock_crawl.return_value = {
            "endpoints": [
                {
                    "url": "http://test.com/page1",
                    "method": "GET",
                    "params": [{"name": "param1", "in": "query"}]
                },
                {
                    "url": "http://test.com/page2", 
                    "method": "POST",
                    "params": [{"name": "param2", "in": "form"}]
                }
            ]
        }
        
        response = client.post("/api/crawl", json={
            "job_id": "test-crawl-123",
            "target_url": "http://test.com",
            "crawl_opts": {
                "max_depth": 2,
                "max_endpoints": 10
            }
        })
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify contract
        assert data["job_id"] == "test-crawl-123"
        assert data["mode"] == "crawl_only"
        assert data["endpoints_count"] == 2
        assert data["persisted"] is True
        assert data["path"] == "jobs/test-crawl-123/endpoints.json"
        
        # Verify persistence
        endpoints_path = DATA_DIR / "jobs" / "test-crawl-123" / "endpoints.json"
        assert endpoints_path.exists()
        
        with open(endpoints_path, 'r') as f:
            persisted_data = json.load(f)
        
        assert persisted_data["job_id"] == "test-crawl-123"
        assert persisted_data["target_url"] == "http://test.com"
        assert len(persisted_data["endpoints"]) == 2

class TestAssessAPI:
    """Test assess API contract."""
    
    def test_assess_multiple_pathways(self):
        """Test assess API rejects multiple pathways."""
        response = client.post("/api/assess", json={
            "job_id": "test-job",
            "endpoints": [{"url": "http://test.com"}],
            "target_url": "http://test.com"
        })
        assert response.status_code == 422
        detail = response.json()["detail"]
        # Check if the error message is in the detail array
        error_messages = [item["msg"] for item in detail if isinstance(item, dict) and "msg" in item]
        assert any("Cannot specify both" in msg for msg in error_messages)
    
    def test_assess_no_pathway(self):
        """Test assess API rejects no pathway."""
        response = client.post("/api/assess", json={
            "job_id": "test-job"
        })
        assert response.status_code == 422
    
    def test_assess_missing_persisted_endpoints(self):
        """Test assess API fails when no persisted endpoints."""
        response = client.post("/api/assess", json={
            "job_id": "nonexistent-job"
        })
        assert response.status_code == 422
        assert "No persisted endpoints found" in response.json()["detail"]
    
    @patch('backend.routes.assess_routes.run_job')
    def test_assess_with_target_url(self, mock_run_job):
        """Test assess API with target_url pathway."""
        # Mock fuzzer response
        mock_run_job.return_value = {
            "results": [
                {
                    "evidence_id": "test-evidence-1",
                    "url": "http://test.com",
                    "path": "/",
                    "method": "GET",
                    "param_in": "query",
                    "param": "test",
                    "family": "xss",
                    "decision": "positive",
                    "why": ["probe_proof"],
                    "cvss": {"base": 6.1},
                    "rank_source": "probe_only",
                    "ml_family": None,
                    "ml_proba": None,
                    "ml_threshold": None,
                    "model_tag": None,
                    "attempt_idx": 0,
                    "top_k_used": 0,
                    "timing_ms": 150,
                    "status": 200
                }
            ],
            "findings": [],
            "meta": {
                "endpoints_supplied": 1,
                "targets_enumerated": 1,
                "injections_attempted": 1,
                "injections_succeeded": 1,
                "budget_ms_used": 1000,
                "errors_by_kind": {}
            }
        }
        
        response = client.post("/api/assess", json={
            "job_id": "test-assess-123",
            "target_url": "http://test.com",
            "top_k": 3
        })
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify contract
        assert data["job_id"] == "test-assess-123"
        assert data["mode"] == "direct"
        assert "summary" in data
        assert "results" in data
        assert "findings" in data
        assert "meta" in data
        assert "healthz" in data
        
        # Verify summary
        summary = data["summary"]
        assert summary["total"] == 1
        assert summary["positive"] == 1
        assert summary["suspected"] == 0
        assert summary["abstain"] == 0
        assert summary["na"] == 0
        
        # Verify results
        results = data["results"]
        assert len(results) == 1
        result = results[0]
        
        # Verify telemetry fields are non-null
        assert "attempt_idx" in result
        assert "top_k_used" in result
        assert "rank_source" in result
        assert result["attempt_idx"] is not None
        assert result["top_k_used"] is not None
        assert result["rank_source"] is not None
        
        # Verify healthz
        healthz = data["healthz"]
        assert "use_ml" in healthz
        assert "ml_active" in healthz
        assert "models_available" in healthz
        assert "thresholds" in healthz
    
    @patch('backend.routes.assess_routes.run_job')
    def test_assess_persist_after_crawl(self, mock_run_job):
        """Test assess API with persist_after_crawl=true."""
        # Mock fuzzer response with endpoints
        mock_run_job.return_value = {
            "results": [
                {
                    "evidence_id": "test-evidence-1",
                    "url": "http://test.com",
                    "path": "/",
                    "method": "GET",
                    "param_in": "query",
                    "param": "test",
                    "decision": "positive",
                    "family": "xss",
                    "why": ["probe_proof"],
                    "cvss": {"base": 6.1},
                    "attempt_idx": 0,
                    "top_k_used": 0,
                    "rank_source": "probe_only"
                }
            ],
            "findings": [],
            "meta": {
                "endpoints_supplied": 1,
                "targets_enumerated": 1
            },
            "endpoints": [
                {
                    "url": "http://test.com",
                    "path": "/",
                    "method": "GET",
                    "params": ["test"],
                    "param_locs": {"query": ["test"], "form": [], "json": []},
                    "status": 200,
                    "source": "nav",
                    "content_type": "text/html",
                    "seen": 1
                }
            ]
        }
        
        response = client.post("/api/assess", json={
            "job_id": "test-persist-123",
            "target_url": "http://test.com",
            "persist_after_crawl": True,
            "top_k": 3
        })
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify mode is set correctly
        assert data["mode"] == "crawl_then_assess"
        
        # Verify endpoints were persisted
        job_dir = DATA_DIR / "jobs" / "test-persist-123"
        endpoints_path = job_dir / "endpoints.json"
        assert endpoints_path.exists()
        
        with open(endpoints_path, 'r') as f:
            persisted_data = json.load(f)
            assert persisted_data["job_id"] == "test-persist-123"
            assert persisted_data["target_url"] == "http://test.com"
            assert len(persisted_data["endpoints"]) == 1
            assert persisted_data["endpoints_count"] == 1
    
    def test_assess_with_persisted_endpoints(self):
        """Test assess API loading from persisted endpoints with enumeration."""
        # Create test persisted endpoints with proper param_locs structure
        job_dir = DATA_DIR / "jobs" / "test-persisted-123"
        job_dir.mkdir(parents=True, exist_ok=True)
        
        endpoints_data = {
            "job_id": "test-persisted-123",
            "target_url": "http://test.com",
            "endpoints": [
                {
                    "url": "http://test.com/page1?param1=value1",
                    "path": "/page1",
                    "method": "GET",
                    "status": 200,
                    "content_type": "text/html",
                    "param_locs": {
                        "query": [{"name": "param1"}],
                        "form": [],
                        "json": []
                    }
                },
                {
                    "url": "http://test.com/api",
                    "path": "/api",
                    "method": "POST",
                    "status": 200,
                    "content_type": "application/json",
                    "param_locs": {
                        "query": [],
                        "form": [],
                        "json": [{"name": "data"}]
                    }
                }
            ],
            "endpoints_count": 2
        }
        
        endpoints_path = job_dir / "endpoints.json"
        with open(endpoints_path, 'w') as f:
            json.dump(endpoints_data, f)
        
        # Test with real enumeration (no mocking to verify actual behavior)
        response = client.post("/api/assess", json={
            "job_id": "test-persisted-123"
        })
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["mode"] == "from_persisted"
        assert data["meta"]["endpoints_supplied"] == 2
        assert data["meta"]["targets_enumerated"] == 2  # Should enumerate 2 targets from the endpoints
        
        # Verify new meta counters are present
        assert "processing_ms" in data["meta"], "Should have processing_ms"
        assert data["meta"]["processing_ms"] > 0, "Processing time should be positive"
        assert "processing_time" in data["meta"], "Should have processing_time string"
        assert "probe_attempts" in data["meta"], "Should have probe_attempts"
        assert "probe_successes" in data["meta"], "Should have probe_successes"
        assert "ml_inject_attempts" in data["meta"], "Should have ml_inject_attempts"
        assert "ml_inject_successes" in data["meta"], "Should have ml_inject_successes"
        
        # Verify all results have non-null telemetry
        for result in data["results"]:
            assert result["attempt_idx"] is not None
            assert result["top_k_used"] is not None
            assert result["rank_source"] is not None

class TestHealthzAPI:
    """Test healthz API contract."""
    
    def test_healthz_returns_diagnostics(self):
        """Test healthz returns required diagnostic fields."""
        response = client.get("/api/healthz")
        
        # Should return 200 or 500 depending on system state
        assert response.status_code in [200, 500]
        
        data = response.json()
        
        # Verify required fields
        required_fields = [
            "use_ml", "ml_active", "models_available", 
            "thresholds", "ok", "data_dir", "model_dir"
        ]
        
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
        
        # Verify types
        assert isinstance(data["use_ml"], bool)
        assert isinstance(data["ml_active"], bool)
        assert isinstance(data["models_available"], (dict, list))
        assert isinstance(data["thresholds"], dict)
        assert isinstance(data["ok"], bool)
        
        # Verify thresholds structure
        thresholds = data["thresholds"]
        expected_thresholds = ["sqli_tau", "xss_tau", "redirect_tau"]
        for threshold in expected_thresholds:
            assert threshold in thresholds
            assert isinstance(thresholds[threshold], (int, float))

class TestEvidenceAPI:
    """Test evidence API contract."""
    
    def test_evidence_not_found(self):
        """Test evidence API returns 404 for non-existent evidence."""
        response = client.get("/api/evidence/nonexistent-job/nonexistent-evidence")
        assert response.status_code == 404
    
    def test_evidence_success(self):
        """Test evidence API returns evidence for valid ID."""
        # Create test evidence file
        job_dir = DATA_DIR / "jobs" / "test-evidence-job"
        job_dir.mkdir(parents=True, exist_ok=True)
        
        evidence_data = {
            "evidence_id": "test-evidence-123",
            "family": "xss",
            "url": "http://test.com",
            "payload": "<script>alert('test')</script>",
            "response_snippet_text": "&lt;script&gt;alert('test')&lt;/script&gt;",
            "response_snippet_raw": "PHNjcmlwdD5hbGVydCgndGVzdCcpPC9zY3JpcHQ+",
            "why": ["probe_proof"],
            "cvss": {"base": 6.1}
        }
        
        evidence_path = job_dir / "test-evidence-123.json"
        with open(evidence_path, 'w') as f:
            json.dump(evidence_data, f)
        
        response = client.get("/api/evidence/test-evidence-job/test-evidence-123")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["evidence_id"] == "test-evidence-123"
        assert data["family"] == "xss"
        assert "response_snippet_text" in data
        assert "response_snippet_raw" in data
