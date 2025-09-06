"""
Integration tests for bandit API endpoints.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
import os

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi.testclient import TestClient
from main import app


class TestBanditAPI(unittest.TestCase):
    """Test bandit API endpoints."""
    
    def setUp(self):
        self.client = TestClient(app)
        self.test_job_id = "test-job-123"
    
    def test_tick_endpoint(self):
        """Test the /jobs/{job_id}/tick endpoint."""
        # Mock the bandit to avoid database dependencies
        with patch('routes.job_routes.get_bandit') as mock_get_bandit:
            mock_bandit = MagicMock()
            mock_bandit.select.return_value = ("xss_basic", 0.5)
            mock_bandit._calculate_epsilon.return_value = 0.2
            mock_get_bandit.return_value = mock_bandit
            
            response = self.client.post(
                f"/api/jobs/{self.test_job_id}/tick",
                json={
                    "url": "https://example.com/search",
                    "param": "q",
                    "family": "xss",
                    "total_budget": 100,
                    "used_budget": 10
                }
            )
            
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["chosen_payload_id"], "xss_basic")
            self.assertEqual(data["reward_estimate"], 0.5)
            self.assertEqual(data["budget_left"], 89)
            self.assertEqual(data["epsilon"], 0.2)
    
    def test_update_endpoint(self):
        """Test the /jobs/{job_id}/update endpoint."""
        with patch('routes.job_routes.get_bandit') as mock_get_bandit:
            mock_bandit = MagicMock()
            mock_get_bandit.return_value = mock_bandit
            
            response = self.client.post(
                f"/api/jobs/{self.test_job_id}/update",
                json={
                    "url": "https://example.com/search",
                    "param": "q",
                    "family": "xss",
                    "payload_id": "xss_basic",
                    "reward": 0.8
                }
            )
            
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertTrue(data["ok"])
            
            # Verify bandit.update was called
            mock_bandit.update.assert_called_once_with(
                job_id=self.test_job_id,
                url="https://example.com/search",
                param="q",
                family="xss",
                payload_id="xss_basic",
                reward=0.8
            )
    
    def test_bandit_stats_endpoint(self):
        """Test the /jobs/{job_id}/bandit-stats endpoint."""
        with patch('routes.job_routes.get_bandit') as mock_get_bandit:
            mock_bandit = MagicMock()
            mock_bandit.get_job_stats.return_value = {
                "job_id": self.test_job_id,
                "total_combinations": 2,
                "total_pulls": 5,
                "combinations": {}
            }
            mock_get_bandit.return_value = mock_bandit
            
            response = self.client.get(f"/api/jobs/{self.test_job_id}/bandit-stats")
            
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["job_id"], self.test_job_id)
            self.assertEqual(data["total_combinations"], 2)
            self.assertEqual(data["total_pulls"], 5)


if __name__ == '__main__':
    unittest.main()
