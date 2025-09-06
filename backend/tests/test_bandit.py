"""
Unit tests for the ε-greedy bandit implementation.
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

from modules.fuzz.bandit import EpsilonGreedyBandit, PayloadTemplate, BanditState


class TestBanditState(unittest.TestCase):
    """Test BanditState functionality."""
    
    def setUp(self):
        self.state = BanditState(
            job_id="test_job",
            url="https://example.com/search",
            param="q",
            family="xss",
            payload_counts={"xss_basic": 5, "xss_img": 3},
            payload_rewards={"xss_basic": 2.5, "xss_img": 1.8},
            total_pulls=8
        )
    
    def test_get_avg_reward(self):
        """Test average reward calculation."""
        # xss_basic: 2.5 / 5 = 0.5
        self.assertEqual(self.state.get_avg_reward("xss_basic"), 0.5)
        # xss_img: 1.8 / 3 = 0.6
        self.assertEqual(self.state.get_avg_reward("xss_img"), 0.6)
        # Non-existent payload
        self.assertEqual(self.state.get_avg_reward("nonexistent"), 0.0)
    
    def test_get_confidence_interval(self):
        """Test confidence interval calculation."""
        # Test with existing payload
        lower, upper = self.state.get_confidence_interval("xss_basic")
        self.assertGreaterEqual(lower, 0.0)
        self.assertLessEqual(upper, 1.0)
        self.assertLess(lower, upper)
        
        # Test with non-existent payload
        lower, upper = self.state.get_confidence_interval("nonexistent")
        self.assertEqual(lower, 0.0)
        self.assertEqual(upper, 1.0)


class TestEpsilonGreedyBandit(unittest.TestCase):
    """Test EpsilonGreedyBandit functionality."""
    
    def setUp(self):
        # Create temporary database for testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        
        self.bandit = EpsilonGreedyBandit(
            db_path=self.temp_db.name,
            checkpoint_interval=0.1  # Very short interval for testing
        )
    
    def tearDown(self):
        # Clean up temporary database
        try:
            os.unlink(self.temp_db.name)
        except OSError:
            pass
    
    def test_initialization(self):
        """Test bandit initialization."""
        self.assertIsNotNone(self.bandit._payload_templates)
        self.assertIn("xss", self.bandit._payload_templates)
        self.assertIn("sqli", self.bandit._payload_templates)
        self.assertIn("redirect", self.bandit._payload_templates)
        
        # Check that templates have required fields
        for family, templates in self.bandit._payload_templates.items():
            for template in templates:
                self.assertIsInstance(template, PayloadTemplate)
                self.assertIsNotNone(template.id)
                self.assertIsNotNone(template.template)
                self.assertEqual(template.family, family)
    
    def test_calculate_epsilon(self):
        """Test epsilon calculation and decay."""
        # Start of job (0% progress)
        epsilon = self.bandit._calculate_epsilon("test_job", 100, 0)
        self.assertEqual(epsilon, 0.2)
        
        # Middle of job (50% progress)
        epsilon = self.bandit._calculate_epsilon("test_job", 100, 50)
        expected = 0.2 - (0.2 - 0.05) * 0.5  # 0.125
        self.assertAlmostEqual(epsilon, expected, places=3)
        
        # End of job (100% progress)
        epsilon = self.bandit._calculate_epsilon("test_job", 100, 100)
        self.assertEqual(epsilon, 0.05)
        
        # Beyond budget (should still be 0.05)
        epsilon = self.bandit._calculate_epsilon("test_job", 100, 150)
        self.assertEqual(epsilon, 0.05)
    
    def test_get_state_key(self):
        """Test state key generation."""
        key1 = self.bandit._get_state_key("job1", "https://example.com/search", "q", "xss")
        key2 = self.bandit._get_state_key("job1", "https://example.com/search", "q", "xss")
        self.assertEqual(key1, key2)
        
        # Different job should have different key
        key3 = self.bandit._get_state_key("job2", "https://example.com/search", "q", "xss")
        self.assertNotEqual(key1, key3)
        
        # Different URL should have different key
        key4 = self.bandit._get_state_key("job1", "https://example.com/login", "q", "xss")
        self.assertNotEqual(key1, key4)
    
    def test_get_state(self):
        """Test state creation and retrieval."""
        state = self.bandit._get_state("test_job", "https://example.com/search", "q", "xss")
        
        self.assertEqual(state.job_id, "test_job")
        self.assertEqual(state.url, "https://example.com/search")
        self.assertEqual(state.param, "q")
        self.assertEqual(state.family, "xss")
        self.assertEqual(state.total_pulls, 0)
        self.assertEqual(len(state.payload_counts), 0)
        self.assertEqual(len(state.payload_rewards), 0)
        
        # Same parameters should return same state
        state2 = self.bandit._get_state("test_job", "https://example.com/search", "q", "xss")
        self.assertIs(state, state2)
    
    def test_select_exploration(self):
        """Test payload selection in exploration mode (high epsilon)."""
        # Force exploration by setting high epsilon
        with patch.object(self.bandit, '_calculate_epsilon', return_value=1.0):
            payload_id, reward_estimate = self.bandit.select(
                "test_job", "https://example.com/search", "q", "xss", 100, 0
            )
        
        # Should select a valid payload
        self.assertIsNotNone(payload_id)
        self.assertIn(payload_id, [t.id for t in self.bandit._payload_templates["xss"]])
        self.assertEqual(reward_estimate, 0.0)  # No prior data
    
    def test_select_exploitation(self):
        """Test payload selection in exploitation mode (low epsilon)."""
        # First, update state with some rewards
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_basic", 0.8)
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_img", 0.3)
        
        # Force exploitation by setting low epsilon
        with patch.object(self.bandit, '_calculate_epsilon', return_value=0.0):
            payload_id, reward_estimate = self.bandit.select(
                "test_job", "https://example.com/search", "q", "xss", 100, 50
            )
        
        # Should select the best payload (xss_basic with 0.8 reward)
        self.assertEqual(payload_id, "xss_basic")
        self.assertEqual(reward_estimate, 0.8)
    
    def test_update(self):
        """Test bandit state update."""
        # Initial state should be empty
        state = self.bandit._get_state("test_job", "https://example.com/search", "q", "xss")
        self.assertEqual(state.total_pulls, 0)
        self.assertEqual(len(state.payload_counts), 0)
        
        # Update with reward
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_basic", 0.7)
        
        # State should be updated
        self.assertEqual(state.total_pulls, 1)
        self.assertEqual(state.payload_counts["xss_basic"], 1)
        self.assertEqual(state.payload_rewards["xss_basic"], 0.7)
        
        # Update again
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_basic", 0.3)
        
        # State should be updated
        self.assertEqual(state.total_pulls, 2)
        self.assertEqual(state.payload_counts["xss_basic"], 2)
        self.assertEqual(state.payload_rewards["xss_basic"], 1.0)  # 0.7 + 0.3
    
    def test_get_stats(self):
        """Test statistics retrieval."""
        # Update state with some data
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_basic", 0.8)
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_img", 0.4)
        
        stats = self.bandit.get_stats("test_job", "https://example.com/search", "q", "xss")
        
        self.assertEqual(stats["job_id"], "test_job")
        self.assertEqual(stats["url"], "https://example.com/search")
        self.assertEqual(stats["param"], "q")
        self.assertEqual(stats["family"], "xss")
        self.assertEqual(stats["total_pulls"], 2)
        
        # Check payload stats
        self.assertIn("xss_basic", stats["payload_stats"])
        self.assertIn("xss_img", stats["payload_stats"])
        
        xss_basic_stats = stats["payload_stats"]["xss_basic"]
        self.assertEqual(xss_basic_stats["count"], 1)
        self.assertEqual(xss_basic_stats["total_reward"], 0.8)
        self.assertEqual(xss_basic_stats["avg_reward"], 0.8)
    
    def test_get_job_stats(self):
        """Test job-level statistics."""
        # Update multiple combinations
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_basic", 0.8)
        self.bandit.update("test_job", "https://example.com/login", "username", "sqli", "sqli_union", 0.6)
        
        stats = self.bandit.get_job_stats("test_job")
        
        self.assertEqual(stats["job_id"], "test_job")
        self.assertEqual(stats["total_combinations"], 2)
        self.assertEqual(stats["total_pulls"], 2)
        self.assertEqual(len(stats["combinations"]), 2)
    
    def test_cleanup_job(self):
        """Test job cleanup."""
        # Create some state
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_basic", 0.8)
        self.bandit.update("other_job", "https://example.com/login", "username", "sqli", "sqli_union", 0.6)
        
        # Verify state exists
        self.assertEqual(len(self.bandit._state), 2)
        
        # Cleanup one job
        self.bandit.cleanup_job("test_job")
        
        # Only other job should remain
        self.assertEqual(len(self.bandit._state), 1)
        remaining_state = list(self.bandit._state.values())[0]
        self.assertEqual(remaining_state.job_id, "other_job")
    
    def test_database_persistence(self):
        """Test database persistence and loading."""
        # Create some state
        self.bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_basic", 0.8)
        
        # Force checkpoint
        self.bandit.force_checkpoint()
        
        # Create new bandit instance (should load from database)
        new_bandit = EpsilonGreedyBandit(db_path=self.temp_db.name)
        
        # Should have loaded the state
        self.assertEqual(len(new_bandit._state), 1)
        
        state = list(new_bandit._state.values())[0]
        self.assertEqual(state.job_id, "test_job")
        self.assertEqual(state.total_pulls, 1)
        self.assertEqual(state.payload_rewards["xss_basic"], 0.8)
    
    def test_graceful_database_failure(self):
        """Test graceful handling of database failures."""
        # Create bandit with invalid database path
        with patch('sqlite3.connect', side_effect=Exception("Database error")):
            bandit = EpsilonGreedyBandit(db_path="/invalid/path.db")
        
        # Should still work in memory-only mode
        bandit.update("test_job", "https://example.com/search", "q", "xss", "xss_basic", 0.8)
        payload_id, reward_estimate = bandit.select(
            "test_job", "https://example.com/search", "q", "xss", 100, 0
        )
        
        self.assertIsNotNone(payload_id)
        self.assertEqual(reward_estimate, 0.8)
    
    def test_unknown_family(self):
        """Test handling of unknown vulnerability families."""
        # Should handle unknown family gracefully
        payload_id, reward_estimate = self.bandit.select(
            "test_job", "https://example.com/search", "q", "unknown_family", 100, 0
        )
        
        self.assertEqual(payload_id, "fallback")
        self.assertEqual(reward_estimate, 0.0)
    
    def test_concurrent_access(self):
        """Test thread safety of bandit operations."""
        import threading
        import time
        
        results = []
        errors = []
        
        def worker(worker_id):
            try:
                for i in range(10):
                    # Update state
                    self.bandit.update(
                        f"job_{worker_id}", 
                        f"https://example.com/search_{i}", 
                        "q", 
                        "xss", 
                        "xss_basic", 
                        0.5
                    )
                    
                    # Select payload
                    payload_id, reward = self.bandit.select(
                        f"job_{worker_id}", 
                        f"https://example.com/search_{i}", 
                        "q", 
                        "xss", 
                        100, 
                        i
                    )
                    
                    results.append((worker_id, i, payload_id, reward))
                    time.sleep(0.001)  # Small delay to increase chance of race conditions
                    
            except Exception as e:
                errors.append(e)
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Should have no errors
        self.assertEqual(len(errors), 0)
        
        # Should have expected number of results
        self.assertEqual(len(results), 50)  # 5 workers * 10 iterations


if __name__ == '__main__':
    unittest.main()
