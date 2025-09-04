"""
Training Data Generator for ML Models
Generates realistic training data for vulnerability prediction and payload scoring
"""

import random
import json
import logging
from typing import List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class TrainingDataGenerator:
    """Generate training data for ML models"""
    
    def __init__(self):
        self.endpoint_templates = [
            # Search endpoints (high XSS risk)
            {"url": "http://example.com/search", "param": "q", "method": "GET", "vulnerability_type": "xss"},
            {"url": "http://example.com/api/search", "param": "query", "method": "GET", "vulnerability_type": "xss"},
            {"url": "http://example.com/find", "param": "term", "method": "GET", "vulnerability_type": "xss"},
            
            # Login endpoints (high SQLi risk)
            {"url": "http://example.com/login", "param": "email", "method": "POST", "vulnerability_type": "sqli"},
            {"url": "http://example.com/api/auth", "param": "username", "method": "POST", "vulnerability_type": "sqli"},
            {"url": "http://example.com/rest/user/login", "param": "email", "method": "POST", "vulnerability_type": "sqli"},
            
            # Product endpoints (medium SQLi risk)
            {"url": "http://example.com/products", "param": "id", "method": "GET", "vulnerability_type": "sqli"},
            {"url": "http://example.com/api/products", "param": "productId", "method": "GET", "vulnerability_type": "sqli"},
            {"url": "http://example.com/rest/products/search", "param": "q", "method": "GET", "vulnerability_type": "sqli"},
            
            # Admin endpoints (high risk)
            {"url": "http://example.com/admin", "param": "user", "method": "GET", "vulnerability_type": "sqli"},
            {"url": "http://example.com/api/admin/users", "param": "role", "method": "GET", "vulnerability_type": "sqli"},
            
            # File upload endpoints (high RCE/LFI risk)
            {"url": "http://example.com/upload", "param": "file", "method": "POST", "vulnerability_type": "rce"},
            {"url": "http://example.com/api/upload", "param": "filename", "method": "POST", "vulnerability_type": "lfi"},
            
            # Redirect endpoints
            {"url": "http://example.com/redirect", "param": "url", "method": "GET", "vulnerability_type": "redirect"},
            {"url": "http://example.com/callback", "param": "return_url", "method": "GET", "vulnerability_type": "redirect"},
            
            # Safe endpoints
            {"url": "http://example.com/about", "param": "id", "method": "GET", "vulnerability_type": "none"},
            {"url": "http://example.com/contact", "param": "id", "method": "GET", "vulnerability_type": "none"},
        ]
        
        self.payload_effectiveness_data = [
            # XSS payloads with effectiveness scores
            {"payload": "<script>alert('XSS')</script>", "vulnerability_type": "xss", "effectiveness_score": 0.8},
            {"payload": "<img src=x onerror=alert('XSS')>", "vulnerability_type": "xss", "effectiveness_score": 0.7},
            {"payload": "javascript:alert('XSS')", "vulnerability_type": "xss", "effectiveness_score": 0.6},
            {"payload": "<svg onload=alert('XSS')>", "vulnerability_type": "xss", "effectiveness_score": 0.9},
            
            # SQLi payloads with effectiveness scores
            {"payload": "' OR '1'='1", "vulnerability_type": "sqli", "effectiveness_score": 0.9},
            {"payload": "'; DROP TABLE users--", "vulnerability_type": "sqli", "effectiveness_score": 0.8},
            {"payload": "' UNION SELECT NULL--", "vulnerability_type": "sqli", "effectiveness_score": 0.7},
            {"payload": "admin'--", "vulnerability_type": "sqli", "effectiveness_score": 0.6},
            
            # RCE payloads with effectiveness scores
            {"payload": "; ls -la", "vulnerability_type": "rce", "effectiveness_score": 0.8},
            {"payload": "| whoami", "vulnerability_type": "rce", "effectiveness_score": 0.7},
            {"payload": "&& cat /etc/passwd", "vulnerability_type": "rce", "effectiveness_score": 0.9},
            {"payload": "; id", "vulnerability_type": "rce", "effectiveness_score": 0.6},
            
            # LFI payloads with effectiveness scores
            {"payload": "../../../etc/passwd", "vulnerability_type": "lfi", "effectiveness_score": 0.9},
            {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "vulnerability_type": "lfi", "effectiveness_score": 0.8},
            {"payload": "....//....//....//etc/passwd", "vulnerability_type": "lfi", "effectiveness_score": 0.7},
            
            # Redirect payloads with effectiveness scores
            {"payload": "https://evil.com", "vulnerability_type": "redirect", "effectiveness_score": 0.8},
            {"payload": "//evil.com", "vulnerability_type": "redirect", "effectiveness_score": 0.7},
            {"payload": "javascript:alert('XSS')", "vulnerability_type": "redirect", "effectiveness_score": 0.6},
        ]
    
    def generate_endpoint_training_data(self, num_samples: int = 1000) -> List[Dict[str, Any]]:
        """Generate training data for endpoint vulnerability prediction"""
        training_data = []
        
        for _ in range(num_samples):
            # Select a random template
            template = random.choice(self.endpoint_templates)
            
            # Create variations
            endpoint = {
                "url": self._generate_url_variation(template["url"]),
                "path": self._extract_path(template["url"]),
                "param": template["param"],
                "method": template["method"],
                "vulnerability_type": template["vulnerability_type"],
                "content_type": self._generate_content_type(template["vulnerability_type"]),
                "status": self._generate_status_code(template["vulnerability_type"]),
            }
            
            training_data.append(endpoint)
        
        logger.info(f"✅ Generated {len(training_data)} endpoint training samples")
        return training_data
    
    def generate_payload_training_data(self, num_samples: int = 2000) -> List[Dict[str, Any]]:
        """Generate training data for payload effectiveness scoring"""
        training_data = []
        
        for _ in range(num_samples):
            # Select a random payload template
            payload_template = random.choice(self.payload_effectiveness_data)
            
            # Create endpoint context
            endpoint_template = random.choice(self.endpoint_templates)
            endpoint = {
                "url": self._generate_url_variation(endpoint_template["url"]),
                "path": self._extract_path(endpoint_template["url"]),
                "param": endpoint_template["param"],
                "method": endpoint_template["method"],
                "content_type": self._generate_content_type(endpoint_template["vulnerability_type"]),
                "status": self._generate_status_code(endpoint_template["vulnerability_type"]),
            }
            
            # Add some noise to effectiveness score
            base_score = payload_template["effectiveness_score"]
            noise = random.uniform(-0.1, 0.1)
            effectiveness_score = max(0.0, min(1.0, base_score + noise))
            
            training_sample = {
                "payload": payload_template["payload"],
                "endpoint": endpoint,
                "vulnerability_type": payload_template["vulnerability_type"],
                "effectiveness_score": effectiveness_score
            }
            
            training_data.append(training_sample)
        
        logger.info(f"✅ Generated {len(training_data)} payload training samples")
        return training_data
    
    def _generate_url_variation(self, base_url: str) -> str:
        """Generate URL variations"""
        variations = [
            base_url,
            base_url.replace("example.com", "test.com"),
            base_url.replace("example.com", "demo.com"),
            base_url.replace("example.com", "app.com"),
            base_url.replace("http://", "https://"),
        ]
        return random.choice(variations)
    
    def _extract_path(self, url: str) -> str:
        """Extract path from URL"""
        return url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
    
    def _generate_content_type(self, vuln_type: str) -> str:
        """Generate realistic content types based on vulnerability type"""
        content_types = {
            "xss": ["text/html; charset=utf-8", "application/json; charset=utf-8"],
            "sqli": ["application/json; charset=utf-8", "text/html; charset=utf-8"],
            "rce": ["text/plain; charset=utf-8", "text/html; charset=utf-8"],
            "lfi": ["text/plain; charset=utf-8", "text/html; charset=utf-8"],
            "redirect": ["text/html; charset=utf-8"],
            "none": ["text/html; charset=utf-8", "application/json; charset=utf-8"]
        }
        return random.choice(content_types.get(vuln_type, ["text/html; charset=utf-8"]))
    
    def _generate_status_code(self, vuln_type: str) -> int:
        """Generate realistic status codes based on vulnerability type"""
        status_codes = {
            "xss": [200, 200, 200, 400],  # XSS often returns 200
            "sqli": [200, 500, 401, 403],  # SQLi often causes 500 errors
            "rce": [200, 500, 403],  # RCE can cause various responses
            "lfi": [200, 404, 403],  # LFI often returns 200 with content
            "redirect": [200, 301, 302],  # Redirects return redirect codes
            "none": [200, 200, 200, 404]  # Safe endpoints mostly return 200
        }
        return random.choice(status_codes.get(vuln_type, [200]))
    
    def save_training_data(self, endpoint_data: List[Dict[str, Any]], 
                          payload_data: List[Dict[str, Any]], 
                          output_dir: str = "data/ml/training"):
        """Save training data to files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save endpoint training data
        endpoint_file = output_path / "endpoint_training_data.json"
        with open(endpoint_file, 'w') as f:
            json.dump(endpoint_data, f, indent=2)
        
        # Save payload training data
        payload_file = output_path / "payload_training_data.json"
        with open(payload_file, 'w') as f:
            json.dump(payload_data, f, indent=2)
        
        logger.info(f"✅ Saved training data to {output_dir}")
        logger.info(f"   - Endpoint data: {len(endpoint_data)} samples")
        logger.info(f"   - Payload data: {len(payload_data)} samples")

def generate_training_data():
    """Generate and save training data"""
    generator = TrainingDataGenerator()
    
    # Generate training data
    endpoint_data = generator.generate_endpoint_training_data(1000)
    payload_data = generator.generate_payload_training_data(2000)
    
    # Save to files
    generator.save_training_data(endpoint_data, payload_data)
    
    return endpoint_data, payload_data

if __name__ == "__main__":
    generate_training_data()
