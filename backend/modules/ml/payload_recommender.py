"""
Real ML-based Payload Recommender
Recommends and scores payloads based on endpoint characteristics and vulnerability type
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score
import joblib
import logging
from typing import List, Dict, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

class PayloadRecommender:
    """Real ML model to recommend and score payloads for fuzzing"""
    
    def __init__(self, model_path: str = "models/payload_recommender.joblib"):
        self.model_path = Path(model_path)
        self.model = None
        
        # Real payload database with effectiveness scores
        self.payload_database = {
            "xss": [
                {"payload": "<script>alert('XSS')</script>", "base_score": 0.8, "context": "basic"},
                {"payload": "<img src=x onerror=alert('XSS')>", "base_score": 0.7, "context": "img_tag"},
                {"payload": "javascript:alert('XSS')", "base_score": 0.6, "context": "javascript_url"},
                {"payload": "<svg onload=alert('XSS')>", "base_score": 0.9, "context": "svg_tag"},
                {"payload": "';alert('XSS');//", "base_score": 0.5, "context": "quote_escape"},
                {"payload": "<iframe src=javascript:alert('XSS')></iframe>", "base_score": 0.8, "context": "iframe"},
                {"payload": "<body onload=alert('XSS')>", "base_score": 0.7, "context": "body_tag"},
                {"payload": "<input onfocus=alert('XSS') autofocus>", "base_score": 0.6, "context": "input_tag"},
            ],
            "sqli": [
                {"payload": "' OR '1'='1", "base_score": 0.9, "context": "boolean_based"},
                {"payload": "'; DROP TABLE users--", "base_score": 0.8, "context": "union_based"},
                {"payload": "' UNION SELECT NULL--", "base_score": 0.7, "context": "union_based"},
                {"payload": "' OR 1=1#", "base_score": 0.8, "context": "boolean_based"},
                {"payload": "admin'--", "base_score": 0.6, "context": "comment_based"},
                {"payload": "' OR 'x'='x", "base_score": 0.7, "context": "boolean_based"},
                {"payload": "1' OR '1'='1' /*", "base_score": 0.8, "context": "comment_based"},
                {"payload": "' UNION SELECT 1,2,3--", "base_score": 0.6, "context": "union_based"},
            ],
            "rce": [
                {"payload": "; ls -la", "base_score": 0.8, "context": "command_injection"},
                {"payload": "| whoami", "base_score": 0.7, "context": "pipe_injection"},
                {"payload": "&& cat /etc/passwd", "base_score": 0.9, "context": "logical_and"},
                {"payload": "; id", "base_score": 0.6, "context": "command_injection"},
                {"payload": "| uname -a", "base_score": 0.5, "context": "pipe_injection"},
                {"payload": "&& whoami", "base_score": 0.7, "context": "logical_and"},
                {"payload": "; cat /etc/hosts", "base_score": 0.8, "context": "command_injection"},
                {"payload": "| ps aux", "base_score": 0.6, "context": "pipe_injection"},
            ],
            "lfi": [
                {"payload": "../../../etc/passwd", "base_score": 0.9, "context": "path_traversal"},
                {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "base_score": 0.8, "context": "windows_path"},
                {"payload": "....//....//....//etc/passwd", "base_score": 0.7, "context": "double_encoding"},
                {"payload": "..%2F..%2F..%2Fetc%2Fpasswd", "base_score": 0.6, "context": "url_encoding"},
                {"payload": "..%252F..%252F..%252Fetc%252Fpasswd", "base_score": 0.5, "context": "double_encoding"},
                {"payload": "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts", "base_score": 0.7, "context": "windows_double"},
            ],
            "redirect": [
                {"payload": "https://evil.com", "base_score": 0.8, "context": "external_url"},
                {"payload": "//evil.com", "base_score": 0.7, "context": "protocol_relative"},
                {"payload": "javascript:alert('XSS')", "base_score": 0.6, "context": "javascript_url"},
                {"payload": "data:text/html,<script>alert('XSS')</script>", "base_score": 0.5, "context": "data_url"},
                {"payload": "http://evil.com", "base_score": 0.8, "context": "http_url"},
                {"payload": "ftp://evil.com", "base_score": 0.4, "context": "ftp_url"},
            ]
        }
    
    def extract_payload_features(self, payload: str, endpoint: Dict[str, Any], vuln_type: str) -> np.ndarray:
        """Extract features for payload scoring"""
        features = []
        
        # Payload characteristics
        features.append(len(payload))
        features.append(payload.count("'"))
        features.append(payload.count('"'))
        features.append(payload.count(";"))
        features.append(payload.count("|"))
        features.append(payload.count("&"))
        features.append(payload.count("<"))
        features.append(payload.count(">"))
        features.append(payload.count("/"))
        features.append(payload.count("\\"))
        
        # Endpoint context features
        url = endpoint.get("url", "")
        path = endpoint.get("path", "")
        param = endpoint.get("param", "")
        method = endpoint.get("method", "GET")
        
        # URL/Path features
        features.append(len(url))
        features.append(path.count("/"))
        features.append(1 if "search" in path.lower() else 0)
        features.append(1 if "login" in path.lower() else 0)
        features.append(1 if "admin" in path.lower() else 0)
        features.append(1 if "upload" in path.lower() else 0)
        
        # Parameter features
        features.append(1 if "id" in param.lower() else 0)
        features.append(1 if "search" in param.lower() or "q" in param.lower() else 0)
        features.append(1 if "email" in param.lower() else 0)
        features.append(1 if "file" in param.lower() else 0)
        
        # Method features
        features.append(1 if method == "GET" else 0)
        features.append(1 if method == "POST" else 0)
        
        # Vulnerability type features
        vuln_type_features = [0] * 5
        vuln_type_map = {"xss": 0, "sqli": 1, "rce": 2, "lfi": 3, "redirect": 4}
        if vuln_type in vuln_type_map:
            vuln_type_features[vuln_type_map[vuln_type]] = 1
        features.extend(vuln_type_features)
        
        return np.array(features)
    
    def train(self, training_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """Train the payload scoring model"""
        logger.info(f"🚀 Training payload recommender with {len(training_data)} samples")
        
        # Prepare training data
        X = []
        y = []
        
        for sample in training_data:
            payload = sample.get("payload", "")
            endpoint = sample.get("endpoint", {})
            vuln_type = sample.get("vulnerability_type", "none")
            effectiveness = sample.get("effectiveness_score", 0.5)
            
            features = self.extract_payload_features(payload, endpoint, vuln_type)
            X.append(features)
            y.append(effectiveness)
        
        X = np.array(X)
        y = np.array(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train model
        self.model = RandomForestRegressor(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        mse = mean_squared_error(y_test, y_pred)
        r2 = r2_score(y_test, y_pred)
        
        logger.info(f"✅ Model trained with MSE: {mse:.3f}, R²: {r2:.3f}")
        
        # Save model
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        
        return {
            "mse": mse,
            "r2_score": r2,
            "training_samples": len(training_data),
            "test_samples": len(X_test)
        }
    
    def recommend_payloads(self, endpoint: Dict[str, Any], vuln_type: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Recommend top payloads for an endpoint"""
        if vuln_type not in self.payload_database:
            return []
        
        recommendations = []
        
        for payload_info in self.payload_database[vuln_type]:
            payload = payload_info["payload"]
            base_score = payload_info["base_score"]
            context = payload_info["context"]
            
            # Extract features for scoring
            features = self.extract_payload_features(payload, endpoint, vuln_type)
            features = features.reshape(1, -1)
            
            # Get ML-predicted score
            if self.model is not None:
                try:
                    ml_score = self.model.predict(features)[0]
                except:
                    ml_score = base_score
            else:
                ml_score = base_score
            
            # Combine base score with ML prediction
            final_score = (base_score * 0.4) + (ml_score * 0.6)
            
            recommendation = {
                "payload": payload,
                "score": float(final_score),
                "base_score": base_score,
                "ml_score": float(ml_score),
                "context": context,
                "vulnerability_type": vuln_type
            }
            
            recommendations.append(recommendation)
        
        # Sort by score and return top_k
        recommendations.sort(key=lambda x: x["score"], reverse=True)
        return recommendations[:top_k]
    
    def load_model(self) -> bool:
        """Load trained model from disk"""
        try:
            if self.model_path.exists():
                self.model = joblib.load(self.model_path)
                logger.info("✅ Loaded payload recommender model")
                return True
            else:
                logger.warning("⚠️ No trained model found, using base scores")
                return False
        except Exception as e:
            logger.error(f"❌ Error loading model: {e}")
            return False
