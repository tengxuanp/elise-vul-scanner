"""
Real ML-Based Fuzzing API
Implements the flow: Crawl → ML Predict → User Choose → Real Fuzz
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any, Optional
import logging
import sys
import os
from pathlib import Path

# Add backend to path for imports
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.ml.vulnerability_predictor import VulnerabilityPredictor
from modules.ml.payload_recommender import PayloadRecommender
from modules.real_fuzzer import RealHTTPFuzzer
from modules.ml.training_data_generator import TrainingDataGenerator

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(tags=["ml-fuzzing"])

# Initialize ML components
vulnerability_predictor = VulnerabilityPredictor()
payload_recommender = PayloadRecommender()
real_fuzzer = RealHTTPFuzzer()

@router.post("/ml-predict")
async def ml_predict_vulnerabilities(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 2: ML predicts vulnerability types and recommends payloads for discovered endpoints
    """
    try:
        endpoints = request.get("endpoints", [])
        if not endpoints:
            raise HTTPException(400, "No endpoints provided")
        
        logger.info(f"🧠 ML Prediction: Analyzing {len(endpoints)} endpoints")
        
        # Step 1: Predict vulnerability types
        predictions = vulnerability_predictor.predict(endpoints)
        
        # Step 2: Recommend payloads for each endpoint
        recommendations = []
        for prediction in predictions:
            endpoint = prediction["endpoint"]
            predicted_type = prediction["predicted_type"]
            confidence = prediction["confidence"]
            
            # Skip if no vulnerability predicted
            if predicted_type == "none":
                continue
            
            # Get payload recommendations
            payload_recs = payload_recommender.recommend_payloads(
                endpoint, predicted_type, top_k=5
            )
            
            recommendation = {
                "endpoint": endpoint,
                "predicted_vulnerability": predicted_type,
                "confidence": confidence,
                "recommended_payloads": payload_recs,
                "total_payloads": len(payload_recs)
            }
            
            recommendations.append(recommendation)
        
        # Sort by confidence
        recommendations.sort(key=lambda x: x["confidence"], reverse=True)
        
        response = {
            "status": "success",
            "message": f"ML analysis completed for {len(endpoints)} endpoints",
            "total_endpoints": len(endpoints),
            "vulnerable_endpoints": len(recommendations),
            "recommendations": recommendations,
            "ml_models": {
                "vulnerability_predictor": "loaded" if vulnerability_predictor.model else "default",
                "payload_recommender": "loaded" if payload_recommender.model else "default"
            }
        }
        
        logger.info(f"✅ ML Prediction: Found {len(recommendations)} potentially vulnerable endpoints")
        return response
        
    except Exception as e:
        logger.error(f"❌ ML Prediction failed: {e}")
        raise HTTPException(500, f"ML prediction failed: {e}")

@router.post("/ml-fuzz")
async def ml_fuzz_endpoints(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 3: Real fuzzing with ML-recommended payloads
    """
    try:
        fuzz_requests = request.get("fuzz_requests", [])
        if not fuzz_requests:
            raise HTTPException(400, "No fuzz requests provided")
        
        logger.info(f"🎯 Real Fuzzing: Testing {len(fuzz_requests)} endpoint-payload combinations")
        
        results = []
        vulnerabilities_found = 0
        
        for fuzz_request in fuzz_requests:
            endpoint = fuzz_request["endpoint"]
            payload = fuzz_request["payload"]
            
            # Perform real HTTP fuzzing
            fuzz_result = real_fuzzer.fuzz_endpoint(endpoint, payload)
            
            # Convert to API response format
            result = {
                "endpoint": {
                    "url": fuzz_result.endpoint["url"],
                    "param": fuzz_result.endpoint["param"],
                    "method": fuzz_result.endpoint["method"]
                },
                "payload": fuzz_result.payload,
                "response_status": fuzz_result.response_status,
                "response_time": fuzz_result.response_time,
                "response_length": fuzz_result.response_length,
                "vulnerability_detected": fuzz_result.vulnerability_detected,
                "confidence_score": fuzz_result.confidence_score,
                "evidence": fuzz_result.detection_evidence,
                "response_preview": fuzz_result.response_body[:200] + "..." if len(fuzz_result.response_body) > 200 else fuzz_result.response_body
            }
            
            results.append(result)
            
            if fuzz_result.vulnerability_detected:
                vulnerabilities_found += 1
        
        # Sort by confidence score
        results.sort(key=lambda x: x["confidence_score"], reverse=True)
        
        response = {
            "status": "success",
            "message": f"Real fuzzing completed for {len(fuzz_requests)} requests",
            "total_requests": len(fuzz_requests),
            "vulnerabilities_found": vulnerabilities_found,
            "results": results,
            "summary": {
                "total_tested": len(fuzz_requests),
                "vulnerabilities_detected": vulnerabilities_found,
                "success_rate": vulnerabilities_found / len(fuzz_requests) if fuzz_requests else 0,
                "avg_confidence": sum(r["confidence_score"] for r in results) / len(results) if results else 0
            }
        }
        
        logger.info(f"✅ Real Fuzzing: Found {vulnerabilities_found} vulnerabilities out of {len(fuzz_requests)} tests")
        return response
        
    except Exception as e:
        logger.error(f"❌ Real fuzzing failed: {e}")
        raise HTTPException(500, f"Real fuzzing failed: {e}")

@router.post("/train-models")
async def train_ml_models(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Train the ML models with generated training data
    """
    try:
        logger.info("🚀 Training ML models...")
        
        # Generate training data
        generator = TrainingDataGenerator()
        endpoint_data = generator.generate_endpoint_training_data(1000)
        payload_data = generator.generate_payload_training_data(2000)
        
        # Train vulnerability predictor
        logger.info("🧠 Training vulnerability predictor...")
        vuln_results = vulnerability_predictor.train(endpoint_data)
        
        # Train payload recommender
        logger.info("🎯 Training payload recommender...")
        payload_results = payload_recommender.train(payload_data)
        
        response = {
            "status": "success",
            "message": "ML models trained successfully",
            "training_results": {
                "vulnerability_predictor": vuln_results,
                "payload_recommender": payload_results
            },
            "training_data": {
                "endpoint_samples": len(endpoint_data),
                "payload_samples": len(payload_data)
            }
        }
        
        logger.info("✅ ML models training completed")
        return response
        
    except Exception as e:
        logger.error(f"❌ Model training failed: {e}")
        raise HTTPException(500, f"Model training failed: {e}")

@router.get("/ml-status")
async def ml_status():
    """Get status of ML models"""
    return {
        "status": "healthy",
        "models": {
            "vulnerability_predictor": {
                "loaded": vulnerability_predictor.model is not None,
                "path": str(vulnerability_predictor.model_path)
            },
            "payload_recommender": {
                "loaded": payload_recommender.model is not None,
                "path": str(payload_recommender.model_path)
            }
        },
        "fuzzer": {
            "type": "real_http_fuzzer",
            "timeout": real_fuzzer.timeout,
            "max_retries": real_fuzzer.max_retries
        }
    }
