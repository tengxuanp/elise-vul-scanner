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
    Step 2: ML predicts vulnerability types and recommends payloads for discovered endpoints.
    Now uses target-based analysis with attackability gates.
    """
    try:
        endpoints = request.get("endpoints", [])
        if not endpoints:
            raise HTTPException(400, "No endpoints provided")
        
        logger.info(f"🧠 ML Prediction: Analyzing {len(endpoints)} endpoints")
        
        # Import target, gate, and probe modules
        from modules.targets import enumerate_targets
        from modules.gates import is_attackable
        from modules.probes.engine import run_probes, ProbeResult
        from modules.ml.enhanced_features import extract_features_v1
        
        # Step 1: Convert endpoints to targets
        all_targets = []
        endpoint_analyses = []
        
        for endpoint in endpoints:
            # Enumerate targets for this endpoint
            targets = enumerate_targets(endpoint)
            
            # Filter targets through attackability gates
            attackable_targets = [t for t in targets if is_attackable(t)]
            
            # Create endpoint analysis
            analysis = {
                "endpoint": endpoint,
                "total_targets": len(targets),
                "attackable_targets": len(attackable_targets),
                "targets": [
                    {
                        "param": t.param,
                        "param_in": t.param_in,
                        "attackable": True
                    }
                    for t in attackable_targets
                ]
            }
            
            # If no attackable targets, mark as not applicable
            if not attackable_targets:
                analysis["analysis"] = "not_applicable"
                analysis["reason"] = "No attackable parameters found"
                logger.info(f"🎯 Endpoint {endpoint.get('method', 'GET')} {endpoint.get('path', '')} - not applicable (no attackable targets)")
            else:
                analysis["analysis"] = "applicable"
                all_targets.extend(attackable_targets)
                logger.info(f"🎯 Endpoint {endpoint.get('method', 'GET')} {endpoint.get('path', '')} - {len(attackable_targets)} attackable targets")
            
            endpoint_analyses.append(analysis)
        
        # Step 2: Run probes and apply hard gates
        recommendations = []
        if all_targets:
            logger.info(f"🔍 Running probes on {len(all_targets)} attackable targets")
            
            # Check if ML models are available
            if not vulnerability_predictor.model:
                raise HTTPException(503, "ML models not available - service unavailable")
            
            ml_eligible_targets = []
            
            for target in all_targets:
                # Run probes first
                probe_result = run_probes(target)
                logger.info(f"🔍 Probe results for {target.param}: XSS={probe_result.xss_context}, Redirect={probe_result.redirect_influence}, SQLi={probe_result.sqli_error_based}")
                
                # Apply hard gates
                xss_allowed = probe_result.xss_context in {"html", "attr", "js_string"}
                redirect_allowed = probe_result.redirect_influence
                sqli_allowed = (probe_result.sqli_error_based or 
                              probe_result.sqli_boolean_delta > 0.08 or 
                              probe_result.sqli_time_based)
                
                # Check if any family passes preconditions
                if not (xss_allowed or redirect_allowed or sqli_allowed):
                    logger.info(f"🚫 Target {target.param} - no families pass hard gates")
                    continue
                
                # Target is eligible for ML
                ml_eligible_targets.append((target, probe_result))
                logger.info(f"✅ Target {target.param} - eligible for ML (XSS={xss_allowed}, Redirect={redirect_allowed}, SQLi={sqli_allowed})")
            
            # Step 3: ML prediction for eligible targets
            if ml_eligible_targets:
                logger.info(f"🧠 Running ML prediction on {len(ml_eligible_targets)} probe-eligible targets")
                
                for target, probe_result in ml_eligible_targets:
                    # Build enhanced features with probe results
                    endpoint_dict = {
                        "url": target.url,
                        "path": target.path,
                        "method": target.method,
                        "param_locs": {target.param_in: [target.param]},
                        "content_type": target.content_type
                    }
                    param_dict = {"name": target.param}
                    probe_dict = {
                        "xss_context": probe_result.xss_context,
                        "redirect_influence": probe_result.redirect_influence,
                        "sqli_error_based": probe_result.sqli_error_based,
                        "sqli_error_db": probe_result.sqli_error_db,
                        "sqli_boolean_delta": probe_result.sqli_boolean_delta,
                        "sqli_time_based": probe_result.sqli_time_based
                    }
                    
                    # Extract enhanced features
                    features = extract_features_v1(endpoint_dict, param_dict, probe_result=probe_dict)
                    
                    # Convert to endpoint format for ML prediction
                    target_endpoint = {
                        "url": target.url,
                        "path": target.path,
                        "method": target.method,
                        "param_names": [target.param],
                        "status": target.status,
                        "content_type": target.content_type,
                        "features": features  # Include enhanced features
                    }
                    
                    # Predict vulnerability types
                    predictions = vulnerability_predictor.predict([target_endpoint])
                    
                    if predictions:
                        prediction = predictions[0]
                        predicted_type = prediction["predicted_type"]
                        confidence = prediction["confidence"]
                        
                        # Skip if no vulnerability predicted
                        if predicted_type == "none":
                            continue
                        
                        # Get payload recommendations
                        payload_recs = payload_recommender.recommend_payloads(
                            target_endpoint, predicted_type, top_k=5
                        )
                        
                        recommendation = {
                            "target": {
                                "url": target.url,
                                "path": target.path,
                                "method": target.method,
                                "param": target.param,
                                "param_in": target.param_in,
                                "status": target.status,
                                "content_type": target.content_type
                            },
                            "predicted_vulnerability": predicted_type,
                            "confidence": confidence,
                            "recommended_payloads": payload_recs,
                            "total_payloads": len(payload_recs),
                            "probe_results": {
                                "xss_context": probe_result.xss_context,
                                "redirect_influence": probe_result.redirect_influence,
                                "sqli_error_based": probe_result.sqli_error_based,
                                "sqli_error_db": probe_result.sqli_error_db,
                                "sqli_boolean_delta": probe_result.sqli_boolean_delta,
                                "sqli_time_based": probe_result.sqli_time_based
                            }
                        }
                        
                        recommendations.append(recommendation)
            else:
                logger.info("🚫 No targets passed hard gates - skipping ML prediction")
        
        # Sort by confidence
        recommendations.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Calculate statistics
        total_endpoints = len(endpoints)
        applicable_endpoints = sum(1 for analysis in endpoint_analyses if analysis["analysis"] == "applicable")
        not_applicable_endpoints = total_endpoints - applicable_endpoints
        total_targets = sum(analysis["total_targets"] for analysis in endpoint_analyses)
        attackable_targets = sum(analysis["attackable_targets"] for analysis in endpoint_analyses)
        
        response = {
            "status": "success",
            "message": f"ML analysis completed for {total_endpoints} endpoints, {attackable_targets} attackable targets",
            "statistics": {
                "total_endpoints": total_endpoints,
                "applicable_endpoints": applicable_endpoints,
                "not_applicable_endpoints": not_applicable_endpoints,
                "total_targets": total_targets,
                "attackable_targets": attackable_targets,
                "vulnerable_targets": len(recommendations)
            },
            "endpoint_analyses": endpoint_analyses,
            "recommendations": recommendations,
            "ml_models": {
                "vulnerability_predictor": "loaded" if vulnerability_predictor.model else "default",
                "payload_recommender": "loaded" if payload_recommender.model else "default"
            }
        }
        
        logger.info(f"✅ ML Prediction: {applicable_endpoints} applicable endpoints, {len(recommendations)} vulnerable targets found")
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
