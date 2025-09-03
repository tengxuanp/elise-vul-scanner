"""
Enhanced ML Fuzzer with CVSS-based Vulnerability Classification
Automation Detection & Exploitation of Web Application Vulnerabilities using Machine Learning
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import logging
import random
from enum import Enum

logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    """OWASP Top 10 vulnerability types"""
    XSS = "xss"
    SQL_INJECTION = "sqli"
    COMMAND_INJECTION = "rce"
    PATH_TRAVERSAL = "lfi"
    OPEN_REDIRECT = "redirect"

class CVSSSeverity(Enum):
    """CVSS severity levels"""
    NONE = 0.0
    LOW = 0.1
    MEDIUM = 0.4
    HIGH = 0.7
    CRITICAL = 0.9

@dataclass
class CVSSMetrics:
    """CVSS Base Metrics for vulnerability scoring"""
    attack_vector: str = "network"
    attack_complexity: str = "low"
    privileges_required: str = "none"
    user_interaction: str = "none"
    scope: str = "unchanged"
    confidentiality: str = "none"
    integrity: str = "none"
    availability: str = "none"
    
    def calculate_base_score(self) -> float:
        """Calculate CVSS Base Score (0.0 - 10.0)"""
        # Simplified CVSS calculation
        impact_score = self._calculate_impact_score()
        exploitability_score = self._calculate_exploitability_score()
        
        if impact_score <= 0:
            return 0.0
        
        base_score = min(10.0, max(0.0, 
            (0.6 * impact_score + 0.4 * exploitability_score - 1.5) * 1.176))
        
        return round(base_score, 1)
    
    def _calculate_impact_score(self) -> float:
        """Calculate Impact Subscore"""
        c = {"none": 0.0, "low": 0.22, "high": 0.56}
        i = {"none": 0.0, "low": 0.22, "high": 0.56}
        a = {"none": 0.0, "low": 0.22, "high": 0.56}
        
        return min(10.0, 10.41 * (1 - (1 - c[self.confidentiality]) * 
                                   (1 - i[self.integrity]) * 
                                   (1 - a[self.availability])))
    
    def _calculate_exploitability_score(self) -> float:
        """Calculate Exploitability Subscore"""
        av = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}
        ac = {"low": 0.77, "high": 0.44}
        pr = {"none": 0.85, "low": 0.62, "high": 0.27}
        ui = {"none": 0.85, "required": 0.62}
        
        return 8.22 * av[self.attack_vector] * ac[self.attack_complexity] * \
               pr[self.privileges_required] * ui[self.user_interaction]

@dataclass
class VulnerabilityAssessment:
    """Enhanced vulnerability assessment with CVSS scoring"""
    vulnerability_type: VulnerabilityType
    confidence_score: float
    cvss_metrics: CVSSMetrics
    cvss_base_score: float = 0.0
    cvss_severity: CVSSSeverity = CVSSSeverity.NONE
    combined_risk_score: float = 0.0
    evidence: List[str] = field(default_factory=list)
    payload_effectiveness: float = 0.0
    exploitation_complexity: str = "low"
    
    def __post_init__(self):
        """Calculate CVSS scores after initialization"""
        self.cvss_base_score = self.cvss_metrics.calculate_base_score()
        self.cvss_severity = self._get_severity_level()
        self.combined_risk_score = self._calculate_combined_score()
    
    def _get_severity_level(self) -> CVSSSeverity:
        """Get CVSS severity level based on base score"""
        if self.cvss_base_score >= 9.0:
            return CVSSSeverity.CRITICAL
        elif self.cvss_base_score >= 7.0:
            return CVSSSeverity.HIGH
        elif self.cvss_base_score >= 4.0:
            return CVSSSeverity.MEDIUM
        elif self.cvss_base_score >= 0.1:
            return CVSSSeverity.LOW
        else:
            return CVSSSeverity.NONE
    
    def _calculate_combined_score(self) -> float:
        """Calculate combined ML confidence × CVSS severity score"""
        severity_multiplier = {
            CVSSSeverity.NONE: 0.0,
            CVSSSeverity.LOW: 0.5,
            CVSSSeverity.MEDIUM: 1.0,
            CVSSSeverity.HIGH: 1.5,
            CVSSSeverity.CRITICAL: 2.0
        }
        
        return self.confidence_score * severity_multiplier[self.cvss_severity]

@dataclass
class FuzzTarget:
    """Enhanced fuzz target with context"""
    url: str
    param: str
    method: str = "GET"
    context: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Extract context from URL and parameters"""
        self.context = {
            "url_path": self.url.split('?')[0] if '?' in self.url else self.url,
            "param_type": self._infer_param_type(),
            "application_context": self._infer_app_context()
        }
    
    def _infer_param_type(self) -> str:
        """Infer parameter type from name and context"""
        param_lower = self.param.lower()
        if any(x in param_lower for x in ['id', 'user', 'uid', 'userid']):
            return "identifier"
        elif any(x in param_lower for x in ['search', 'q', 'query', 'keyword']):
            return "search"
        elif any(x in param_lower for x in ['file', 'path', 'dir', 'folder']):
            return "file_path"
        elif any(x in param_lower for x in ['url', 'redirect', 'next', 'target']):
            return "redirect"
        elif any(x in param_lower for x in ['email', 'mail']):
            return "email"
        else:
            return "generic"
    
    def _infer_app_context(self) -> str:
        """Infer application context from URL path"""
        path_lower = self.url.lower()
        if any(x in path_lower for x in ['admin', 'manage', 'control']):
            return "administrative"
        elif any(x in path_lower for x in ['api', 'rest', 'graphql']):
            return "api"
        elif any(x in path_lower for x in ['search', 'find', 'query']):
            return "search"
        elif any(x in path_lower for x in ['upload', 'file', 'media']):
            return "file_handling"
        elif any(x in path_lower for x in ['auth', 'login', 'register']):
            return "authentication"
        else:
            return "general"

@dataclass
class FuzzResult:
    """Enhanced fuzz result with CVSS assessment"""
    target: FuzzTarget
    payload: str
    response_status: int
    response_time: float
    vulnerability_assessment: Optional[VulnerabilityAssessment] = None
    response_analysis: Dict[str, Any] = field(default_factory=dict)
    exploitation_potential: float = 0.0
    
    def __post_init__(self):
        """Calculate exploitation potential after initialization"""
        if self.vulnerability_assessment:
            self.exploitation_potential = self._calculate_exploitation_potential()
    
    def _calculate_exploitation_potential(self) -> float:
        """Calculate exploitation potential based on CVSS and ML confidence"""
        if not self.vulnerability_assessment:
            return 0.0
        
        # Factors: CVSS score, ML confidence, response analysis
        cvss_factor = self.vulnerability_assessment.cvss_base_score / 10.0
        ml_factor = self.vulnerability_assessment.confidence_score
        response_factor = self._analyze_response_indicators()
        
        return (cvss_factor * 0.4 + ml_factor * 0.4 + response_factor * 0.2)
    
    def _analyze_response_indicators(self) -> float:
        """Analyze response for vulnerability indicators"""
        indicators = 0.0
        
        # Status code indicators
        if self.response_status in [500, 502, 503]:
            indicators += 0.3
        elif self.response_status == 200:
            indicators += 0.1
        
        # Response time indicators
        if self.response_time > 5.0:
            indicators += 0.2
        
        return min(1.0, indicators)

class EnhancedMLFuzzer:
    """Enhanced ML Fuzzer with CVSS-based vulnerability classification"""
    
    def __init__(self):
        logger.info("🚀 Initializing CVSS-based Enhanced ML Fuzzer")
        self.vulnerability_patterns = self._initialize_patterns()
        self.cvss_templates = self._initialize_cvss_templates()
        self.ml_models = self._initialize_ml_models()
        logger.info("✅ CVSS-based Enhanced ML Fuzzer initialized successfully")
    
    def _initialize_patterns(self) -> Dict[VulnerabilityType, List[Dict[str, Any]]]:
        """Initialize vulnerability detection patterns"""
        return {
            VulnerabilityType.XSS: [
                {"pattern": "<script>", "cvss": {"attack_vector": "network"}},
                {"pattern": "javascript:", "cvss": {"attack_vector": "network"}},
                {"pattern": "onerror=", "cvss": {"attack_vector": "network"}}
            ],
            VulnerabilityType.SQL_INJECTION: [
                {"pattern": "' OR '1'='1", "cvss": {"attack_vector": "network"}},
                {"pattern": "'; DROP TABLE", "cvss": {"attack_vector": "network"}},
                {"pattern": "UNION SELECT", "cvss": {"attack_vector": "network"}}
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                {"pattern": "; ls", "cvss": {"attack_vector": "network"}},
                {"pattern": "| whoami", "cvss": {"attack_vector": "network"}},
                {"pattern": "&& cat", "cvss": {"attack_vector": "network"}}
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                {"pattern": "../../../etc/passwd", "cvss": {"attack_vector": "network"}},
                {"pattern": "..\\..\\..\\windows", "cvss": {"attack_vector": "network"}}
            ],
            VulnerabilityType.OPEN_REDIRECT: [
                {"pattern": "https://evil.com", "cvss": {"attack_vector": "network"}},
                {"pattern": "javascript:", "cvss": {"attack_vector": "network"}}
            ]
        }
    
    def _initialize_cvss_templates(self) -> Dict[VulnerabilityType, CVSSMetrics]:
        """Initialize CVSS templates for different vulnerability types"""
        return {
            VulnerabilityType.XSS: CVSSMetrics(
                attack_vector="network", attack_complexity="low", 
                privileges_required="none", user_interaction="required",
                scope="unchanged", confidentiality="low", integrity="low", availability="none"
            ),
            VulnerabilityType.SQL_INJECTION: CVSSMetrics(
                attack_vector="network", attack_complexity="low",
                privileges_required="none", user_interaction="none",
                scope="changed", confidentiality="high", integrity="high", availability="high"
            ),
            VulnerabilityType.COMMAND_INJECTION: CVSSMetrics(
                attack_vector="network", attack_complexity="low",
                privileges_required="none", user_interaction="none",
                scope="changed", confidentiality="high", integrity="high", availability="high"
            ),
            VulnerabilityType.PATH_TRAVERSAL: CVSSMetrics(
                attack_vector="network", attack_complexity="low",
                privileges_required="none", user_interaction="none",
                scope="unchanged", confidentiality="high", integrity="none", availability="none"
            ),
            VulnerabilityType.OPEN_REDIRECT: CVSSMetrics(
                attack_vector="network", attack_complexity="low",
                privileges_required="none", user_interaction="required",
                scope="unchanged", confidentiality="none", integrity="low", availability="none"
            )
        }
    
    def _initialize_ml_models(self) -> Dict[str, Any]:
        """Initialize ML models for vulnerability detection"""
        return {
            "vulnerability_classifier": "rule_based_ml",
            "confidence_calculator": "context_aware_scoring",
            "false_positive_filter": "response_analysis"
        }
    
    def classify_vulnerability(self, target: FuzzTarget, payload: str, 
                             response: Dict[str, Any]) -> Optional[VulnerabilityAssessment]:
        """Classify vulnerability using ML-enhanced detection with CVSS scoring"""
        
        logger.info(f"🔍 Classifying vulnerability for payload: {payload[:30]}...")
        
        # Analyze payload against known patterns
        detected_vulns = []
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern_info in patterns:
                if pattern_info["pattern"].lower() in payload.lower():
                    detected_vulns.append({
                        "type": vuln_type,
                        "pattern": pattern_info["pattern"],
                        "cvss_template": pattern_info["cvss"]
                    })
        
        if not detected_vulns:
            logger.info("❌ No vulnerability patterns matched")
            return None
        
        # Select the most likely vulnerability type
        primary_vuln = detected_vulns[0]
        vuln_type = primary_vuln["type"]
        
        logger.info(f"✅ Detected vulnerability type: {vuln_type.value}")
        
        # Calculate ML confidence score
        confidence_score = self._calculate_ml_confidence(target, payload, response, vuln_type)
        
        # Get CVSS metrics
        cvss_metrics = self.cvss_templates[vuln_type]
        
        # Create vulnerability assessment
        assessment = VulnerabilityAssessment(
            vulnerability_type=vuln_type,
            confidence_score=confidence_score,
            cvss_metrics=cvss_metrics,
            evidence=[f"Pattern match: {primary_vuln['pattern']}"],
            payload_effectiveness=self._assess_payload_effectiveness(payload, response),
            exploitation_complexity=self._assess_exploitation_complexity(target, vuln_type)
        )
        
        logger.info(f"🎯 Vulnerability assessment: {vuln_type.value}, CVSS: {assessment.cvss_base_score}, Confidence: {confidence_score:.2f}")
        
        return assessment
    
    def _calculate_ml_confidence(self, target: FuzzTarget, payload: str, 
                                response: Dict[str, Any], vuln_type: VulnerabilityType) -> float:
        """Calculate ML confidence score using multiple factors"""
        
        confidence_factors = []
        
        # 1. Pattern match strength (0.3 weight)
        pattern_strength = self._calculate_pattern_strength(payload, vuln_type)
        confidence_factors.append(pattern_strength * 0.3)
        
        # 2. Context relevance (0.2 weight)
        context_relevance = self._calculate_context_relevance(target, vuln_type)
        confidence_factors.append(context_relevance * 0.2)
        
        # 3. Response analysis (0.3 weight)
        response_confidence = self._analyze_response_confidence(response, vuln_type)
        confidence_factors.append(response_confidence * 0.3)
        
        # 4. Payload sophistication (0.2 weight)
        payload_sophistication = self._assess_payload_sophistication(payload)
        confidence_factors.append(payload_sophistication * 0.2)
        
        # Calculate weighted average
        total_confidence = sum(confidence_factors)
        return min(1.0, max(0.0, total_confidence))
    
    def _calculate_pattern_strength(self, payload: str, vuln_type: VulnerabilityType) -> float:
        """Calculate pattern match strength"""
        patterns = self.vulnerability_patterns[vuln_type]
        max_strength = 0.0
        
        for pattern_info in patterns:
            pattern = pattern_info["pattern"].lower()
            if pattern in payload.lower():
                if len(pattern) > 10:
                    strength = 0.9
                elif len(pattern) > 5:
                    strength = 0.7
                else:
                    strength = 0.5
                max_strength = max(max_strength, strength)
        
        return max_strength
    
    def _calculate_context_relevance(self, target: FuzzTarget, vuln_type: VulnerabilityType) -> float:
        """Calculate context relevance score"""
        relevance_scores = {
            VulnerabilityType.XSS: {
                "search": 0.8,
                "generic": 0.6,
                "identifier": 0.4
            },
            VulnerabilityType.SQL_INJECTION: {
                "identifier": 0.9,
                "search": 0.8,
                "generic": 0.7
            },
            VulnerabilityType.COMMAND_INJECTION: {
                "file_path": 0.9,
                "generic": 0.6
            },
            VulnerabilityType.PATH_TRAVERSAL: {
                "file_path": 0.9,
                "generic": 0.4
            },
            VulnerabilityType.OPEN_REDIRECT: {
                "redirect": 0.9,
                "generic": 0.3
            }
        }
        
        param_type = target.context["param_type"]
        return relevance_scores.get(vuln_type, {}).get(param_type, 0.5)
    
    def _analyze_response_confidence(self, response: Dict[str, Any], vuln_type: VulnerabilityType) -> float:
        """Analyze response for vulnerability indicators"""
        confidence = 0.5  # Base confidence
        
        # Status code analysis
        status = response.get("status", 200)
        if status in [500, 502, 503]:
            confidence += 0.3
        elif status == 200:
            confidence += 0.1
        
        # Response time analysis
        response_time = response.get("response_time", 0)
        if response_time > 5.0:
            confidence += 0.1
        
        # Content analysis
        content = response.get("content", "")
        if vuln_type == VulnerabilityType.XSS and "<script>" in content:
            confidence += 0.2
        elif vuln_type == VulnerabilityType.SQL_INJECTION and "sql" in content.lower():
            confidence += 0.2
        
        return min(1.0, confidence)
    
    def _assess_payload_sophistication(self, payload: str) -> float:
        """Assess payload sophistication level"""
        sophistication = 0.5  # Base sophistication
        
        # Length factor
        if len(payload) > 100:
            sophistication += 0.2
        elif len(payload) > 50:
            sophistication += 0.1
        
        # Encoding factor
        if any(enc in payload for enc in ["%3C", "%3E", "%27", "%22"]):
            sophistication += 0.2
        
        # Evasion factor
        if any(evasion in payload for evasion in ["<img", "javascript:", "vbscript:"]):
            sophistication += 0.1
        
        return min(1.0, sophistication)
    
    def _assess_payload_effectiveness(self, payload: str, response: Dict[str, Any]) -> float:
        """Assess how effective the payload was"""
        effectiveness = 0.5  # Base effectiveness
        
        # Status code effectiveness
        status = response.get("status", 200)
        if status in [500, 502, 503]:
            effectiveness += 0.3
        elif status == 200:
            effectiveness += 0.1
        
        # Response time effectiveness
        response_time = response.get("response_time", 0)
        if response_time > 5.0:
            effectiveness += 0.2
        
        return min(1.0, effectiveness)
    
    def _assess_exploitation_complexity(self, target: FuzzTarget, vuln_type: VulnerabilityType) -> str:
        """Assess exploitation complexity"""
        complexity = "low"  # Default complexity
        
        # Adjust based on application context
        app_context = target.context["application_context"]
        if app_context == "administrative":
            complexity = "high"
        elif app_context == "api":
            complexity = "medium"
        
        # Adjust based on parameter type
        param_type = target.context["param_type"]
        if param_type == "identifier":
            complexity = "low"
        elif param_type == "file_path":
            complexity = "medium"
        
        return complexity
    
    def fuzz_target(self, target: FuzzTarget, top_k: int = 5) -> List[FuzzResult]:
        """Fuzz a single target with enhanced ML classification"""
        results = []
        
        logger.info(f"🚀 Starting CVSS-based fuzzing for {target.url} param={target.param}")
        
        # Generate payloads for the target
        payloads = self._generate_payloads(target, top_k)
        logger.info(f"🧪 Generated {len(payloads)} payloads: {[p[:20] + '...' for p in payloads]}")
        
        for payload in payloads:
            # Simulate fuzzing (in production, make actual HTTP requests)
            response = self._simulate_request(target, payload)
            logger.info(f"🔍 Response for payload '{payload[:30]}...': status={response['status']}, time={response['response_time']}")
            
            # Classify vulnerability
            vulnerability = self.classify_vulnerability(target, payload, response)
            
            # Create result
            result = FuzzResult(
                target=target,
                payload=payload,
                response_status=response["status"],
                response_time=response["response_time"],
                vulnerability_assessment=vulnerability,
                response_analysis=response
            )
            
            logger.info(f"✅ Created result with exploitation potential: {result.exploitation_potential}")
            results.append(result)
        
        # Sort by exploitation potential
        results.sort(key=lambda x: x.exploitation_potential, reverse=True)
        logger.info(f"🎉 CVSS-based fuzzing completed with {len(results)} results")
        return results
    
    def fuzz_multiple_targets(self, targets: List[FuzzTarget], top_k: int = 5) -> List[FuzzResult]:
        """Fuzz multiple targets with enhanced ML classification"""
        all_results = []
        
        for target in targets:
            target_results = self.fuzz_target(target, top_k)
            all_results.extend(target_results)
        
        # Sort all results by exploitation potential
        all_results.sort(key=lambda x: x.exploitation_potential, reverse=True)
        return all_results
    
    def _generate_payloads(self, target: FuzzTarget, top_k: int) -> List[str]:
        """Generate payloads based on target context and vulnerability types"""
        payloads = []
        
        # Calculate payloads per type (ensure at least 1)
        payloads_per_type = max(1, top_k // len(VulnerabilityType))
        
        # Generate payloads for each vulnerability type
        for vuln_type in VulnerabilityType:
            type_payloads = self._generate_type_specific_payloads(vuln_type, target, payloads_per_type)
            payloads.extend(type_payloads)
        
        # Shuffle and limit to top_k
        random.shuffle(payloads)
        return payloads[:top_k]
    
    def _generate_type_specific_payloads(self, vuln_type: VulnerabilityType, target: FuzzTarget, count: int) -> List[str]:
        """Generate payloads for a specific vulnerability type"""
        payloads = []
        
        if vuln_type == VulnerabilityType.XSS:
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//"
            ]
        elif vuln_type == VulnerabilityType.SQL_INJECTION:
            payloads = [
                "' OR '1'='1",
                "'; DROP TABLE users--",
                "' UNION SELECT NULL--",
                "' OR 1=1#",
                "admin'--"
            ]
        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            payloads = [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "; id",
                "| uname -a"
            ]
        elif vuln_type == VulnerabilityType.PATH_TRAVERSAL:
            payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd"
            ]
        elif vuln_type == VulnerabilityType.OPEN_REDIRECT:
            payloads = [
                "https://evil.com",
                "javascript:alert('redirect')",
                "data:text/html,<script>alert('redirect')</script>",
                "//evil.com",
                "\\\\evil.com"
            ]
        
        # Limit to requested count
        return payloads[:count]
    
    def _simulate_request(self, target: FuzzTarget, payload: str) -> Dict[str, Any]:
        """Simulate HTTP request (in production, make actual requests)"""
        logger.info(f"🌐 Simulating request for payload: {payload[:30]}...")
        
        # Simulate different response scenarios based on payload content
        if "script" in payload.lower():
            return {
                "status": 200,
                "response_time": 0.5,
                "content": f"<div>Search results for: {payload}</div>",
                "content_length": len(payload) * 2
            }
        elif "sql" in payload.lower() or "union" in payload.lower() or "or" in payload.lower():
            return {
                "status": 500,
                "response_time": 2.0,
                "content": "Internal Server Error",
                "content_length": 100
            }
        elif "ls" in payload or "whoami" in payload:
            return {
                "status": 200,
                "response_time": 1.5,
                "content": "Command executed successfully",
                "content_length": 200
            }
        else:
            return {
                "status": 200,
                "response_time": 0.3,
                "content": f"Parameter value: {payload}",
                "content_length": len(payload) + 20
            }


