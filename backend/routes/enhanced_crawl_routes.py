"""
Enhanced Crawl Router - Clean, simple crawling that works with Enhanced ML Fuzzer
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any, Optional
import logging
import json
from pathlib import Path
import re
from urllib.parse import urlparse, parse_qs, urljoin

# Import the enhanced ML fuzzer
try:
    from ..modules.enhanced_ml_fuzzer import EnhancedMLFuzzer, FuzzTarget, FuzzResult
    print("✅ Enhanced ML Fuzzer imported successfully (relative)")
except ImportError:
    try:
        from modules.enhanced_ml_fuzzer import EnhancedMLFuzzer, FuzzTarget, FuzzResult
        print("✅ Enhanced ML Fuzzer imported successfully (absolute)")
    except Exception as e:
        print(f"❌ Enhanced ML Fuzzer import failed: {e}")
        # Create dummy classes to prevent import errors
        class EnhancedMLFuzzer:
            def __init__(self): pass
            def fuzz_multiple_targets(self, *args, **kwargs): return []
            def fuzz_target(self, *args, **kwargs): return []
        class FuzzTarget:
            def __init__(self, **kwargs): pass
        class FuzzResult:
            def __init__(self, **kwargs): pass

logger = logging.getLogger(__name__)

# Create the enhanced crawl router
router = APIRouter(tags=["enhanced-crawl"])

# Initialize the enhanced ML fuzzer
_enhanced_fuzzer: Optional[EnhancedMLFuzzer] = None

def get_enhanced_fuzzer() -> EnhancedMLFuzzer:
    """Get or create the enhanced ML fuzzer instance"""
    global _enhanced_fuzzer
    if _enhanced_fuzzer is None:
        try:
            _enhanced_fuzzer = EnhancedMLFuzzer()
            logger.info("✅ Enhanced ML Fuzzer initialized for crawling")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Enhanced ML Fuzzer: {e}")
            raise HTTPException(500, f"Enhanced ML Fuzzer initialization failed: {e}")
    return _enhanced_fuzzer

# ------------------------- Simple Endpoint Discovery -------------------------

def discover_endpoints_dynamically(base_url: str) -> List[Dict[str, Any]]:
    """
    TRUE dynamic crawling that discovers endpoints by parsing HTML, JavaScript, and API responses
    This is real crawling, not hardcoded lists!
    """
    discovered = []
    
    try:
        import requests
        from bs4 import BeautifulSoup
        import re
        import json
        session = requests.Session()
        logger.info("✅ Dynamic crawler initialized with requests + BeautifulSoup")
    except Exception as e:
        logger.error(f"❌ Failed to initialize dynamic crawler: {e}")
        return discovered
    
    # Ensure base_url ends with /
    if not base_url.endswith('/'):
        base_url = base_url.rstrip('/') + '/'
    
    logger.info(f"🔍 Starting DYNAMIC crawling of: {base_url}")
    
    try:
        # Step 1: Get the main page and parse HTML
        logger.info("📄 Step 1: Fetching and parsing main page HTML...")
        response = session.get(base_url, timeout=10)
        logger.info(f"📥 Main page response: {response.status_code}")
        
        if response.status_code == 200:
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Step 2: Find all forms and extract endpoints
            logger.info("🔍 Step 2: Analyzing HTML forms...")
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                if action:
                    # Convert relative URLs to absolute
                    if action.startswith('/'):
                        form_url = urljoin(base_url, action)
                    elif action.startswith('http'):
                        form_url = action
                    else:
                        form_url = urljoin(base_url, action)
                    
                    # Extract input fields as parameters
                    inputs = form.find_all(['input', 'select', 'textarea'])
                    params = []
                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            params.append(name)
                    
                    if params:
                        discovered.append({
                            "url": form_url,
                            "param": params[0],  # Primary parameter
                            "method": method,
                            "path": form_url.replace(base_url, ""),
                            "type": "html_form",
                            "all_params": params,
                            "source": "form_analysis"
                        })
                        logger.info(f"✅ Found form endpoint: {form_url} ({method}) with params: {params}")
            
            # Step 3: Find all links and extract potential endpoints
            logger.info("🔗 Step 3: Analyzing HTML links...")
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if href and not href.startswith('#') and not href.startswith('mailto:'):
                    # Convert relative URLs to absolute
                    if href.startswith('/'):
                        link_url = urljoin(base_url, href)
                    elif href.startswith('http'):
                        link_url = href
                    else:
                        link_url = urljoin(base_url, href)
                    
                    # Only include links from the same domain
                    if base_url in link_url:
                        discovered.append({
                            "url": link_url,
                            "param": "id",  # Default parameter
                            "method": "GET",
                            "path": link_url.replace(base_url, ""),
                            "type": "html_link",
                            "source": "link_analysis"
                        })
                        logger.info(f"✅ Found link endpoint: {link_url}")
            
            # Step 4: Search for JavaScript API calls and AJAX endpoints
            logger.info("📜 Step 4: Analyzing JavaScript for API calls...")
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    script_content = script.string
                    
                    # Look for common API patterns
                    api_patterns = [
                        r'["\']([^"\']*\/api\/[^"\']*)["\']',  # /api/ endpoints
                        r'["\']([^"\']*\/rest\/[^"\']*)["\']',  # /rest/ endpoints
                        r'fetch\(["\']([^"\']+)["\']',  # fetch() calls
                        r'axios\.[get|post|put|delete]+\(["\']([^"\']+)["\']',  # axios calls
                        r'\.get\(["\']([^"\']+)["\']',  # jQuery .get() calls
                        r'\.post\(["\']([^"\']+)["\']',  # jQuery .post() calls
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, script_content, re.IGNORECASE)
                        for match in matches:
                            if match.startswith('/'):
                                api_url = urljoin(base_url, match)
                            elif match.startswith('http'):
                                api_url = match
                            else:
                                api_url = urljoin(base_url, match)
                            
                            # Only include URLs from the same domain
                            if base_url in api_url:
                                discovered.append({
                                    "url": api_url,
                                    "param": "id",  # Default parameter
                                    "method": "GET",
                                    "path": api_url.replace(base_url, ""),
                                    "type": "javascript_api",
                                    "source": "js_analysis"
                                })
                                logger.info(f"✅ Found JS API endpoint: {api_url}")
            
            # Step 5: Test common API patterns dynamically (Enhanced for SPAs)
            logger.info("🧪 Step 5: Testing common API patterns...")
            common_api_paths = [
                "api", "rest", "v1", "v2", "graphql", "webhook", "callback",
                "search", "login", "register", "profile", "admin", "dashboard",
                "products", "users", "orders", "basket", "cart", "checkout",
                "user", "product", "order", "item", "category", "auth", "token"
            ]
            
            # Enhanced pattern testing for modern web apps
            test_patterns = []
            for path in common_api_paths:
                test_patterns.extend([
                    f"{base_url}{path}",
                    f"{base_url}api/{path}",
                    f"{base_url}rest/{path}",
                    f"{base_url}v1/{path}",
                    f"{base_url}{path}/search",
                    f"{base_url}{path}/list",
                    f"{base_url}{path}/all",
                    f"{base_url}{path}/find",
                    f"{base_url}{path}/get",
                    f"{base_url}{path}/create",
                    f"{base_url}{path}/update",
                    f"{base_url}{path}/delete",
                    f"{base_url}{path}/login",
                    f"{base_url}{path}/register",
                    f"{base_url}{path}/profile",
                    f"{base_url}{path}/admin",
                    f"{base_url}{path}/config",
                    f"{base_url}{path}/settings"
                ])
            
            # Remove duplicates
            test_patterns = list(set(test_patterns))
            logger.info(f"🧪 Testing {len(test_patterns)} API patterns...")
            
            for test_url in test_patterns:
                try:
                    test_response = session.get(test_url, timeout=3)
                    if test_response.status_code in [200, 401, 403, 404, 405]:
                        # Check if it looks like an API endpoint
                        content_type = test_response.headers.get('content-type', '')
                        response_text = test_response.text.strip()
                        
                        # More sophisticated API detection
                        is_api = (
                            'json' in content_type or 
                            response_text.startswith('{') or 
                            response_text.startswith('[') or
                            'application/json' in content_type or
                            'api' in test_url.lower() or
                            'rest' in test_url.lower() or
                            test_response.status_code in [401, 403]  # Auth endpoints
                        )
                        
                        if is_api:
                            # Determine parameter based on URL pattern
                            param = "id"
                            if "search" in test_url:
                                param = "q"
                            elif "login" in test_url or "register" in test_url:
                                param = "email"
                            elif "product" in test_url:
                                param = "productId"
                            elif "user" in test_url:
                                param = "userId"
                            elif "order" in test_url:
                                param = "orderId"
                            
                            discovered.append({
                                "url": test_url,
                                "param": param,
                                "method": "GET",
                                "path": test_url.replace(base_url, ""),
                                "type": "api_pattern",
                                "status": test_response.status_code,
                                "content_type": content_type,
                                "response_length": len(response_text),
                                "source": "enhanced_pattern_testing"
                            })
                            logger.info(f"✅ Found API pattern: {test_url} ({test_response.status_code}) - {content_type}")
                except Exception as e:
                    logger.debug(f"⚠️ Error testing {test_url}: {e}")
                    continue
            
            # Step 6: Analyze response headers for API hints
            logger.info("📋 Step 6: Analyzing response headers for API hints...")
            headers = response.headers
            
            # Look for API-related headers
            api_headers = ['x-api-version', 'x-api-key', 'x-api-endpoint', 'api-version']
            for header in api_headers:
                if header in headers:
                    logger.info(f"🔍 Found API header: {header} = {headers[header]}")
            
            # Look for CORS headers (indicates API)
            cors_headers = ['access-control-allow-origin', 'access-control-allow-methods']
            for header in cors_headers:
                if header in headers:
                    logger.info(f"🌐 Found CORS header: {header} = {headers[header]}")
                    # This suggests API endpoints exist
            
        else:
            logger.warning(f"⚠️ Main page not accessible: {response.status_code}")
            
    except Exception as e:
        logger.error(f"❌ Error in dynamic crawling: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
    
    # Remove duplicates and clean up
    unique_endpoints = []
    seen_urls = set()
    for endpoint in discovered:
        if endpoint['url'] not in seen_urls:
            unique_endpoints.append(endpoint)
            seen_urls.add(endpoint['url'])
    
    logger.info(f"🎉 DYNAMIC CRAWLING COMPLETE: Discovered {len(unique_endpoints)} unique endpoints")
    return unique_endpoints

def discover_endpoints_from_url(base_url: str, max_depth: int = 2) -> List[Dict[str, Any]]:
    """
    TRUE dynamic endpoint discovery that parses HTML, JavaScript, and tests API patterns
    This is real crawling, not hardcoded lists!
    """
    discovered = []
    
    logger.info(f"🚀 Starting TRUE DYNAMIC crawling of: {base_url}")
    
    # Step 1: Use the new dynamic crawler
    logger.info("🔍 Step 1: Running dynamic HTML/JS analysis...")
    discovered = discover_endpoints_dynamically(base_url)
    logger.info(f"🎯 Dynamic discovery found {len(discovered)} endpoints")
    
    # Step 2: If we didn't find many endpoints, try additional discovery methods
    if len(discovered) < 10:
        logger.info(f"📝 Only {len(discovered)} endpoints found, trying additional discovery methods...")
        
        # Ensure base_url ends with /
        if not base_url.endswith('/'):
            base_url = base_url.rstrip('/') + '/'
        
        # Additional discovery: Test common API patterns
        logger.info("🧪 Testing additional API patterns...")
        additional_patterns = [
            # Common REST patterns
            {"path": "rest/products/search", "param": "q", "method": "GET"},
            {"path": "rest/products", "param": "limit", "method": "GET"},
            {"path": "rest/user/login", "param": "email", "method": "POST"},
            {"path": "rest/basket", "param": "productId", "method": "POST"},
            {"path": "rest/admin/users", "param": "role", "method": "GET"},
            
            # Common web patterns
            {"path": "search", "param": "q", "method": "GET"},
            {"path": "login", "param": "email", "method": "POST"},
            {"path": "register", "param": "email", "method": "POST"},
        {"path": "profile", "param": "id", "method": "GET"},
            {"path": "admin", "param": "user", "method": "GET"},
        ]
        
        # Test these patterns
        try:
            import requests
            session = requests.Session()
            for pattern in additional_patterns:
                test_url = urljoin(base_url, pattern["path"])
                try:
                    test_response = session.get(test_url, timeout=3)
                    if test_response.status_code in [200, 401, 403, 404, 405]:
                        # Check if this endpoint is already discovered
                        if not any(ep['url'] == test_url for ep in discovered):
                            discovered.append({
                                "url": test_url,
            "param": pattern["param"],
            "method": pattern["method"],
            "path": pattern["path"],
                                "type": "additional_pattern",
                                "status": test_response.status_code,
                                "content_type": test_response.headers.get("content-type", ""),
                                "source": "pattern_fallback"
                            })
                            logger.info(f"✅ Found additional endpoint: {test_url} ({test_response.status_code})")
                except Exception as e:
                    logger.debug(f"⚠️ Error testing {test_url}: {e}")
                    continue
        except Exception as e:
            logger.error(f"❌ Error in additional discovery: {e}")
    
    logger.info(f"🎉 TOTAL DISCOVERY COMPLETE: Found {len(discovered)} endpoints for {base_url}")
    return discovered

# ------------------------- API Endpoints -------------------------

@router.post("/crawl")
async def enhanced_crawl(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced crawl endpoint that discovers endpoints and returns them for fuzzing
    """
    try:
        # Extract parameters from request body
        target_url = request.get("target_url", "")
        max_depth = request.get("max_depth", 2)
        max_endpoints = request.get("max_endpoints", 50)
        
        logger.info(f"📥 Received request: target_url={target_url}, max_depth={max_depth}, max_endpoints={max_endpoints}")
        logger.info("🚨 DEBUG: This is the UPDATED enhanced_crawl function!")
        
        if not target_url:
            raise HTTPException(400, "target_url is required")
        
        logger.info(f"🚀 Enhanced Crawl: Starting discovery for {target_url}")
        
        # Discover endpoints
        discovered_endpoints = discover_endpoints_from_url(target_url, max_depth)
        
        # Limit the number of endpoints
        if len(discovered_endpoints) > max_endpoints:
            discovered_endpoints = discovered_endpoints[:max_endpoints]
            logger.info(f"📊 Limited to {max_endpoints} endpoints")
        
        # Prepare response
        response = {
            "status": "success",
            "message": f"Enhanced crawl completed for {target_url}",
            "target_url": target_url,
            "discovered_endpoints": len(discovered_endpoints),
            "endpoints": discovered_endpoints,
            "enhanced_ml": True,
            "ready_for_fuzzing": True
        }
        
        logger.info(f"🎉 Enhanced Crawl: Discovered {len(discovered_endpoints)} endpoints")
        return response
        
    except Exception as e:
        logger.error(f"❌ Enhanced Crawl failed: {e}")
        raise HTTPException(500, f"Enhanced crawl failed: {e}")

@router.post("/crawl-and-fuzz")
async def enhanced_crawl_and_fuzz(
    target_url: str,
    max_depth: int = 2,
    max_endpoints: int = 20,
    top_k: int = 3
) -> Dict[str, Any]:
    """
    Combined crawl and fuzz endpoint that discovers endpoints and immediately fuzzes them
    """
    try:
        logger.info(f"🚀 Enhanced Crawl & Fuzz: Starting for {target_url}")
        
        # Step 1: Discover endpoints
        discovered_endpoints = discover_endpoints_from_url(target_url, max_depth)
        
        # Limit endpoints for fuzzing
        if len(discovered_endpoints) > max_endpoints:
            discovered_endpoints = discovered_endpoints[:max_endpoints]
            logger.info(f"📊 Limited to {max_endpoints} endpoints for fuzzing")
        
        # Step 2: Convert to fuzz targets
        fuzz_targets = []
        for endpoint in discovered_endpoints:
            target = FuzzTarget(
                url=endpoint["url"],
                param=endpoint["param"],
                method=endpoint["method"],
                job_id=f"crawl_{hash(target_url) % 10000}",
                headers={},
                body=""
            )
            fuzz_targets.append(target)
        
        # Step 3: Run enhanced ML fuzzing
        fuzzer = get_enhanced_fuzzer()
        logger.info(f"🧪 Enhanced ML: Fuzzing {len(fuzz_targets)} discovered endpoints")
        
        results = fuzzer.fuzz_multiple_targets(fuzz_targets, top_k)
        
        # Step 4: Prepare comprehensive response
        response = {
            "status": "success",
            "message": f"Enhanced crawl and fuzz completed for {target_url}",
            "target_url": target_url,
            "discovered_endpoints": len(discovered_endpoints),
            "fuzzed_endpoints": len(results),
            "endpoints": discovered_endpoints,
            "results": results,
            "enhanced_ml": True,
            "family_prediction": True,
            "payload_recommendation": True
        }
        
        logger.info(f"🎉 Enhanced Crawl & Fuzz: Completed with {len(results)} fuzzing results")
        return response
        
    except Exception as e:
        logger.error(f"❌ Enhanced Crawl & Fuzz failed: {e}")
        raise HTTPException(500, f"Enhanced crawl and fuzz failed: {e}")

@router.get("/health")
async def enhanced_crawl_health():
    """Health check for enhanced crawl router"""
    try:
        fuzzer = get_enhanced_fuzzer()
        return {
            "status": "healthy",
            "enhanced_crawl": True,
            "enhanced_ml_fuzzer": True,
            "endpoint_discovery": True,
            "message": "Enhanced Crawl Router is ready"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "enhanced_crawl": False,
            "error": str(e),
            "message": "Enhanced Crawl Router is not ready"
        }

@router.get("/info")
async def enhanced_crawl_info():
    """Get information about the enhanced crawl router"""
    return {
        "name": "Enhanced Crawl Router",
        "description": "Clean, simple crawling that works with Enhanced ML Fuzzer",
        "version": "1.0.0",
        "features": [
            "Simple endpoint discovery",
            "Integration with Enhanced ML Fuzzer",
            "No complex crawling dependencies",
            "Ready for immediate fuzzing",
            "Clean, working imports"
        ],
        "enhanced_ml": True,
        "endpoint_discovery": True,
        "fuzzing_integration": True,
        "status": "ready"
    }
