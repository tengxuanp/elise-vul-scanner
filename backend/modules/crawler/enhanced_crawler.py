"""
Enhanced Crawler - Active capture-only endpoint discovery via Playwright
Discovers real endpoints through BFS link traversal, GET form submission, and seed paths
Only records actual browser activity - no pattern synthesis
"""

import logging
from typing import List, Dict, Any, Set, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qs, urljoin, urlunparse
from dataclasses import dataclass
from collections import defaultdict, deque
import json
import asyncio

from infrastructure.browser_pool import browser_pool

logger = logging.getLogger(__name__)

# Helper functions
def normalize_url(base: str, href: str) -> str:
    """Resolve relative URLs and strip fragments"""
    if not href:
        return base
    
    # Remove fragments
    if '#' in href:
        href = href.split('#')[0]
    
    # Resolve relative URLs
    full_url = urljoin(base, href)
    
    # Parse and reconstruct to normalize
    parsed = urlparse(full_url)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        ''  # Remove fragment
    ))

def same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin (scheme, host, port)"""
    try:
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        return (parsed1.scheme == parsed2.scheme and 
                parsed1.netloc == parsed2.netloc)
    except Exception:
        return False

def major_ct(content_type: str) -> str:
    """Extract major content type (e.g., 'text/html', 'application/json')"""
    if not content_type:
        return 'unknown'
    return content_type.split(';')[0].strip().lower()

def extract_param_names(request_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """Extract parameter names from request data, separated by location"""
    params = {
        'query': [],
        'form': [],
        'json': []
    }
    
    # From query string
    parsed_url = urlparse(request_data.get('url', ''))
    if parsed_url.query:
        query_params = parse_qs(parsed_url.query)
        params['query'] = list(query_params.keys())
    
    # From POST form data
    if request_data.get('method', '').upper() == 'POST':
        content_type = request_data.get('content_type', '').lower()
        
        if 'application/x-www-form-urlencoded' in content_type:
            post_data = request_data.get('post_data', '')
            if post_data:
                try:
                    form_params = parse_qs(post_data)
                    params['form'] = list(form_params.keys())
                except Exception:
                    pass
        
        elif 'application/json' in content_type:
            post_data_json = request_data.get('post_data_json')
            if isinstance(post_data_json, dict):
                params['json'] = list(post_data_json.keys())
    
    return params

def classify_source(request_data: Dict[str, Any], forced_source: Optional[str] = None) -> str:
    """Classify the source of a request"""
    if forced_source:
        return forced_source
    
    resource_type = request_data.get('resource_type', '')
    method = request_data.get('method', '').upper()
    
    if resource_type in {'xhr', 'fetch'}:
        return 'xhr_fetch'
    elif method == 'POST' or request_data.get('form_submit', False):
        return 'form_submit'
    elif resource_type == 'document':
        return 'document'
    else:
        return 'other'

@dataclass
class CapturedEndpoint:
    """Represents a captured endpoint from real browser activity"""
    url: str
    path: str
    method: str
    param_names: List[str]  # All parameter names (for backward compatibility)
    param_locs: Dict[str, List[str]]  # Parameters by location: query, form, json
    content_type: str
    status: Optional[int]
    source: str  # "document", "xhr_fetch", "form_submit"

class EnhancedCrawler:
    """
    Active capture-only crawler that discovers endpoints through BFS traversal,
    GET form submission, and seed paths. Only records real browser activity.
    """
    
    def __init__(self):
        self.captured_requests: List[Dict[str, Any]] = []
        self.captured_endpoints: Dict[Tuple, CapturedEndpoint] = {}
        self.start_url: Optional[str] = None
        self.start_origin: Optional[str] = None
        self.seen_requests: Set[str] = set()
        
    def _normalize_path(self, path: str) -> str:
        """Normalize path by removing leading slash"""
        return path.lstrip('/')
    
    def _get_origin(self, url: str) -> str:
        """Extract origin (scheme+host+port) from URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _create_endpoint_key(self, endpoint: CapturedEndpoint) -> Tuple:
        """Create a deduplication key for endpoints"""
        return (
            endpoint.method,
            endpoint.path,
            tuple(endpoint.param_names),
            major_ct(endpoint.content_type)
        )
    
    def _get_type_aware_default(self, input_type: str, name: str) -> str:
        """Get type-aware default values for form inputs"""
        name_lower = name.lower()
        type_lower = input_type.lower()
        
        # Email fields
        if 'email' in name_lower or type_lower == 'email':
            return 'a@a.com'
        
        # Number/ID fields
        if 'id' in name_lower or type_lower in ['number', 'range']:
            return '1'
        
        # Search/query fields
        if any(term in name_lower for term in ['search', 'query', 'q']):
            return 'test'
        
        # Message/text fields
        if any(term in name_lower for term in ['msg', 'message', 'text', 'comment']):
            return 'test'
        
        # Name fields
        if 'name' in name_lower:
            return 'test'
        
        # Default for text inputs
        if type_lower in ['text', 'search', 'url', 'tel']:
            return 'test'
        
        # Default fallback
        return 'test'
    
    async def _setup_network_capture(self, page):
        """Set up network request/response capture"""
        self.captured_requests.clear()
        self.captured_endpoints.clear()
        self.seen_requests.clear()
        
        async def on_request(request):
            """Handle request events"""
            try:
                # Only capture same-origin requests
                if not same_origin(request.url, self.start_origin):
                    return
                
                # Filter resource types - keep only document, xhr, fetch
                resource_type = request.resource_type
                if resource_type not in {'document', 'xhr', 'fetch'}:
                    return
                
                # Extract request data
                request_data = {
                    'url': request.url,
                    'method': request.method,
                    'resource_type': resource_type,
                    'content_type': request.headers.get('content-type', ''),
                    'post_data': None,
                    'post_data_json': None,
                    'form_submit': False
                }
                
                # Get POST data if available
                if request.method.upper() == 'POST':
                    try:
                        post_data = request.post_data
                        if post_data:
                            request_data['post_data'] = post_data
                            # Try to parse as JSON
                            if 'application/json' in request_data['content_type'].lower():
                                try:
                                    request_data['post_data_json'] = json.loads(post_data)
                                except:
                                    pass
                    except Exception as e:
                        logger.debug(f"Could not get POST data: {e}")
                
                self.captured_requests.append(request_data)
                logger.debug(f"📥 Captured request: {request.method} {request.url}")
                
            except Exception as e:
                logger.error(f"Error handling request: {e}")
        
        async def on_response(response):
            """Handle response events"""
            try:
                # Find matching request
                matching_request = None
                for req in reversed(self.captured_requests):
                    if req['url'] == response.url and req['method'] == response.request.method:
                        matching_request = req
                        break
                
                if not matching_request:
                    return
                
                # Update request data with response info
                matching_request['status'] = response.status
                matching_request['response_content_type'] = response.headers.get('content-type', '')
                
                # Create endpoint
                parsed_url = urlparse(response.url)
                path = self._normalize_path(parsed_url.path)
                
                param_locs = extract_param_names(matching_request)
                # Create combined param_names list for backward compatibility
                all_param_names = []
                for loc_params in param_locs.values():
                    all_param_names.extend(loc_params)
                param_names = sorted(list(set(all_param_names)))
                
                source = classify_source(matching_request)
                
                endpoint = CapturedEndpoint(
                    url=response.url,
                    path=path,
                    method=matching_request['method'].upper(),
                    param_names=param_names,
                    param_locs=param_locs,
                    content_type=matching_request['response_content_type'],
                    status=response.status,
                    source=source
                )
                
                # Deduplicate endpoints
                endpoint_key = self._create_endpoint_key(endpoint)
                if endpoint_key not in self.captured_endpoints:
                    self.captured_endpoints[endpoint_key] = endpoint
                    logger.info(f"📤 New endpoint: {endpoint.method} {endpoint.path} (params: {param_names}, source: {source}, status: {response.status})")
                else:
                    logger.debug(f"🔄 Endpoint deduplicated: {endpoint.method} {endpoint.path}")
                
            except Exception as e:
                logger.error(f"Error handling response: {e}")
        
        # Set up listeners
        page.on("request", on_request)
        page.on("response", on_response)
    
    async def _collect_links(self, page, current_url: str, max_links_per_page: int) -> List[str]:
        """Collect same-origin links from the current page"""
        try:
            links = await page.query_selector_all('a[href]')
            collected_links = []
            
            for link in links[:max_links_per_page]:
                try:
                    href = await link.get_attribute('href')
                    if not href:
                        continue
                    
                    # Normalize URL
                    full_url = normalize_url(current_url, href)
                    
                    # Check if same origin
                    if not same_origin(full_url, self.start_origin):
                        continue
                    
                    # Skip destructive links
                    href_lower = href.lower()
                    if any(destructive in href_lower for destructive in ['logout', 'signout', 'delete', 'destroy', 'remove']):
                        logger.debug(f"⏭️ Skipping destructive link: {href}")
                        continue
                    
                    collected_links.append(full_url)
                    
                except Exception as e:
                    logger.debug(f"Error processing link: {e}")
                    continue
            
            return collected_links
            
        except Exception as e:
            logger.error(f"Error collecting links: {e}")
            return []
    
    async def _submit_get_forms(self, page, current_url: str, max_forms_per_page: int) -> int:
        """Submit GET forms with type-aware defaults"""
        try:
            forms = await page.query_selector_all('form')
            submitted_count = 0
            
            for form in forms[:max_forms_per_page]:
                try:
                    # Only process GET forms
                    method = await form.get_attribute('method')
                    if method and method.upper() != 'GET':
                        continue
                    
                    # Fill form inputs with type-aware defaults
                    inputs = await form.query_selector_all('input, select, textarea')
                    for input_elem in inputs:
                        try:
                            input_type = await input_elem.get_attribute('type') or 'text'
                            input_name = await input_elem.get_attribute('name')
                            
                            if not input_name:
                                continue
                            
                            # Skip hidden inputs
                            if input_type.lower() == 'hidden':
                                continue
                            
                            # Get type-aware default value
                            default_value = self._get_type_aware_default(input_type, input_name)
                            
                            # Fill the input
                            if input_type.lower() in ['text', 'search', 'email', 'url', 'tel']:
                                await input_elem.fill(default_value)
                            elif input_type.lower() == 'number':
                                await input_elem.fill(default_value)
                            elif input_type.lower() in ['select-one', 'select-multiple']:
                                # For selects, try to select the first option
                                options = await input_elem.query_selector_all('option')
                                if options:
                                    await input_elem.select_option(index=0)
                            
                        except Exception as e:
                            logger.debug(f"Error filling input: {e}")
                            continue
                    
                    # Submit the form
                    try:
                        # Try to find and click submit button
                        submit_button = await form.query_selector('input[type="submit"], button[type="submit"], button:not([type])')
                        if submit_button:
                            await submit_button.click()
                        else:
                            # Fallback: submit form directly
                            await form.evaluate('form => form.submit()')
                        
                        # Wait for network to settle
                        await page.wait_for_load_state('networkidle', timeout=5000)
                        submitted_count += 1
                        
                        # Go back to continue collecting more forms
                        await page.go_back()
                        await page.wait_for_load_state('networkidle', timeout=5000)
                        
                        logger.info(f"📝 Submitted GET form on {current_url}")
                        
                    except Exception as e:
                        logger.debug(f"Error submitting form: {e}")
                        continue
                
                except Exception as e:
                    logger.debug(f"Error processing form: {e}")
                    continue
            
            return submitted_count
            
        except Exception as e:
            logger.error(f"Error submitting forms: {e}")
            return 0
    
    async def _explore_page(self, page, url: str, max_links_per_page: int, max_forms_per_page: int) -> Tuple[List[str], int]:
        """Explore a single page and collect links and submit forms"""
        try:
            logger.info(f"🔍 Exploring page: {url}")
            
            # Navigate to page
            await page.goto(url, wait_until='networkidle', timeout=10000)
            
            # Collect links
            links = await self._collect_links(page, url, max_links_per_page)
            logger.info(f"🔗 Found {len(links)} same-origin links")
            
            # Submit GET forms
            forms_submitted = await self._submit_get_forms(page, url, max_forms_per_page)
            logger.info(f"📝 Submitted {forms_submitted} GET forms")
            
            return links, forms_submitted
            
        except Exception as e:
            logger.error(f"Error exploring page {url}: {e}")
            return [], 0
    
    async def crawl(self, context, start_url: str, max_pages: int = 12, max_links_per_page: int = 20, 
                   max_forms_per_page: int = 10, max_depth: int = 3, same_origin_only: bool = True,
                   submit_get_forms: bool = True, seed_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform active capture-only crawling using BFS traversal, GET form submission, and seed paths.
        Returns only endpoints observed from real browser activity.
        """
        self.start_url = start_url
        self.start_origin = self._get_origin(start_url)
        
        logger.info(f"🚀 Starting active crawl of: {start_url}")
        logger.info(f"🎯 Origin filter: {self.start_origin}")
        logger.info(f"📊 Limits: max_pages={max_pages}, max_links_per_page={max_links_per_page}, max_forms_per_page={max_forms_per_page}, max_depth={max_depth}")
        
        try:
            # Use the provided context
            page = await context.new_page()
            
            # Set up network capture
            await self._setup_network_capture(page)
            
            # Initialize BFS queue with start URL and seed paths
            url_queue = deque([(start_url, 0)])  # (url, depth)
            visited_urls = {start_url}
            
            # Add seed paths
            if seed_paths:
                for seed_path in seed_paths:
                    if seed_path.startswith('http'):
                        # Absolute URL
                        seed_url = seed_path
                    else:
                        # Relative URL
                        seed_url = normalize_url(start_url, seed_path)
                    
                    if same_origin_only and not same_origin(seed_url, self.start_origin):
                        logger.debug(f"⏭️ Skipping cross-origin seed path: {seed_path}")
                        continue
                    
                    if seed_url not in visited_urls:
                        url_queue.append((seed_url, 0))
                        visited_urls.add(seed_url)
                        logger.info(f"🌱 Added seed path: {seed_url}")
            
            pages_explored = 0
            total_links_found = 0
            total_forms_submitted = 0
            
            # BFS exploration
            while url_queue and pages_explored < max_pages:
                current_url, current_depth = url_queue.popleft()
                
                if current_depth >= max_depth:
                    logger.debug(f"⏭️ Skipping {current_url} - max depth reached")
                    continue
                
                # Explore the page
                links, forms_submitted = await self._explore_page(
                    page, current_url, max_links_per_page, max_forms_per_page
                )
                
                pages_explored += 1
                total_links_found += len(links)
                total_forms_submitted += forms_submitted
                
                # Add new links to queue
                for link in links:
                    if link not in visited_urls:
                        visited_urls.add(link)
                        url_queue.append((link, current_depth + 1))
                
                logger.info(f"📊 Page {pages_explored}/{max_pages}: {len(links)} links, {forms_submitted} forms")
            
            # Close page
            await page.close()
            
            # Prepare results
            endpoints = list(self.captured_endpoints.values())
            
            logger.info(f"🎉 Active crawl completed: {pages_explored} pages explored")
            logger.info(f"📊 Statistics: {total_links_found} links found, {total_forms_submitted} forms submitted")
            logger.info(f"🎯 Discovered {len(endpoints)} unique endpoints")
            
            # Log endpoint summary
            if endpoints:
                logger.info("📍 Final endpoints:")
                for endpoint in endpoints:
                    logger.info(f"   {endpoint.method} {endpoint.path} (params: {endpoint.param_names}, source: {endpoint.source}, status: {endpoint.status})")
            else:
                logger.warning("⚠️ No endpoints discovered - try increasing max_depth or provide seed_paths")
            
            return {
                "status": "success",
                "target_url": start_url,
                "discovered_endpoints": len(endpoints),
                "endpoints": [
                    {
                        "url": endpoint.url,
                        "path": endpoint.path,
                        "method": endpoint.method,
                        "param_names": endpoint.param_names,
                        "param_locs": endpoint.param_locs,
                        "status": endpoint.status,
                        "content_type": endpoint.content_type,
                        "source": endpoint.source
                    }
                    for endpoint in endpoints
                ],
                "capture_only": True,
                "pattern_fallback_used": False
            }
                
        except Exception as e:
            logger.error(f"❌ Active crawl failed: {e}")
            return {
                "status": "error",
                "target_url": start_url,
                "discovered_endpoints": 0,
                "endpoints": [],
                "capture_only": True,
                "pattern_fallback_used": False,
                "error": str(e)
            }

# Main function for backward compatibility
async def crawl_capture_only(
    context,
    start_url: str,
    max_pages: int = 12,
    max_links_per_page: int = 20,
    max_forms_per_page: int = 10,
    max_depth: int = 3,
    same_origin_only: bool = True,
    submit_get_forms: bool = True,
    seed_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Main function for active capture-only crawling.
    Discovers endpoints through BFS traversal, GET form submission, and seed paths.
    """
    crawler = EnhancedCrawler()
    return await crawler.crawl(
        context=context,
        start_url=start_url,
        max_pages=max_pages,
        max_links_per_page=max_links_per_page,
        max_forms_per_page=max_forms_per_page,
        max_depth=max_depth,
        same_origin_only=same_origin_only,
        submit_get_forms=submit_get_forms,
        seed_paths=seed_paths
    )