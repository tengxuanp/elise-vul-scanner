// API Types for Elise Vulnerability Scanner
// Version: 0.2.0

export type HTTPMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

export type RequestSource = "xhr" | "nav" | "other";

export interface EnrichedEndpoint {
  /** Full URL of the endpoint */
  url: string;
  /** URL path component (e.g., '/api/users') */
  path: string;
  /** HTTP method */
  method: HTTPMethod;
  /** All parameter names across all locations */
  params: string[];
  /** Parameter names grouped by location */
  param_locs: {
    query: string[];
    form: string[];
    json: string[];
  };
  /** HTTP response status code */
  status?: number;
  /** Request source type */
  source?: RequestSource;
  /** Response content type */
  content_type?: string;
  /** Number of times this endpoint was observed */
  seen?: number;
}

export interface CrawlMeta {
  /** Engine identifier (should be "playwright-strict") */
  engine: string;
  /** Number of pages visited during crawl */
  pagesVisited: number;
  /** Number of XHR/fetch requests captured */
  xhrCount: number;
  /** Number of unique endpoints emitted */
  emitted: number;
  /** Number of unique URL paths */
  uniquePaths: number;
  /** Number of endpoints with parameters */
  withParams: number;
}

export interface CrawlResponse {
  /** Array of discovered endpoints */
  endpoints: EnrichedEndpoint[];
  /** Crawl metadata */
  meta: CrawlMeta;
}

export interface CrawlRequest {
  /** Target URL to crawl */
  target_url: string;
  /** Maximum crawl depth */
  depth?: number;
  /** Maximum number of endpoints to discover */
  max_endpoints?: number;
  /** Whether to submit GET forms */
  submit_get_forms?: boolean;
  /** Whether to submit POST forms */
  submit_post_forms?: boolean;
  /** Seed URLs to start crawling from */
  seeds?: string[];
}

export interface HealthResponse {
  /** Overall system health */
  ok: boolean;
  /** Browser pool readiness */
  browser_pool_ready: boolean;
  /** ML models readiness */
  ml_ready: boolean;
  /** Available models */
  models: Record<string, any>;
  /** Available API routes */
  routes: Array<{
    method: string;
    path: string;
  }>;
}
