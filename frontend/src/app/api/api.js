// frontend/src/app/api/api.js
import axios from 'axios';

// Base URL comes from env in dev/prod; hardcoded fallback is only for local.
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000/api';

export const api = axios.create({
  baseURL: API_BASE,
  // Don't fight long scans with client timeouts
  timeout: 0,
});

// -------- helpers --------
const normalizeBearer = (token) => {
  if (!token) return null;
  const t = String(token).trim();
  return t.toLowerCase().startsWith('bearer ') ? t : `Bearer ${t}`;
};

// Pull bearer from several possible option keys for robustness
const pickBearerFromOpts = (opts = {}) =>
  normalizeBearer(
    opts.bearerToken ??
      opts.bearer_token ??
      opts.bearer ??
      opts.token ??
      null
  );

// Global response interceptor (cleaner error logs)
api.interceptors.response.use(
  (res) => res,
  (error) => {
    const payload = error?.response?.data;
    const msg =
      payload?.detail ||
      payload?.message ||
      error.message ||
      'Unknown API error';
    console.error('API Error:', msg, payload);
    return Promise.reject(error);
  }
);

/* ===================== Jobs ===================== */
export const startJob = async ({ target, notes = '' }) =>
  (await api.post('/job/start', { target, notes })).data; // -> { job_id }

/* ===================== Crawl ===================== */
// auth: {mode:'none'} | {mode:'cookie', cookie} | {mode:'bearer', bearer_token} | {mode:'form', login_url, username, password, username_selector, password_selector, submit_selector}
export const crawlTarget = async ({ job_id, target_url, auth }) =>
  (await api.post('/crawl', { job_id, target_url, auth })).data;

export const getCrawlStatus = async (job_id) =>
  (await api.get(`/crawl/status/${job_id}`)).data; // -> { status }

export const getCrawlResult = async (job_id) =>
  (await api.get(`/crawl/result/${job_id}`)).data; // -> { endpoints, captured_requests }

/* ========== Categorization (still target-scoped) ========== */
export const getCategorizedEndpoints = async (target_url) =>
  (await api.get('/categorized-endpoints', { params: { target_url } })).data;

/* ===================== Fuzzing ===================== */
/**
 * Run fuzzing for a job.
 * opts = {
 *   engine: 'core' | 'ffuf' | 'hybrid' (default 'core'),
 *   selection: [{ method, url, params? }] | null,
 *   bearerToken | bearer_token | bearer | token: string | null,  // auto 'Bearer ' prefix if missing
 *   topN: number (ffuf only),
 *   threshold: number (ffuf only),
 *   extraHeaders | extra_headers: { [k: string]: string }  // optional additional headers
 * }
 */
export const fuzzByJob = async (job_id, opts = {}) => {
  const {
    engine = 'core',
    selection = null,
    topN = 3,
    threshold = 0.2,
    extraHeaders,
    extra_headers,
  } = opts;

  const bearer = pickBearerFromOpts(opts);
  const extras = extraHeaders || extra_headers || null;

  const body = {
    engine,
    selection,
    top_n: topN,
    threshold,
  };

  if (bearer) body.bearer_token = bearer;
  if (extras) body.extra_headers = extras;

  return (await api.post(`/fuzz/by_job/${job_id}`, body)).data;
};

// Convenience: send only chosen endpoint shapes to the backend (defaults to core engine)
export const fuzzSelected = async (
  job_id,
  selection, // array of { method, url, params? }
  opts = {} // same shape as fuzzByJob opts (you can pass bearerToken/bearer_token/engine/extraHeaders here)
) => {
  const {
    engine = 'core',
    topN = 3,
    threshold = 0.2,
    extraHeaders,
    extra_headers,
  } = opts;

  const bearer = pickBearerFromOpts(opts);
  const extras = extraHeaders || extra_headers || null;

  const body = {
    engine,
    selection,
    top_n: topN,
    threshold,
  };

  if (bearer) body.bearer_token = bearer;
  if (extras) body.extra_headers = extras;

  return (await api.post(`/fuzz/by_job/${job_id}`, body)).data;
};

// If you expose a pollable results route per job, keep this.
export const getFuzzResultByJob = async (job_id) =>
  (await api.get(`/fuzz/result/${job_id}`)).data;

/* ============ Probe & Recommendations (job-scoped) ============ */
export const startProbe = async (job_id) =>
  (await api.post(`/probe/${job_id}`)).data;

// Backend expected path is job-scoped; adjust if your backend uses a flat route.
export const getRecommendations = async (job_id) =>
  (await api.get(`/recommend_probed/${job_id}`)).data;

/* ===================== Exploitation ===================== */
// If your backend isn’t job-scoped for exploit, change to POST /exploit with body.
export const exploitTarget = async (job_id, tool, endpoint_url, options = {}) =>
  (await api.post(`/exploit/${job_id}`, { tool, endpoint_url, options })).data;

/* ===================== Reporting ===================== */
// JSON report
export const getReport = async (job_id) =>
  (await api.get(`/report/${job_id}`)).data;

// Markdown report (string)
export const getReportMarkdown = async (job_id) =>
  (await api.get(`/report/${job_id}/md`, { responseType: 'text' })).data;

/* ===================== Utilities ===================== */
export const setAuthHeader = (key, value) => {
  if (!value) delete api.defaults.headers.common[key];
  else api.defaults.headers.common[key] = value;
};

// Convenience for UI: normalize a raw token into a proper Authorization header
export const setBearerAuth = (token) => {
  const val = normalizeBearer(token);
  if (!val) return setAuthHeader('Authorization', undefined);
  setAuthHeader('Authorization', val);
};

export default {
  api,
  startJob,
  crawlTarget,
  getCrawlStatus,
  getCrawlResult,
  getCategorizedEndpoints,
  fuzzByJob,
  fuzzSelected,
  getFuzzResultByJob,
  startProbe,
  getRecommendations,
  exploitTarget,
  getReport,
  getReportMarkdown,
  setAuthHeader,
  setBearerAuth,
};
