// src/app/api/api.js
import axios from 'axios';

// Base URL comes from env in dev/prod; hardcoded fallback is only for local.
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000/api';

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 0, // don't fight long scans with client timeouts
});

// Global response interceptor (cleaner error logs)
api.interceptors.response.use(
  (res) => res,
  (error) => {
    const payload = error?.response?.data;
    const msg = payload?.detail || payload?.message || error.message || 'Unknown API error';
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
export const fuzzByJob = async (job_id) =>
  (await api.post(`/fuzz/by_job/${job_id}`)).data; // ffuf summary/evidence

// Send only chosen endpoint shapes to the backend
export const fuzzSelected = async (job_id, selection /* array of {method,url,params?,body_keys?} */) =>
  (await api.post(`/fuzz/by_job/${job_id}`, { selection })).data;

// If you expose a pollable results route per job, keep this. If not, remove it.
export const getFuzzResultByJob = async (job_id) =>
  (await api.get(`/fuzz/result/${job_id}`)).data;

/* ============ Probe & Recommendations (job-scoped) ============ */
export const startProbe = async (job_id) =>
  (await api.post(`/probe/${job_id}`)).data;

export const getRecommendations = async (job_id) =>
  (await api.get(`/recommend_probed/${job_id}`)).data;

/* ===================== Exploitation ===================== */
// If your backend isn’t job-scoped for exploit, change to POST /exploit with body.
export const exploitTarget = async (job_id, tool, endpoint_url, options = {}) =>
  (await api.post(`/exploit/${job_id}`, { tool, endpoint_url, options })).data;

/* ===================== Reporting ===================== */
export const getReport = async (job_id) =>
  (await api.get(`/report/${job_id}`, { responseType: 'blob' })).data;

/* ===================== Utilities ===================== */
export const setAuthHeader = (key, value) => {
  if (!value) delete api.defaults.headers.common[key];
  else api.defaults.headers.common[key] = value;
};

export default {
  api,
  startJob,
  crawlTarget,
  getCrawlStatus,
  getCrawlResult,
  getCategorizedEndpoints,
  fuzzByJob,
  getFuzzResultByJob,
  startProbe,
  getRecommendations,
  exploitTarget,
  getReport,
  setAuthHeader,
};
