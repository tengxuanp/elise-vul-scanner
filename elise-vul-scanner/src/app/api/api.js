import axios from 'axios';

// Axios instance with baseURL
const api = axios.create({
  baseURL: 'http://localhost:8000/api',  // Adjust if needed
  timeout: 50000,
});

// Global Response Interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

// === Proxy-Based Crawl API ===

// 🟢 Start Proxy-Based Crawl with Target Domains
export const crawlTarget = async ({ target_url }) => {
  try {
    const res = await api.post('/crawl', { target_url });  // ✅ uses target_url now
    return res.data;
  } catch (err) {
    console.error('Crawl failed:', err);
    throw err;
  }
};


// 🟢 Poll for Crawl Results
export const getCrawlResult = async () => {
  try {
    const res = await api.get('/crawl/result');
    return res.data;
  } catch (err) {
    console.error('Get Crawl Result failed:', err);
    throw err;
  }
};

// === Fuzzing API ===

export const startFuzz = async (endpoints = []) => {
  try {
    const res = await api.post('/fuzz', { endpoints });
    return res.data;
  } catch (err) {
    console.error('Start Fuzzing failed:', err);
    throw err;
  }
};

export const getFuzzResult = async () => {
  try {
    const res = await api.get('/fuzz/result');
    return res.data;
  } catch (err) {
    console.error('Get Fuzz Result failed:', err);
    throw err;
  }
};

export const fuzzMultipleEndpoints = async (endpoints = []) => {
  try {
    const res = await api.post('/fuzz', { endpoints });
    return res.data;
  } catch (err) {
    console.error('Mass Fuzzing failed:', err);
    throw err;
  }
};

export const fuzzEndpoint = async (endpoint_url, method, payloads = []) => {
  try {
    const res = await api.post('/fuzz', {
      endpoint_url,
      method,
      payloads,
    });
    return res.data;
  } catch (err) {
    console.error('Fuzzing failed:', err);
    throw err;
  }
};

// === Exploit API ===

export const exploitTarget = (tool, endpoint_url, options = {}) => {
  return api.post('/exploit', { tool, endpoint_url, options });
};

// === Reporting API ===

export const getReport = () => {
  return api.get('/report', { responseType: 'blob' });
};
