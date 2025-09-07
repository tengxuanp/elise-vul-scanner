const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000/api";
async function jsonFetch(url, options={}) {
  const r = await fetch(url, { ...options, headers: { "content-type":"application/json", ...(options.headers||{}) }});
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
export function crawl(url){ return jsonFetch(`${API_BASE}/crawl`, { method:"POST", body: JSON.stringify({target_url: url})}); }
export function assess({ endpoints, job_id, top_k=3 }){ return jsonFetch(`${API_BASE}/assess`, { method:"POST", body: JSON.stringify({ endpoints, job_id, top_k }) }); }
export function getReport(job_id){ return jsonFetch(`${API_BASE}/report`, { method:"POST", body: JSON.stringify({ job_id }) }); }
export function health(){ return jsonFetch(`${API_BASE}/healthz`); }
export { API_BASE };
