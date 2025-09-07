const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000/api";

export async function crawl(body) {
  const r = await fetch(`${API_BASE}/crawl`, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(await r.text()); return r.json();
}

export async function assess({ endpoints, job_id, top_k=3 }) {
  const r = await fetch(`${API_BASE}/assess`, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify({ endpoints, job_id, top_k }) });
  if (!r.ok) throw new Error(await r.text()); return r.json();
}

export async function getReport(job_id) {
  const r = await fetch(`${API_BASE}/report`, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify({ job_id }) });
  if (!r.ok) throw new Error(await r.text()); return r.json();
}

export async function health() { 
  const r = await fetch(`${API_BASE}/healthz`); 
  if (!r.ok) throw new Error(await r.text()); 
  return r.json(); 
}

export { API_BASE };