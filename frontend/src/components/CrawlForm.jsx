"use client";
import { useState } from "react";
import { crawl } from "../lib/api";

export default function CrawlForm({ onCrawled, onMeta }) {
  const [url, setUrl] = useState("http://localhost:5001/");
  const [maxDepth, setMaxDepth] = useState(3);
  const [maxPages, setMaxPages] = useState(12);
  const [maxLinksPerPage, setMaxLinks] = useState(20);
  const [submitGetForms, setSubmitGetForms] = useState(true);
  const [submitPostForms, setSubmitPostForms] = useState(true);
  const [seedPaths, setSeedPaths] = useState("");
  const [loading, setLoading] = useState(false);
  const [note, setNote] = useState(null);

  async function run() {
    setLoading(true);
    setNote(null);
    try {
      const payload = {
        target_url: url,
        max_depth: Number(maxDepth) || 2,
        max_endpoints: Number(maxLinksPerPage) || 30,
        submit_get_forms: submitGetForms,
        submit_post_forms: submitPostForms,
        seeds: seedPaths ? seedPaths.split(",").map(s => s.trim()).filter(Boolean) : []
      };
      const res = await crawl(payload);
      onCrawled(res.endpoints || []);
      if (onMeta) onMeta(res.meta || {});
      
      // Show helper message for empty results
      if (res.endpoints && res.endpoints.length === 0) {
        setNote("Got 0 endpoints. For dev, try: add seed paths or ensure the site is active. Default seeds are auto-filled.");
      }
    } catch (e) {
      setNote(e?.body?.detail || e?.body?.error || "Crawl failed");
      onCrawled([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="bg-white rounded-xl shadow p-4 space-y-3">
      <h2 className="font-semibold">Crawl</h2>
      <input className="w-full border rounded p-2" value={url} onChange={e=>setUrl(e.target.value)} placeholder="http://target/" />
      <div className="grid grid-cols-2 gap-2">
        <input className="border rounded p-2" type="number" value={maxDepth} onChange={e=>setMaxDepth(e.target.value)} placeholder="max depth" />
        <input className="border rounded p-2" type="number" value={maxPages} onChange={e=>setMaxPages(e.target.value)} placeholder="max pages" />
        <input className="border rounded p-2" type="number" value={maxLinksPerPage} onChange={e=>setMaxLinks(e.target.value)} placeholder="max endpoints" />
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={submitGetForms} onChange={e=>setSubmitGetForms(e.target.checked)} />
          Submit GET forms
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={submitPostForms} onChange={e=>setSubmitPostForms(e.target.checked)} />
          Submit POST forms
        </label>
      </div>
      <input className="w-full border rounded p-2" value={seedPaths} onChange={e=>setSeedPaths(e.target.value)} placeholder="seed paths (comma separated)" />
      <button className={`w-full rounded p-2 ${loading?"bg-gray-300":"bg-indigo-600 text-white hover:bg-indigo-700"}`} disabled={loading} onClick={run}>
        {loading ? "Crawling…" : "Run Crawl"}
      </button>
      {note && <div className="text-sm text-amber-700">{note}</div>}
    </div>
  );
}
