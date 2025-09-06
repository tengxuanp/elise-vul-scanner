"use client";
import { useState } from "react";
import { postCrawl } from "../lib/api";

export default function CrawlForm({ onCrawled }) {
  const [url, setUrl] = useState("http://localhost:5001/");
  const [maxDepth, setMaxDepth] = useState(3);
  const [maxPages, setMaxPages] = useState(12);
  const [maxLinksPerPage, setMaxLinks] = useState(20);
  const [submitGetForms, setSubmitGetForms] = useState(true);
  const [seedPaths, setSeedPaths] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState(null);

  async function run() {
    setBusy(true); setNote(null);
    try {
      const payload = {
        target_url: url,
        max_depth: Number(maxDepth), 
        max_pages: Number(maxPages),
        max_endpoints: Number(maxLinksPerPage),
        submit_get_forms: !!submitGetForms,
        seed_paths: seedPaths ? seedPaths.split(",").map(s => s.trim()).filter(Boolean) : null
      };
      const res = await postCrawl(payload);
      if (res.capture_only !== true) setNote("Warning: pattern candidates present; they won't be fuzzed until proven.");
      onCrawled(res.endpoints || []);
    } catch (e) {
      setNote(e?.body?.detail || e?.body?.error || "Crawl failed");
      onCrawled([]);
    } finally {
      setBusy(false);
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
      </div>
      <input className="w-full border rounded p-2" value={seedPaths} onChange={e=>setSeedPaths(e.target.value)} placeholder="seed paths (comma separated)" />
      <button className={`w-full rounded p-2 ${busy?"bg-gray-300":"bg-indigo-600 text-white hover:bg-indigo-700"}`} disabled={busy} onClick={run}>
        {busy ? "Crawling…" : "Run Crawl"}
      </button>
      {note && <div className="text-sm text-amber-700">{note}</div>}
    </div>
  );
}
