"use client";
import { useState } from "react";
import Stepbar from "../components/Stepbar";
import FindingsTable from "../components/FindingsTable";
import EvidenceModal from "../components/EvidenceModal";
import { crawl, assess, getReport } from "../../lib/api";

export default function ScanPage() {
  const [active, setActive] = useState("crawl");
  const [endpoints, setEndpoints] = useState([]);
  const [res, setRes] = useState(null);
  const [jobId, setJobId] = useState("");
  const [view, setView] = useState(null);
  const [tab, setTab] = useState("confirmed");
  const [loading, setLoading] = useState(false);

  async function onCrawl() {
    setLoading(true);
    try {
      const url = document.getElementById("seed").value;
      console.log("Crawling URL:", url);
      const out = await crawl(url);
      console.log("Crawl response:", out);
      setEndpoints(out.endpoints || []);
      setActive("probe");
    } catch (error) {
      console.error("Crawl error:", error);
      alert("Crawl failed: " + error.message);
    } finally { 
      setLoading(false); 
    }
  }
  async function onAssess() {
    setLoading(true);
    try {
      const jid = Date.now().toString(); setJobId(jid);
      const out = await assess({ endpoints, job_id: jid, top_k: 3 });
      setRes(out); setActive("assess");
    } finally { setLoading(false); }
  }
  async function onExport() {
    if (!jobId) return;
    const out = await getReport(jobId);
    const blob = new Blob([out.markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `elise-report-${jobId}.md`; a.click();
    URL.revokeObjectURL(url); setActive("report");
  }

  // Calculate target count from endpoints
  const calculateTargetCount = (endpoints) => {
    return endpoints.reduce((total, ep) => {
      const paramLocs = ep.param_locs || {};
      const queryCount = paramLocs.query?.length || 0;
      const formCount = paramLocs.form?.length || 0;
      const jsonCount = paramLocs.json?.length || 0;
      
      // Handle legacy params object
      const legacyCount = ep.params ? Object.keys(ep.params).length : 0;
      
      return total + queryCount + formCount + jsonCount + legacyCount;
    }, 0);
  };

  const targetCount = calculateTargetCount(endpoints);
  const findings = res?.findings || [];
  const negatives = (res?.results || []).filter(r=>r.decision==="tested_negative");
  
  // Calculate detailed breakdown for summary
  const confirmedProbe = (res?.results || []).filter(r => 
    r.decision === "confirmed" && r.why?.includes("probe_proof")
  ).length;
  
  const confirmedMLInject = (res?.results || []).filter(r => 
    r.decision === "confirmed" && 
    r.why?.includes("ml_ranked") && 
    r.why?.includes("inject_confirmed")
  ).length;

  return (
    <div className="mx-auto max-w-6xl p-4">
      <h1 className="text-2xl font-bold mb-2">Elise — Crawl & Assess</h1>
      <Stepbar active={active} />
      <div className="grid grid-cols-1 md:grid-cols-[2fr_1fr] gap-4">
        <div className="card p-4">
          <div className="flex gap-2 mb-3">
            <input id="seed" type="url" placeholder="https://target" className="flex-1 border rounded px-3 py-2" />
            <button onClick={onCrawl} disabled={loading} className="px-3 py-2 rounded bg-zinc-900 text-white disabled:opacity-50">
              {loading ? "Crawling..." : "Crawl"}
            </button>
            <button onClick={onAssess} disabled={targetCount === 0 || loading} className="px-3 py-2 rounded bg-blue-600 text-white disabled:opacity-50">
              Assess {targetCount > 0 && `(${targetCount})`}
            </button>
            <button onClick={onExport} disabled={!res || loading} className="px-3 py-2 rounded bg-emerald-600 text-white disabled:opacity-50">Export</button>
          </div>
          {endpoints.length > 0 && (
            <div className="mb-3 p-3 bg-green-50 border border-green-200 rounded">
              <div className="text-sm font-medium text-green-800 mb-2">Crawled Endpoints ({endpoints.length})</div>
              {endpoints.map((ep, i) => (
                <div key={i} className="text-xs text-green-700 mb-1">
                  {ep.method} {ep.url} - {Object.keys(ep.param_locs || {}).reduce((acc, loc) => acc + (ep.param_locs[loc]?.length || 0), 0)} params
                </div>
              ))}
            </div>
          )}
          <div className="border-b mb-3 flex gap-4">
            <button onClick={()=>setTab("confirmed")} className={`pb-2 -mb-px border-b-2 ${tab==="confirmed"?"border-zinc-900":"border-transparent"}`}>Confirmed ({findings.length})</button>
            <button onClick={()=>setTab("clean")} className={`pb-2 -mb-px border-b-2 ${tab==="clean"?"border-zinc-900":"border-transparent"}`}>Clean ({negatives.length})</button>
          </div>
          {res?.summary?.na > 0 && (
            <div className="mb-3 p-2 bg-yellow-50 border border-yellow-200 rounded text-xs text-yellow-800">
              {res.summary.na} endpoints had no parameters and were marked NA.
            </div>
          )}
          {tab==="confirmed" ? (
            <FindingsTable findings={findings} results={res?.results || []} onView={setView}/>
          ) : (
            <div className="overflow-x-auto">
              {negatives.length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-zinc-500">
                      <th className="p-2">Target</th>
                      <th className="p-2">Param</th>
                      <th className="p-2">Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {negatives.map((item, i) => (
                      <tr key={i} className="border-t">
                        <td className="p-2 break-all">{item.target.method} {item.target.url}</td>
                        <td className="p-2">{item.target.param_in}:{item.target.param}</td>
                        <td className="p-2 text-zinc-600">
                          {item.p ? `Tried ML Top-K` : `Tested`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="text-sm text-zinc-500 p-4">No clean targets to display.</div>
              )}
            </div>
          )}
        </div>
        <aside className="card p-4">
          <h3 className="font-semibold mb-2">Summary</h3>
          <ul className="text-sm space-y-1">
            <li>Endpoints: {res?.meta?.endpoints_crawled ?? endpoints.length}</li>
            <li>Targets: {res?.meta?.targets_enumerated ?? targetCount}</li>
            <li>Total (incl. NA): {res?.summary?.total ?? 0}</li>
            <li>Confirmed (Probe): {confirmedProbe}</li>
            <li>Confirmed (ML+Inject): {confirmedMLInject}</li>
            <li>Clean: {negatives.length}</li>
            <li>NA (no params): {res?.summary?.na ?? 0}</li>
            <li>Job ID: {jobId || "-"}</li>
          </ul>
        </aside>
      </div>
      <EvidenceModal open={!!view} onClose={()=>setView(null)} evidence={view} results={res?.results || []} />
    </div>
  );
}
