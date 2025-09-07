"use client";
import { useState } from "react";
import { assess } from "../lib/api";

export default function TriagePanel({ endpoints, mlReady, onTriage }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setBusy(true); setErr(null);
    try {
      const res = await assess({ endpoints: endpoints || [], job_id: `triage-${Date.now()}`, top_k: 3 });
      onTriage && onTriage(res);
    } catch (e) {
      if (e.type === "ML_UNAVAILABLE") {
        setErr("ML models not available. Train models first using 'make models' or the training endpoint.");
      } else if (e.type === "SERVICE_UNAVAILABLE") {
        setErr("Service temporarily unavailable. Please try again.");
      } else {
        setErr(e?.body?.detail || e?.body?.error || e?.message || "Triage failed");
      }
    } finally { setBusy(false); }
  }

  return (
    <div className="bg-white rounded-xl shadow p-4 space-y-2">
      <h2 className="font-semibold">ML Triage</h2>
      <button
        className={`w-full rounded p-2 ${(!mlReady || !endpoints?.length) ? "bg-gray-300" : "bg-blue-600 text-white hover:bg-blue-700"}`}
        disabled={!mlReady || !endpoints?.length || busy}
        onClick={run}
        title={!mlReady ? "Model not ready (503)" : undefined}
      >
        {busy ? "Running…" : "Run ML Triage"}
      </button>
      {err && (
        <div className={`text-sm p-2 rounded ${
          err.includes("ML models not available") 
            ? "bg-amber-50 text-amber-700 border border-amber-200" 
            : "bg-red-50 text-red-700 border border-red-200"
        }`}>
          {err}
        </div>
      )}
    </div>
  );
}

/* Results renderer (attach to right column) */
TriagePanel.Results = function Results({ triage }) {
  if (!triage) return null;
  const results = triage.results || [];
  const summary = triage.summary || triage; // accept either shape
  return (
    <div className="bg-white rounded-xl shadow p-4 space-y-2">
      <h2 className="font-semibold">Triage Results</h2>
      <div className="text-sm text-gray-700">
        eligible: {summary.eligible_targets ?? "—"} ·
        positive: {summary.positive_targets ?? results.filter(r=>r.decision==="positive").length} ·
        abstain: {summary.abstained_targets ?? results.filter(r=>r.decision==="abstain").length} ·
        NA: {summary.not_applicable_targets ?? results.filter(r=>r.decision==="not_applicable").length} ·
        suspected: {results.filter(r=>r.decision==="suspected").length}
      </div>
      <div className="space-y-2 max-h-[60vh] overflow-auto">
        {results.map((r,i)=>(
          <div key={i} className="border rounded p-2">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs">{r?.target?.method} {r?.target?.path} ({r?.target?.in}:{r?.target?.param})</span>
              <span className={`px-2 py-0.5 rounded text-xs ${
                r.decision==="positive" ? "bg-emerald-100 text-emerald-800" :
                r.decision==="suspected" ? "bg-amber-100 text-amber-800" :
                r.decision==="abstain" ? "bg-gray-200 text-gray-700" :
                "bg-zinc-200 text-zinc-800"
              }`}>{r.decision}</span>
              {r.family && <span className="px-2 py-0.5 rounded text-xs bg-indigo-100 text-indigo-800">{r.family}</span>}
            </div>
            {r.proof && (
              <div className="text-xs text-gray-700 mt-1">
                {r.proof.xss_context && <>xss_context: <b>{r.proof.xss_context}</b> · </>}
                {typeof r.proof.sqli_boolean_delta === "number" && <>boolΔ: {r.proof.sqli_boolean_delta.toFixed(2)} · </>}
                {r.proof.sqli_error_based && <>error_based: true · </>}
                {r.proof.redirect_location && <>location: <span className="font-mono">{r.proof.redirect_location}</span></>}
              </div>
            )}
            {Array.isArray(r.recommendations) && r.recommendations.length>0 && (r.decision==="positive" || r.decision==="suspected") && (
              <div className="text-xs text-gray-600 mt-1">payload plan: {r.recommendations.map(p=>p.payload || p).slice(0,3).join("  •  ")}</div>
            )}
            {Array.isArray(r.why) && r.why.length>0 && <div className="text-xs text-gray-500 mt-1">why: {r.why.join("; ")}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}
