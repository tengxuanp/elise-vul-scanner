"use client";
import { useState } from "react";
import { postFuzz } from "../lib/api";

export default function FuzzPanel({ endpoints, mlReady, onStarted }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  async function run() {
    setBusy(true); setMsg(null);
    try {
      // Convert endpoints to targets format for enhanced-fuzz
      const targets = (endpoints || []).map(endpoint => {
        // Extract parameters from param_locs
        const params = [];
        if (endpoint.param_locs?.query) params.push(...endpoint.param_locs.query);
        if (endpoint.param_locs?.form) params.push(...endpoint.param_locs.form);
        if (endpoint.param_locs?.json) params.push(...endpoint.param_locs.json);
        
        // Create targets for each parameter
        return params.map(param => ({
          url: endpoint.url,
          param: param,
          method: endpoint.method || 'GET'
        }));
      }).flat();
      
      const res = await postFuzz(targets);
      if (res?.job_id) onStarted && onStarted(res.job_id);
      setMsg(null);
    } catch (e) {
      if (e.type === "ML_UNAVAILABLE") {
        setMsg("ML models not available. Train models first using 'make models' or the training endpoint.");
      } else if (e.type === "SERVICE_UNAVAILABLE") {
        setMsg("Service temporarily unavailable. Please try again.");
      } else {
        setMsg(e?.body?.detail || e?.body?.error || e?.message || "Fuzz failed");
      }
    } finally { setBusy(false); }
  }

  const canRun = endpoints?.length > 0 && mlReady;

  return (
    <div className="bg-white rounded-xl shadow p-4 space-y-2">
      <h2 className="font-semibold">Fuzz</h2>
      <button
        className={`w-full rounded p-2 ${
          !canRun 
            ? "bg-gray-300 text-gray-500 cursor-not-allowed" 
            : "bg-rose-600 text-white hover:bg-rose-700"
        }`}
        disabled={!canRun || busy}
        onClick={run}
        title={
          !endpoints?.length 
            ? "No endpoints to fuzz" 
            : !mlReady 
            ? "ML models not ready - train models first" 
            : undefined
        }
      >
        {busy ? "Starting…" : "Run Fuzz"}
      </button>
      {!mlReady && endpoints?.length > 0 && (
        <div className="text-xs text-amber-600">
          ⚠️ ML models required for fuzzing
        </div>
      )}
      {msg && (
        <div className={`text-sm p-2 rounded ${
          msg.includes("ML models not available") 
            ? "bg-amber-50 text-amber-700 border border-amber-200" 
            : "bg-red-50 text-red-700 border border-red-200"
        }`}>
          {msg}
        </div>
      )}
    </div>
  );
}
