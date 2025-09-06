"use client";
import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { getHealth, getReport } from "../lib/api";
import HealthBadge from "../components/HealthBadge";
import CrawlForm from "../components/CrawlForm";
import EndpointTable from "../components/EndpointTable";
import TriagePanel from "../components/TriagePanel";
import FuzzPanel from "../components/FuzzPanel";
import FindingsTable from "../components/FindingsTable";

export default function Page() {
  const { data: health } = useQuery({ queryKey: ["health"], queryFn: getHealth });
  const mlReady = !!(health && health.ml_ready);
  const [endpoints, setEndpoints] = useState([]);
  const [triage, setTriage] = useState(null);
  const [jobId, setJobId] = useState(null);
  const [report, setReport] = useState(null);
  const [fuzzProgress, setFuzzProgress] = useState(null);

  useEffect(() => {
    if (!jobId) return;
    let ticks = 0, lastFindings = 0, attempts = 0;
    const id = setInterval(async () => {
      try {
        attempts++;
        const r = await getReport(jobId);
        setReport(r);
        
        // Update progress tracking
        const f = Array.isArray(r.findings) ? r.findings.length : 0;
        setFuzzProgress({
          attempts,
          findings: f,
          totalTargets: r.summary?.targets_total || 0,
          positive: r.summary?.positive || 0,
          abstain: r.summary?.abstain || 0,
          suspected: r.summary?.suspected || 0
        });
        
        if (f === lastFindings) ticks++; else { ticks = 0; lastFindings = f; }
        if (ticks >= 5) clearInterval(id); // stop after ~7.5s idle
      } catch {
        clearInterval(id);
      }
    }, 1500);
    return () => clearInterval(id);
  }, [jobId]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Elise — Probe-first Scanner</h1>
        <HealthBadge />
      </div>

      {/* ML Readiness Banner */}
      {!mlReady && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-amber-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-amber-800">
                ML Models Not Ready
              </h3>
              <div className="mt-2 text-sm text-amber-700">
                <p>Train models first to enable fuzzing. Run <code className="bg-amber-100 px-1 rounded">make models</code> or use the training endpoint.</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Fuzz Progress Banner */}
      {fuzzProgress && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <svg className="animate-spin h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-blue-800">
                  Fuzzing in Progress
                </h3>
                <div className="mt-1 text-sm text-blue-700">
                  <p>Attempts: {fuzzProgress.attempts} · Findings: {fuzzProgress.findings} · Targets: {fuzzProgress.totalTargets}</p>
                  <p>Positive: {fuzzProgress.positive} · Suspected: {fuzzProgress.suspected} · Abstain: {fuzzProgress.abstain}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-12 gap-5">
        <div className="col-span-12 lg:col-span-3 space-y-4">
          <CrawlForm onCrawled={(eps) => { setEndpoints(eps || []); setTriage(null); setJobId(null); setReport(null); setFuzzProgress(null); }} />
          <TriagePanel endpoints={endpoints} mlReady={mlReady} onTriage={(res) => setTriage(res)} />
          <FuzzPanel endpoints={endpoints} mlReady={mlReady} onStarted={(id) => { setJobId(id); setFuzzProgress({ attempts: 0, findings: 0, totalTargets: 0, positive: 0, abstain: 0, suspected: 0 }); }} />
        </div>

        <div className="col-span-12 lg:col-span-5 space-y-4">
          <EndpointTable endpoints={endpoints} />
        </div>

        <div className="col-span-12 lg:col-span-4 space-y-4">
          {triage && <TriagePanel.Results triage={triage} />}
          {report && <FindingsTable report={report} />}
        </div>
      </div>
    </div>
  );
}