"use client";
import { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { assess, getReport } from "../../lib/api";
import FindingsTable from "../components/FindingsTable";
import EvidenceModal from "../components/EvidenceModal";

export default function AssessPage() {
  const [loading, setLoading] = useState(false);
  const [crawlResult, setCrawlResult] = useState(null);
  const [assessmentResult, setAssessmentResult] = useState(null);
  const [view, setView] = useState(null);
  const [tab, setTab] = useState("confirmed");
  const [topK, setTopK] = useState(3);
  const router = useRouter();
  const searchParams = useSearchParams();
  const jobId = searchParams.get("jobId");

  useEffect(() => {
    if (jobId) {
      const stored = sessionStorage.getItem(`crawl_${jobId}`);
      if (stored) {
        setCrawlResult(JSON.parse(stored));
      }
    }
  }, [jobId]);

  async function onAssess() {
    if (!crawlResult || !jobId) return;
    
    setLoading(true);
    try {
      const result = await assess({
        endpoints: crawlResult.endpoints,
        job_id: jobId,
        top_k: topK
      });
      setAssessmentResult(result);
    } catch (error) {
      console.error("Assessment error:", error);
      alert("Assessment failed: " + error.message);
    } finally {
      setLoading(false);
    }
  }

  async function onExport() {
    if (!jobId) return;
    try {
      const result = await getReport(jobId);
      const blob = new Blob([result.markdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `elise-report-${jobId}.md`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Export error:", error);
      alert("Export failed: " + error.message);
    }
  }

  // Calculate target count from endpoints
  const calculateTargetCount = (endpoints) => {
    return endpoints?.reduce((total, ep) => {
      const paramLocs = ep.param_locs || {};
      const queryCount = paramLocs.query?.length || 0;
      const formCount = paramLocs.form?.length || 0;
      const jsonCount = paramLocs.json?.length || 0;
      const legacyCount = ep.params ? Object.keys(ep.params).length : 0;
      return total + queryCount + formCount + jsonCount + legacyCount;
    }, 0) || 0;
  };

  const targetCount = calculateTargetCount(crawlResult?.endpoints);
  const findings = assessmentResult?.findings || [];
  const negatives = (assessmentResult?.results || []).filter(r => r.decision === "tested_negative");
  
  // Calculate detailed breakdown for summary
  const confirmedProbe = (assessmentResult?.results || []).filter(r => 
    r.decision === "confirmed" && r.why?.includes("probe_proof")
  ).length;
  
  const confirmedMLInject = (assessmentResult?.results || []).filter(r => 
    r.decision === "confirmed" && 
    r.why?.includes("ml_ranked") && 
    r.why?.includes("inject_confirmed")
  ).length;

  if (!crawlResult) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">No Crawl Data Found</h1>
          <button
            onClick={() => router.push("/scan")}
            className="px-4 py-2 rounded bg-blue-600 text-white"
          >
            Back to Scan
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">Assessment Results</h1>
        <div className="flex gap-2">
          <button
            onClick={() => router.push("/scan")}
            className="px-4 py-2 rounded bg-gray-600 text-white"
          >
            New Scan
          </button>
          <button
            onClick={() => router.push(`/evidence/${jobId}`)}
            className="px-4 py-2 rounded bg-green-600 text-white"
          >
            View Evidence
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[2fr_1fr] gap-6">
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">Step 2: Assessment</h2>
            <div className="flex gap-2">
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium">Top-K:</label>
                <select
                  value={topK}
                  onChange={(e) => setTopK(parseInt(e.target.value))}
                  className="border rounded px-2 py-1 text-sm"
                >
                  <option value={1}>1</option>
                  <option value={2}>2</option>
                  <option value={3}>3</option>
                  <option value={4}>4</option>
                  <option value={5}>5</option>
                </select>
              </div>
              <button
                onClick={onAssess}
                disabled={targetCount === 0 || loading}
                className="px-4 py-2 rounded bg-blue-600 text-white disabled:opacity-50"
              >
                Assess {targetCount > 0 && `(${targetCount})`}
              </button>
              <button
                onClick={onExport}
                disabled={!assessmentResult || loading}
                className="px-4 py-2 rounded bg-emerald-600 text-white disabled:opacity-50"
              >
                Export Report
              </button>
            </div>
          </div>

          {crawlResult.endpoints.length > 0 && (
            <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded">
              <div className="text-sm font-medium text-green-800 mb-2">
                Crawled Endpoints ({crawlResult.endpoints.length})
              </div>
              {crawlResult.endpoints.map((ep, i) => (
                <div key={i} className="text-xs text-green-700 mb-1">
                  {ep.method} {ep.url} - {Object.keys(ep.param_locs || {}).reduce((acc, loc) => acc + (ep.param_locs[loc]?.length || 0), 0)} params
                </div>
              ))}
            </div>
          )}

          {assessmentResult?.summary?.na > 0 && (
            <div className="mb-4 p-2 bg-yellow-50 border border-yellow-200 rounded text-xs text-yellow-800">
              {assessmentResult.summary.na} endpoints had no parameters and were marked NA.
            </div>
          )}

          {assessmentResult && (
            <div className="mb-4 flex flex-wrap gap-2">
              <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-medium">
                Total: {assessmentResult.summary.total}
              </span>
              <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-medium">
                Probe: {confirmedProbe}
              </span>
              <span className="px-2 py-1 bg-purple-100 text-purple-800 rounded text-xs font-medium">
                ML: {confirmedMLInject}
              </span>
              <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs font-medium">
                Clean: {negatives.length}
              </span>
            </div>
          )}

          {assessmentResult && (
            <>
              <div className="border-b mb-4 flex gap-4">
                <button
                  onClick={() => setTab("confirmed")}
                  className={`pb-2 -mb-px border-b-2 ${tab === "confirmed" ? "border-zinc-900" : "border-transparent"}`}
                >
                  Confirmed ({findings.length})
                </button>
                <button
                  onClick={() => setTab("clean")}
                  className={`pb-2 -mb-px border-b-2 ${tab === "clean" ? "border-zinc-900" : "border-transparent"}`}
                >
                  Clean ({negatives.length})
                </button>
              </div>

              {tab === "confirmed" ? (
                <FindingsTable findings={findings} results={assessmentResult.results || []} onView={setView} />
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
            </>
          )}
        </div>

        <aside className="card p-6">
          <h3 className="font-semibold mb-4">Summary</h3>
          <ul className="text-sm space-y-2">
            <li>Endpoints: {assessmentResult?.meta?.endpoints_crawled ?? crawlResult.endpoints.length}</li>
            <li>Targets: {assessmentResult?.meta?.targets_enumerated ?? targetCount}</li>
            <li>Total (incl. NA): {assessmentResult?.summary?.total ?? 0}</li>
            <li>Confirmed (Probe): {confirmedProbe}</li>
            <li>Confirmed (ML+Inject): {confirmedMLInject}</li>
            <li>Clean: {negatives.length}</li>
            <li>NA (no params): {assessmentResult?.summary?.na ?? 0}</li>
            <li>Job ID: {jobId || "-"}</li>
          </ul>
        </aside>
      </div>

      <EvidenceModal
        open={!!view}
        onClose={() => setView(null)}
        evidence={view}
        results={assessmentResult?.results || []}
      />
    </div>
  );
}
