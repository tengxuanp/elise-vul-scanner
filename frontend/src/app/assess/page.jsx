"use client";
import { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { assess, getReport, health } from "../../lib/api";
import FindingsTable from "../components/FindingsTable";
import EvidenceModal from "../components/EvidenceModal";
import SummaryPanel from "../components/SummaryPanel";

export default function AssessPage() {
  const [loading, setLoading] = useState(false);
  const [assessmentResult, setAssessmentResult] = useState(null);
  const [view, setView] = useState(null);
  const [tab, setTab] = useState("positive");
  const [topK, setTopK] = useState(3);
  const [mlMode, setMlMode] = useState("Off");
  const router = useRouter();
  const searchParams = useSearchParams();
  const jobId = searchParams.get("jobId");
  const targetUrl = searchParams.get("targetUrl");

  useEffect(() => {
    // Fetch ML mode from healthz
    const fetchMLMode = async () => {
      try {
        const healthResponse = await health();
        // Healthz returns [data, status_code], we need the data part
        const healthData = Array.isArray(healthResponse) ? healthResponse[0] : healthResponse;
        const ml_active = healthData.use_ml;
        const using_defaults = healthData.defaults_in_use;
        
        if (ml_active) {
          setMlMode(using_defaults ? "Defaults only" : "Calibrated models");
        } else {
          setMlMode("Off");
        }
      } catch (error) {
        console.error("Failed to fetch ML mode:", error);
        setMlMode("Off");
      }
    };

    fetchMLMode();
  }, []);

  // Removed auto-assessment - user must click "Assess" button manually

  async function onAssess() {
    if (!jobId || !targetUrl) return;
    
    setLoading(true);
    try {
      const result = await assess({
        target_url: targetUrl,
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

  const findings = assessmentResult?.findings || [];
  const results = assessmentResult?.results || [];
  const negatives = results.filter(r => r.decision === "clean");
  
  // Calculate detailed breakdown for summary using new decision taxonomy
  const totalResults = results.length;
  const positiveResults = results.filter(r => r.decision === "positive");
  const suspectedResults = results.filter(r => r.decision === "suspected");
  const cleanResults = results.filter(r => r.decision === "clean");
  const naResults = results.filter(r => r.decision === "not_applicable");
  const errorResults = results.filter(r => r.decision === "error");
  
  // Calculate ML vs Probe confirmation
  const confirmedProbe = results.filter(r => 
    r.decision === "positive" && r.rank_source === "probe_only"
  ).length;
  
  const confirmedML = results.filter(r => 
    r.decision === "positive" && r.rank_source === "ml"
  ).length;

  if (!jobId || !targetUrl) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">Missing Parameters</h1>
          <p className="text-gray-600 mb-4">Job ID and target URL are required.</p>
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
                disabled={loading}
                className="px-4 py-2 rounded bg-blue-600 text-white disabled:opacity-50"
              >
                {loading ? "Assessing..." : (assessmentResult ? "Re-assess" : "Assess")}
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

          {/* ML Mode Badge */}
          <div className="mb-4">
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${
              mlMode === "Calibrated models" ? "bg-green-100 text-green-700" :
              mlMode === "Defaults only" ? "bg-amber-100 text-amber-700" :
              "bg-gray-100 text-gray-700"
            }`}>
              ML: {mlMode}
            </span>
          </div>

          {assessmentResult?.meta && (
            <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded">
              <div className="text-sm font-medium text-green-800 mb-2">
                Target: {targetUrl}
              </div>
              <div className="text-xs text-green-700">
                Endpoints supplied: {assessmentResult.meta.endpoints_supplied} | 
                Targets enumerated: {assessmentResult.meta.targets_enumerated} |
                Injections attempted: {assessmentResult.meta.injections_attempted} |
                Injections succeeded: {assessmentResult.meta.injections_succeeded} |
                Processing time: {(assessmentResult.meta.budget_ms_used / 1000).toFixed(1)}s
              </div>
            </div>
          )}

          {(() => {
            const naCount = results.filter(r => r.decision === "not_applicable").length;
            return naCount > 0 && (
              <div className="mb-4 p-2 bg-yellow-50 border border-yellow-200 rounded text-xs text-yellow-800">
                {naCount} endpoints had no parameters and were marked NA.
              </div>
            );
          })()}

          {assessmentResult && (
            <div className="mb-4 flex flex-wrap gap-2">
              <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-medium">
                Total: {totalResults}
              </span>
              <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-medium">
                Positive: {positiveResults.length}
              </span>
              <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded text-xs font-medium">
                Suspected: {suspectedResults.length}
              </span>
              <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs font-medium">
                Clean: {cleanResults.length}
              </span>
              <span className="px-2 py-1 bg-slate-100 text-slate-800 rounded text-xs font-medium">
                NA: {naResults.length}
              </span>
              <span className="px-2 py-1 bg-red-100 text-red-800 rounded text-xs font-medium">
                Error: {errorResults.length}
              </span>
              <span className="px-2 py-1 bg-indigo-100 text-indigo-800 rounded text-xs font-medium">
                Confirmed (Probe): {confirmedProbe}
              </span>
              <span className="px-2 py-1 bg-purple-100 text-purple-800 rounded text-xs font-medium">
                Confirmed (ML): {confirmedML}
              </span>
            </div>
          )}

          {assessmentResult ? (
            <>
              <div className="border-b mb-4 flex gap-4">
                <button
                  onClick={() => setTab("positive")}
                  className={`pb-2 -mb-px border-b-2 ${tab === "positive" ? "border-zinc-900" : "border-transparent"}`}
                >
                  Positive ({positiveResults.length})
                </button>
                <button
                  onClick={() => setTab("suspected")}
                  className={`pb-2 -mb-px border-b-2 ${tab === "suspected" ? "border-zinc-900" : "border-transparent"}`}
                >
                  Suspected ({suspectedResults.length})
                </button>
                <button
                  onClick={() => setTab("clean")}
                  className={`pb-2 -mb-px border-b-2 ${tab === "clean" ? "border-zinc-900" : "border-transparent"}`}
                >
                  Clean ({cleanResults.length})
                </button>
                <button
                  onClick={() => setTab("na")}
                  className={`pb-2 -mb-px border-b-2 ${tab === "na" ? "border-zinc-900" : "border-transparent"}`}
                >
                  NA ({naResults.length})
                </button>
                <button
                  onClick={() => setTab("error")}
                  className={`pb-2 -mb-px border-b-2 ${tab === "error" ? "border-zinc-900" : "border-transparent"}`}
                >
                  Error ({errorResults.length})
                </button>
              </div>

              {tab === "positive" ? (
                <FindingsTable results={positiveResults} onView={setView} />
              ) : tab === "suspected" ? (
                <FindingsTable results={suspectedResults} onView={setView} />
              ) : (
                <div className="overflow-x-auto">
                  {(() => {
                    const currentResults = tab === "clean" ? cleanResults : 
                                         tab === "na" ? naResults : 
                                         tab === "error" ? errorResults : [];
                    
                    return currentResults.length > 0 ? (
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="text-left text-zinc-500">
                            <th className="p-2">Target</th>
                            <th className="p-2">Param</th>
                            <th className="p-2">Decision</th>
                            <th className="p-2">Notes</th>
                          </tr>
                        </thead>
                        <tbody>
                          {currentResults.map((item, i) => (
                            <tr key={i} className="border-t">
                              <td className="p-2 break-all">{item.method} {item.url}</td>
                              <td className="p-2">{item.param_in}:{item.param}</td>
                              <td className="p-2">
                                <span className={`px-2 py-1 rounded text-xs ${
                                  item.decision === "clean" ? "bg-gray-100 text-gray-800" :
                                  item.decision === "not_applicable" ? "bg-slate-100 text-slate-800" :
                                  item.decision === "error" ? "bg-red-100 text-red-800" :
                                  "bg-yellow-100 text-yellow-800"
                                }`}>
                                  {item.decision}
                                </span>
                              </td>
                              <td className="p-2 text-zinc-600">
                                {item.rank_source === "ml" ? `ML proba: ${item.ml_proba?.toFixed(2) || 'N/A'}` : 
                                 item.rank_source === "probe_only" ? `Probe confirmed` :
                                 `Tested`}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div className="text-sm text-zinc-500 p-4">No {tab} targets to display.</div>
                    );
                  })()}
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-8 text-zinc-600">
              <p className="mb-4">Ready to assess {targetUrl}</p>
              <p className="text-sm">Click the "Assess" button above to start vulnerability assessment.</p>
            </div>
          )}
        </div>

        <SummaryPanel 
          assessmentResult={assessmentResult}
          mlMode={mlMode}
          jobId={jobId}
        />
      </div>

      <EvidenceModal
        open={!!view}
        onClose={() => setView(null)}
        evidenceId={view}
        jobId={jobId}
      />
    </div>
  );
}
