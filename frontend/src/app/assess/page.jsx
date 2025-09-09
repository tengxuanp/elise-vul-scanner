"use client";
import { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { assess, getReport, health } from "../../lib/api";
import FindingsTable from "../components/FindingsTable";
import EvidenceModal from "../components/EvidenceModal";
import SummaryPanel from "../components/SummaryPanel";
import DiagnosticsCard from "../components/DiagnosticsCard";
import Stepbar from "../components/Stepbar";
import { humanizeWhyCodes } from "../../lib/microcopy";

export default function AssessPage() {
  const [loading, setLoading] = useState(false);
  const [assessmentResult, setAssessmentResult] = useState(null);
  const [view, setView] = useState(null);
  const [tab, setTab] = useState("positive");
  const [topK, setTopK] = useState(3);
  const [mlMode, setMlMode] = useState("Off");
  const [strategy, setStrategy] = useState("auto");
  const router = useRouter();
  const searchParams = useSearchParams();
  const jobId = searchParams.get("jobId");
  const targetUrl = searchParams.get("targetUrl");
  
  // Initialize strategy from URL parameter
  useEffect(() => {
    const urlStrategy = searchParams.get("strategy");
    if (urlStrategy && ["auto", "probe_only", "ml_only", "ml_with_context", "hybrid"].includes(urlStrategy)) {
      setStrategy(urlStrategy);
    }
  }, [searchParams]);

  // Update URL when strategy changes
  const updateStrategy = (newStrategy) => {
    setStrategy(newStrategy);
    const params = new URLSearchParams(searchParams.toString());
    params.set("strategy", newStrategy);
    router.replace(`/assess?${params.toString()}`);
  };

  useEffect(() => {
    // Fetch ML mode from healthz
    const fetchMLMode = async () => {
      try {
        const healthResponse = await health();
        // Healthz returns [data, status_code], we need the data part
        const healthData = Array.isArray(healthResponse) ? healthResponse[0] : healthResponse;
        const use_ml = healthData.use_ml;
        const ml_active = healthData.ml_active;
        const models_available = healthData.models_available || {};
        const defaults_in_use = healthData.defaults_in_use;
        
        if (use_ml && ml_active) {
          // Check if we have actual models available
          const hasModels = Object.values(models_available).some(model => model.has_model);
          setMlMode(hasModels ? "Calibrated models" : "Defaults only");
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
    if (!jobId) return;
    
    setLoading(true);
    try {
      // Use new API contract - try job_id only first (from persisted endpoints)
      let result;
      try {
        result = await assess({
          job_id: jobId,
          top_k: topK,
          strategy: strategy
        });
      } catch (err) {
        // If no persisted endpoints, try with target_url
        if (targetUrl) {
          result = await assess({
            job_id: jobId,
            target_url: targetUrl,
            top_k: topK,
            strategy: strategy
          });
        } else {
          throw err;
        }
      }
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
  const negatives = results.filter(r => r.decision === "abstain");
  
  // Check for strategy violations
  const resultStrategy = assessmentResult?.meta?.strategy;
  const violations = assessmentResult?.meta?.violations || [];
  const hasProbeViolations = resultStrategy === "ml_only" && results.some(r => r.rank_source === "probe_only");
  const hasRedirectViolations = (resultStrategy === "ml_only" || resultStrategy === "ml_with_context") && 
                                results.some(r => r.family === "redirect");
  const hasViolations = violations.length > 0 || hasProbeViolations || hasRedirectViolations;
  
  // Calculate detailed breakdown for summary using new decision taxonomy
  const totalResults = results.length;
  const positiveResults = results.filter(r => r.decision === "positive");
  const suspectedResults = results.filter(r => r.decision === "suspected");
  const abstainResults = results.filter(r => r.decision === "abstain");
  const cleanResults = results.filter(r => r.decision === "clean");
  const naResults = results.filter(r => r.decision === "not_applicable");
  const errorResults = results.filter(r => r.decision === "error");
  
  // Consistency check: total should equal sum of all categories
  const categorySum = positiveResults.length + suspectedResults.length + abstainResults.length + cleanResults.length + naResults.length + errorResults.length;
  const countsConsistent = totalResults === categorySum;
  
  // Log inconsistency in dev mode
  if (!countsConsistent && process.env.NODE_ENV === 'development') {
    console.warn(`Counts mismatch for job ${jobId}: total=${totalResults}, categories=${categorySum}`);
  }
  
  // Calculate ML vs Probe confirmation
  const confirmedProbe = results.filter(r => 
    r.decision === "positive" && r.provenance === "Probe"
  ).length;
  
  const confirmedML = results.filter(r => 
    r.decision === "positive" && r.provenance === "Inject"
  ).length;

  if (!jobId) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">Missing Parameters</h1>
          <p className="text-gray-600 mb-4">Job ID is required.</p>
          <button
            onClick={() => router.push("/crawl")}
            className="px-4 py-2 rounded bg-blue-600 text-white"
          >
            Back to Crawl
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <Stepbar currentStep="assess" />
        
        {/* Mode Banner */}
        {assessmentResult && (
          <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-blue-900">
                  Mode: {assessmentResult.mode}
                </h2>
                <p className="text-sm text-blue-700">Job ID: {jobId}</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => router.push("/crawl")}
                  className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  New Crawl
                </button>
                <button
                  onClick={() => router.push(`/report?jobId=${jobId}`)}
                  className="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700"
                >
                  View Report
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="mt-8">
          <div className="flex items-center justify-between mb-6">
            <h1 className="text-3xl font-bold text-gray-900">Assessment Results</h1>
            <div className="flex gap-2">
              <button
                onClick={() => router.push("/crawl")}
                className="px-4 py-2 rounded bg-gray-600 text-white"
              >
                New Crawl
              </button>
              <button
                onClick={() => router.push(`/report?jobId=${jobId}`)}
                className="px-4 py-2 rounded bg-green-600 text-white"
              >
                View Report
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-semibold">Step 2: Assessment</h2>
                  <div className="flex gap-2">
                    <div className="flex items-center gap-2">
                      <label className="text-sm font-medium">Strategy:</label>
                      <select
                        value={strategy}
                        onChange={(e) => updateStrategy(e.target.value)}
                        className="border rounded px-2 py-1 text-sm"
                      >
                        <option value="auto">Auto (recommended)</option>
                        <option value="probe_only">Probe-only</option>
                        <option value="ml_only">ML-only</option>
                        <option value="ml_with_context">ML with Context</option>
                        <option value="hybrid">Hybrid (demo)</option>
                      </select>
                    </div>
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

                {/* Warning banner for enumeration issues */}
                {assessmentResult?.meta && 
                 assessmentResult.meta.targets_enumerated === 0 && 
                 assessmentResult.meta.endpoints_supplied > 0 && (
                  <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                    <div className="text-sm font-medium text-yellow-800">
                      ⚠️ No targets enumerated despite detected parameters
                    </div>
                    <div className="text-xs text-yellow-700 mt-1">
                      Check enumeration/gating rules. Endpoints may have parameters that weren't recognized.
                    </div>
                  </div>
                )}

                {assessmentResult?.meta && (
                  <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded">
                    <div className="text-sm font-medium text-green-800 mb-2">
                      Target: {targetUrl}
                    </div>
                    <div className="text-xs text-green-700 mb-2">
                      Strategy: {strategy === "auto" ? "Auto (recommended)" : 
                                strategy === "probe_only" ? "Probe-only" :
                                strategy === "ml_only" ? "ML-only" :
                                strategy === "ml_with_context" ? "ML with Context" :
                                strategy === "hybrid" ? "Hybrid (demo)" : strategy}
                    </div>
                    <div className="text-xs text-green-700 space-y-1">
                      <div>
                        Endpoints supplied: {assessmentResult.meta.endpoints_supplied} | 
                        Targets enumerated: {assessmentResult.meta.targets_enumerated}
                      </div>
                      <div>
                        Probes attempted: {assessmentResult.meta.probe_attempts || 0} | 
                        ML injections attempted: {assessmentResult.meta.ml_inject_attempts || 0}
                      </div>
                      <div>
                        Injections succeeded (Probe): {assessmentResult.meta.probe_successes || 0} | 
                        Injections succeeded (ML): {assessmentResult.meta.ml_inject_successes || 0}
                      </div>
                      <div>
                        Processing time: {assessmentResult.meta.processing_time || 
                          (assessmentResult.meta.processing_ms ? 
                            `${(assessmentResult.meta.processing_ms / 1000).toFixed(1)}s` : 
                            'N/A')}
                      </div>
                    </div>
                  </div>
                )}

                {/* Strategy hint */}
                {assessmentResult?.meta?.flags && (
                  (() => {
                    const flags = assessmentResult.meta.flags;
                    const probesDisabled = flags.probes_disabled && flags.probes_disabled.length > 0;
                    const injectionsDisabled = !flags.allow_injections;
                    
                    if (probesDisabled && injectionsDisabled) {
                      return null; // Both disabled - no hint needed
                    } else if (probesDisabled) {
                      return (
                        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                          <div className="text-sm text-yellow-800">
                            Probes disabled; Top-K injections only.
                          </div>
                        </div>
                      );
                    } else if (injectionsDisabled) {
                      return (
                        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                          <div className="text-sm text-yellow-800">
                            Probes only; injections disabled.
                          </div>
                        </div>
                      );
                    } else if (flags.force_ctx_inject_on_probe) {
                      return (
                        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                          <div className="text-sm text-yellow-800">
                            Probe + one context-guided injection per XSS hit (demo).
                          </div>
                        </div>
                      );
                    } else if (assessmentResult?.meta?.strategy === "ml_with_context") {
                      return (
                        <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded">
                          <div className="text-sm text-blue-800">
                            XSS canary for context; Top‑K injections. Redirect/SQLi probes disabled.
                          </div>
                        </div>
                      );
                    }
                    return null;
                  })()
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
                    <span 
                      className={`px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-medium ${!countsConsistent ? 'border-2 border-yellow-400' : ''}`}
                      title={!countsConsistent ? 'Counts mismatch: total ≠ sum of categories' : ''}
                    >
                      Total: {totalResults}
                      {!countsConsistent && <span className="ml-1 text-yellow-600">⚠️</span>}
                    </span>
                    <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-medium">
                      Positive: {positiveResults.length}
                    </span>
                    <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded text-xs font-medium">
                      Suspected: {suspectedResults.length}
                    </span>
                    <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs font-medium">
                      Abstain: {abstainResults.length}
                    </span>
                    <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-medium">
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
                        onClick={() => setTab("abstain")}
                        className={`pb-2 -mb-px border-b-2 ${tab === "abstain" ? "border-zinc-900" : "border-transparent"}`}
                      >
                        Abstain ({abstainResults.length})
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
                          const currentResults = tab === "abstain" ? abstainResults : 
                                               tab === "clean" ? cleanResults :
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
                                    <td className="p-2 break-all">{item.target?.method || item.method} {item.target?.url || item.url}</td>
                                    <td className="p-2">{item.target?.param_in || item.param_in}:{item.target?.param || item.param}</td>
                                    <td className="p-2">
                                      <span className={`px-2 py-1 rounded text-xs ${
                                        item.decision === "abstain" ? "bg-gray-100 text-gray-800" :
                                        item.decision === "clean" ? "bg-blue-100 text-blue-800" :
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
                
                {/* Violation Badge */}
                {hasViolations && (
                  <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded">
                    <div className="flex items-center">
                      <div className="text-sm text-red-800 font-medium">
                        ⚠️ Strategy Violation Detected
                      </div>
                    </div>
                    <div className="text-xs text-red-600 mt-1">
                      {hasProbeViolations && "Probe results found in ML-only mode. "}
                      {hasRedirectViolations && "Redirect results found in ML mode. "}
                      {violations.length > 0 && `Backend violations: ${violations.join(", ")}`}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="lg:col-span-1 space-y-6">
              <SummaryPanel 
                assessmentResult={assessmentResult}
                mlMode={mlMode}
                jobId={jobId}
                strategy={strategy}
              />
              <DiagnosticsCard healthz={assessmentResult?.healthz} />
            </div>
          </div>
        </div>

        <EvidenceModal
          open={!!view}
          onClose={() => setView(null)}
          evidenceId={view}
          jobId={jobId}
          meta={assessmentResult?.meta}
        />
      </div>
    </div>
  );
}
