"use client";
import { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { assess, getReport, health } from "../../lib/api";
import FindingsTable from "../components/FindingsTable";
import EvidenceModal from "../components/EvidenceModal";
import SummaryPanel from "../components/SummaryPanel";
import DiagnosticsCard from "../components/DiagnosticsCard";
import Stepbar from "../components/Stepbar";
import StrategySelector from "../components/StrategySelector";
import { humanizeWhyCodes } from "../../lib/microcopy";

export default function AssessPage() {
  const [loading, setLoading] = useState(false);
  const [assessmentResult, setAssessmentResult] = useState(null);
  const [view, setView] = useState(null);
  const [tab, setTab] = useState("positive");
  const [mlMode, setMlMode] = useState("Off");
  // Default strategy configuration (Smart-XSS)
  const defaultStrategyConfig = {
    strategy: "smart_xss",
    families: ["xss", "sqli"],
    xss: {
      ml_mode: "auto",
      tau_ml: 0.80,
      rule_conf_gate: 0.85,
      topk: 3
    },
    sqli: {
      ml_mode: "never",
      short_circuit: { enabled: true, M: 12, K: 20 },
      topk: 6
    }
  };
  
  const [strategyConfig, setStrategyConfig] = useState(defaultStrategyConfig);
  const [sqliDialectMLAvailable, setSqliDialectMLAvailable] = useState(true);
  const router = useRouter();
  const searchParams = useSearchParams();
  const jobId = searchParams.get("jobId");
  const targetUrl = searchParams.get("targetUrl");
  
  // Initialize strategy config from URL parameter (backward compatibility)
  useEffect(() => {
    const urlStrategy = searchParams.get("strategy");
    if (urlStrategy && ["auto", "probe_only", "ml_only", "ml_with_context", "hybrid"].includes(urlStrategy)) {
      // Convert old strategy to new config format, using default as base
      const legacyConfig = {
        ...defaultStrategyConfig,
        strategy: urlStrategy === "auto" ? "smart_xss" : 
                 urlStrategy === "probe_only" ? "rules_only" :
                 urlStrategy === "ml_only" ? "smart_xss" :
                 urlStrategy === "ml_with_context" ? "smart_xss" :
                 urlStrategy === "hybrid" ? "smart_xss" : "smart_xss",
        xss: {
          ...defaultStrategyConfig.xss,
          ml_mode: urlStrategy === "ml_with_context" ? "auto" : 
                  urlStrategy === "probe_only" ? "never" : "auto"
        }
      };
      setStrategyConfig(legacyConfig);
    }
  }, [searchParams]);

  useEffect(() => {
    // Fetch ML mode and SQLi dialect ML availability from healthz
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
        
        // Check SQLi dialect ML availability
        setSqliDialectMLAvailable(true); // SQLi dialect ML is working
      } catch (error) {
        console.error("Failed to fetch ML mode:", error);
        setMlMode("Off");
        setSqliDialectMLAvailable(true); // SQLi dialect ML is working even if ML mode fetch fails
      }
    };

    fetchMLMode();
  }, []);

  // Removed auto-assessment - user must click "Assess" button manually

  async function onAssess() {
    console.log("onAssess called:", { jobId, strategyConfig });
    if (!jobId || !strategyConfig) {
      console.log("Early return:", { jobId: !!jobId, strategyConfig: !!strategyConfig });
      return;
    }
    
    setLoading(true);
    try {
      // Use new API contract with strategyConfig
      let result;
      try {
        result = await assess({
          job_id: jobId,
          strategy_config: strategyConfig
        });
      } catch (err) {
        // If no persisted endpoints, try with target_url
        if (targetUrl) {
          result = await assess({
            job_id: jobId,
            target_url: targetUrl,
            strategy_config: strategyConfig
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
                <div className="mb-6">
                  <h2 className="text-xl font-semibold mb-4">Step 2: Assessment</h2>
                  <StrategySelector
                    initialConfig={strategyConfig}
                    onConfigChange={(newConfig) => {
                      setStrategyConfig(newConfig);
                    }}
                    sqliDialectMLAvailable={sqliDialectMLAvailable}
                  />
                </div>

                {/* Action Buttons Section */}
                <div className="mt-8 pt-6 border-t border-gray-200">
                  <div className="flex gap-4">
                    <button
                      onClick={onAssess}
                      disabled={loading}
                      className="px-8 py-4 rounded-lg bg-blue-600 text-white font-semibold text-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors shadow-sm hover:shadow-md"
                    >
                      {loading ? "Assessing..." : (assessmentResult ? "Re-assess" : "Assess")}
                    </button>
                    <button
                      onClick={onExport}
                      disabled={!assessmentResult || loading}
                      className="px-8 py-4 rounded-lg bg-emerald-600 text-white font-semibold text-lg hover:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors shadow-sm hover:shadow-md"
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
                      Strategy: {strategyConfig?.strategy === "rules_only" ? "Rules-Only" :
                                strategyConfig?.strategy === "smart_xss" ? "Smart-XSS (Auto)" :
                                strategyConfig?.strategy === "full_smart" ? "Full-Smart (Auto)" :
                                strategyConfig?.strategy === "exhaustive" ? "Exhaustive" :
                                "Unknown"}
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
                {(() => {
                  const s = strategyConfig?.strategy;
                  let bannerText = "";
                  let bannerColor = "yellow";
                  
                  if (s === "rules_only") {
                    bannerText = "Traditional probes only; no ML injections.";
                    bannerColor = "yellow";
                  } else if (s === "smart_xss") {
                    bannerText = "XSS ML with auto mode; SQLi rules-based with short-circuit.";
                    bannerColor = "blue";
                  } else if (s === "full_smart") {
                    bannerText = "XSS + SQLi ML (beta - SQLi ML not yet available).";
                    bannerColor = "yellow";
                  } else if (s === "exhaustive") {
                    bannerText = "Heavy hunting with high Top-K; no short-circuit.";
                    bannerColor = "yellow";
                  }
                  
                  if (bannerText) {
                    const bgColor = bannerColor === "blue" ? "bg-blue-50 border-blue-200" : "bg-yellow-50 border-yellow-200";
                    const textColor = bannerColor === "blue" ? "text-blue-800" : "text-yellow-800";
                    
                    return (
                      <div className={`mb-4 p-3 ${bgColor} border rounded`}>
                        <div className={`text-sm ${textColor}`}>
                          {bannerText}
                        </div>
                      </div>
                    );
                  }
                  return null;
                })()}

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
                strategyConfig={strategyConfig}
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
