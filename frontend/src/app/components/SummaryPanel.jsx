"use client";
import React from 'react';

const SummaryPanel = ({ 
  assessmentResult, 
  mlMode, 
  jobId,
  strategyConfig
}) => {
  if (!assessmentResult) return null;

  const { summary, meta } = assessmentResult;
  
  // Check for strategy violations
  const hasViolations = meta?.violations && meta.violations.length > 0;
  const strategyViolation = meta?.strategy === "ml_only" && (summary?.confirmed_probe > 0 || meta?.probe_attempts > 0);
  
  // Calculate confirmed breakdown using new decision taxonomy
  const confirmedProbe = assessmentResult.results?.filter(r => 
    r.decision === "positive" && r.provenance === "Probe"
  ).length || 0;
  
  const confirmedMLInject = assessmentResult.results?.filter(r => 
    r.decision === "positive" && r.provenance === "Inject"
  ).length || 0;
  
  const abstain = assessmentResult.results?.filter(r => 
    r.decision === "abstain"
  ).length || 0;
  
  const na = summary?.na || 0;

  // ML mode badge color
  const getMLBadgeColor = (mode) => {
    switch (mode) {
      case "Calibrated models": return "bg-green-100 text-green-700";
      case "Defaults only": return "bg-amber-100 text-amber-700";
      case "Off": return "bg-gray-100 text-gray-700";
      default: return "bg-gray-100 text-gray-700";
    }
  };

  // Format processing time
  const formatTime = (ms) => {
    if (!ms) return "N/A";
    const seconds = (ms / 1000).toFixed(1);
    return `${seconds}s`;
  };

  // Check if we're in context mode
  const isCtxMode = (summary?.strategy || "").startsWith("ml_with_context") || meta?.xss_ctx_invoke === "force_ml";
  
  // Helper to show "—" instead of "0" for non-applicable metrics
  const showNA = (value, applicable) => (applicable ? value : "—");

  // Generate plan summary string
  const generatePlanSummary = () => {
    if (!strategyConfig) return "No strategy configured";
    
    const xssMode = strategyConfig.xss.ml_mode;
    const xssTau = strategyConfig.xss.tau_ml;
    const xssRule = strategyConfig.xss.rule_conf_gate;
    const xssTopk = strategyConfig.xss.topk;
    
    const sqliDialect = strategyConfig.sqli.dialect_mode;
    const sqliTopk = strategyConfig.sqli.topk;
    const sqliSC = strategyConfig.sqli.short_circuit.enabled;
    const sqliM = strategyConfig.sqli.short_circuit.M;
    const sqliK = strategyConfig.sqli.short_circuit.K;
    
    const families = strategyConfig.families.join(", ");
    
    return `XSS=${xssMode} (τ=${xssTau}, rule=${xssRule}), XSS Top-K=${xssTopk} • SQLi=dialect ${sqliDialect}, SQLi Top-K=${sqliTopk} • Short-circuit ${sqliSC ? `M=${sqliM}/K=${sqliK}` : 'OFF'} • Families: ${families}`;
  };

  return (
    <div className="card p-6">
      <h3 className="font-semibold mb-4">Summary</h3>
      
      {/* ML Mode Badge */}
      <div className="mb-4">
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getMLBadgeColor(mlMode)}`}>
          ML: {mlMode}
        </span>
      </div>

      {/* Strategy Badge */}
      <div className="mb-4">
        <span className="px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-700">
          Strategy: {strategyConfig?.strategy === "rules_only" ? "Rules-Only" :
                    strategyConfig?.strategy === "smart_xss" ? "Smart-XSS (Auto)" :
                    strategyConfig?.strategy === "full_smart" ? "Full-Smart (Auto)" :
                    strategyConfig?.strategy === "exhaustive" ? "Exhaustive" :
                    "Unknown"}
        </span>
      </div>

      {/* Plan Summary */}
      <div className="mb-4">
        <div className="text-xs text-gray-600 mb-1">Plan:</div>
        <div className="text-xs text-gray-700 font-mono bg-gray-50 p-2 rounded">
          {generatePlanSummary()}
        </div>
      </div>

      {/* Strategy Violation Alert */}
      {(hasViolations || strategyViolation) && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded">
          <div className="text-sm font-medium text-red-800 mb-1">
            ⚠️ Strategy Violation
          </div>
          <div className="text-xs text-red-700">
            {strategyViolation && "Probes ran under ML-only strategy"}
            {hasViolations && meta?.violations && (
              <div>
                <div>Violations detected:</div>
                <ul className="list-disc list-inside ml-2">
                  {meta.violations.map((violation, index) => (
                    <li key={index}>{violation}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Counters Consistency Check */}
      {meta?.counters_consistent === false && (
        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
          <div className="text-sm font-medium text-yellow-800 mb-1">
            ⚠️ Counters Inconsistent
          </div>
          <div className="text-xs text-yellow-700">
            Event counters don't match table rows. Check server logs for details.
          </div>
        </div>
      )}

      {/* Totals Consistency Check */}
      {assessmentResult?.results && (
        (() => {
          const totalFromSummary = summary?.total || ((summary?.positive || 0) + (summary?.suspected || 0) + (summary?.abstain || 0) + (summary?.na || 0));
          const totalFromResults = assessmentResult.results.length;
          const naCount = summary?.na || 0;
          // NA results are not included in the results array, so we need to account for that
          const totalsMatch = totalFromSummary === (totalFromResults + naCount);
          
          if (!totalsMatch) {
            return (
              <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                <div className="text-sm font-medium text-yellow-800 mb-1">
                  ⚠️ Totals Mismatch
                </div>
                <div className="text-xs text-yellow-700">
                  Summary total ({totalFromSummary}) ≠ Results count ({totalFromResults}) + NA count ({naCount})
                  {jobId && <div>Job ID: {jobId}</div>}
                </div>
              </div>
            );
          }
          return null;
        })()
      )}

      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="text-gray-600">Endpoints crawled</div>
          <div className="font-semibold">{meta?.endpoints_supplied || 0}</div>
        </div>
        
        <div>
          <div className="text-gray-600">Targets enumerated</div>
          <div className="font-semibold">{meta?.targets_enumerated || 0}</div>
        </div>
        
        <div>
          <div className="text-gray-600 flex items-center gap-1">
            Confirmed (Probe)
            {meta?.probe_successes !== undefined && (
              <span className="text-xs text-blue-500" title="Server-reported counter">ℹ️</span>
            )}
            {meta?.counters_consistent === false && (
              <span className="text-xs text-yellow-500" title="Server/event counters don't match table rows">⚠️</span>
            )}
          </div>
          <div className="font-semibold text-green-600">
            {meta?.probe_successes !== undefined ? meta.probe_successes : confirmedProbe}
          </div>
        </div>
        
        <div>
          <div className="text-gray-600 flex items-center gap-1">
            Confirmed (ML+Inject)
            {meta?.ml_inject_successes !== undefined && (
              <span className="text-xs text-blue-500" title="Server-reported counter">ℹ️</span>
            )}
            {meta?.counters_consistent === false && (
              <span className="text-xs text-yellow-500" title="Server/event counters don't match table rows">⚠️</span>
            )}
          </div>
          <div className="font-semibold text-blue-600">
            {meta?.ml_inject_successes !== undefined ? meta.ml_inject_successes : confirmedMLInject}
          </div>
        </div>
        
        <div>
          <div className="text-gray-600">Abstain</div>
          <div className="font-semibold text-gray-600">{abstain}</div>
        </div>
        
        <div>
          <div className="text-gray-600">NA (no params)</div>
          <div className="font-semibold text-gray-500">{na}</div>
        </div>
        
        <div>
          <div className="text-gray-600 flex items-center gap-1">
            Total
            {assessmentResult?.results && (
              <span className="text-xs text-blue-500" title="Total results count">ℹ️</span>
            )}
          </div>
          <div className="font-semibold">
            {assessmentResult?.results?.length || 0}
          </div>
        </div>
        
        <div>
          <div className="text-gray-600">Processing time</div>
          <div className="font-semibold">
            {meta?.processing_time || formatTime(meta?.processing_ms || meta?.budget_ms_used)}
          </div>
        </div>
        
        <div>
          <div className="text-gray-600">Job ID</div>
          <div className="font-mono text-xs">{jobId || "-"}</div>
        </div>
      </div>
      
      {/* Strategy Telemetry */}
      {meta && (
        <div className="mt-6 pt-4 border-t">
          <h4 className="font-medium text-sm text-gray-700 mb-3">Strategy Telemetry</h4>
          
          {/* ML Usage Split */}
          {meta.ml_stats && (
            <div className="mb-4 p-3 bg-gray-50 rounded">
              <div className="text-xs font-medium text-gray-700 mb-2">ML Usage Split</div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <div className="text-gray-600">rank_source=model</div>
                  <div className="font-semibold text-green-700">{meta.ml_stats.ranker_active_count}</div>
                </div>
                <div>
                  <div className="text-gray-600">rank_source=defaults</div>
                  <div className="font-semibold text-gray-700">{meta.ml_stats.ranker_inactive_count}</div>
                </div>
              </div>
              
              {/* Require Ranker Violation Warning */}
              {meta.ml_stats.require_ranker_violated && (
                <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded">
                  <div className="text-xs text-red-600 font-medium">⚠️ Require Ranker Violation</div>
                  <div className="text-xs text-red-800">{meta.ml_stats.require_ranker_message}</div>
                </div>
              )}
            </div>
          )}
          
          {/* Family Statistics */}
          {meta.family_stats && (
            <div className="mb-4 p-3 bg-gray-50 rounded">
              <div className="text-xs font-medium text-gray-700 mb-2">Family Statistics</div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <div className="text-gray-600">Family Mismatches</div>
                  <div className={`font-semibold ${meta.family_stats.family_mismatches > 0 ? 'text-red-700' : 'text-green-700'}`}>
                    {meta.family_stats.family_mismatches}
                  </div>
                </div>
                <div>
                  <div className="text-gray-600">Attempt Families</div>
                  <div className="font-semibold">{Object.keys(meta.family_stats.attempt_families).length}</div>
                </div>
              </div>
            </div>
          )}
          
          <div className="grid grid-cols-2 gap-3 text-xs">
            {meta.xss_ml_invoked !== undefined && (
              <div>
                <div className="text-gray-600">XSS ML invoked</div>
                <div className="font-semibold">{meta.xss_ml_invoked}</div>
              </div>
            )}
            {meta.xss_final_from_ml !== undefined && (
              <div>
                <div className="text-gray-600">XSS ML final</div>
                <div className="font-semibold">{meta.xss_final_from_ml}</div>
              </div>
            )}
            {meta.xss_rank_source_ml !== undefined && (
              <div>
                <div className="text-gray-600">XSS rank_source=ml</div>
                <div className="font-semibold">{meta.xss_rank_source_ml}</div>
              </div>
            )}
            {meta.xss_context_pool_used !== undefined && (
              <div>
                <div className="text-gray-600">Context pool used</div>
                <div className="font-semibold">{meta.xss_context_pool_used}</div>
              </div>
            )}
            {meta.xss_first_hit_attempts_ctx !== undefined && (
              <div>
                <div className="text-gray-600">First-hit attempts (ctx)</div>
                <div className="font-semibold">{meta.xss_first_hit_attempts_ctx}</div>
              </div>
            )}
            {meta.xss_first_hit_attempts_baseline !== undefined && (
              <div>
                <div className="text-gray-600">First-hit attempts (baseline)</div>
                <div className="font-semibold">{meta.xss_first_hit_attempts_baseline}</div>
              </div>
            )}
            {meta.attempts_saved !== undefined && (
              <div>
                <div className="text-gray-600">Attempts saved</div>
                <div className="font-semibold">{meta.attempts_saved}</div>
              </div>
            )}
            {meta.sqli_short_circuit !== undefined && (
              <div>
                <div className="text-gray-600">SQLi short-circuit</div>
                <div className="font-semibold">{meta.sqli_short_circuit ? "on" : "off"}</div>
              </div>
            )}
            {meta.sqli_dialect_ml !== undefined && (
              <div>
                <div className="text-gray-600">SQLi dialect ML</div>
                <div className="font-semibold">{meta.sqli_dialect_ml ? "on" : "off"}</div>
              </div>
            )}
          </div>
        </div>
      )}
      
      {/* Top Payload Families */}
      {assessmentResult.results && assessmentResult.results.length > 0 && (
        <div className="mt-6 pt-4 border-t">
          <h4 className="font-medium text-sm text-gray-700 mb-3">Top Payload Families (by positives)</h4>
          {(() => {
            // Group by family
            const familyCounts = {};
            assessmentResult.results
              .filter(r => r.decision === "positive" && r.family)
              .forEach(r => {
                const family = r.family || "unknown";
                familyCounts[family] = (familyCounts[family] || 0) + 1;
              });
            
            const sortedFamilies = Object.entries(familyCounts)
              .sort(([,a], [,b]) => b - a)
              .slice(0, 5); // Top 5
            
            if (sortedFamilies.length === 0) {
              return <div className="text-sm text-gray-500">No positive results to analyze</div>;
            }
            
            return (
              <div className="space-y-2">
                {sortedFamilies.map(([family, count]) => (
                  <div key={family} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium capitalize">{family}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-green-600">{count}</span>
                      <span className="text-xs text-gray-500">positives</span>
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}
        </div>
      )}
      
      {/* XSS Context Statistics */}
      {meta?.xss_reflections_total > 0 && (
        <div className="mt-6 pt-4 border-t">
          <h4 className="font-medium text-sm text-gray-700 mb-3">XSS Context Analysis</h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <div className="text-gray-600">Context ML mode</div>
              <div className="font-semibold">{meta?.xss_ctx_invoke || "auto"}</div>
            </div>
            <div>
              <div className="text-gray-600">XSS reflections</div>
              <div className="font-semibold">{meta.xss_reflections_total}</div>
            </div>
            
            <div>
              <div className="text-gray-600">Rule high-conf</div>
              <div className="font-semibold text-green-600">{showNA(meta.xss_rule_high_conf ?? 0, !isCtxMode)}</div>
            </div>
            
            <div>
              <div className="text-gray-600">ML invoked</div>
              <div className="font-semibold text-purple-600">{meta.xss_ml_invoked || 0}</div>
            </div>
            
            <div>
              <div className="text-gray-600">Final from ML</div>
              <div className="font-semibold text-purple-600">{meta.xss_final_from_ml || 0}</div>
            </div>
            
            <div>
              <div className="text-gray-600">Context pool used</div>
              <div className="font-semibold text-blue-600">{meta.xss_ctx_pool_used || 0}</div>
            </div>
            
            <div>
              <div className="text-gray-600">First-hit attempts (ctx)</div>
              <div className="font-semibold text-green-600">{meta.xss_first_hit_attempts_ctx || 0}</div>
            </div>
            
            <div>
              <div className="text-gray-600">First-hit attempts (baseline)</div>
              <div className="font-semibold text-orange-600">{meta.xss_first_hit_attempts_baseline || 0}</div>
            </div>
            
            <div>
              <div className="text-gray-600">Attempts saved</div>
              <div className="font-semibold text-green-600">{meta.attempts_saved || 0}</div>
            </div>
          </div>
          
          {/* Context Distribution */}
          {meta.xss_context_dist && Object.keys(meta.xss_context_dist).length > 0 && (
            <div className="mt-3">
              <div className="text-gray-600 text-xs mb-2">Context Distribution</div>
              <div className="flex flex-wrap gap-1">
                {Object.entries(meta.xss_context_dist).map(([context, count]) => (
                  <span 
                    key={context}
                    className="px-2 py-1 rounded text-xs bg-gray-100 text-gray-700"
                    title={`${context}: ${count} reflections`}
                  >
                    {context}: {count}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SummaryPanel;
