"use client";
import React from 'react';

const SummaryPanel = ({ 
  assessmentResult, 
  mlMode, 
  jobId,
  strategy = "auto"
}) => {
  if (!assessmentResult) return null;

  const { summary, meta } = assessmentResult;
  
  // Check for strategy violations
  const hasViolations = meta?.violations && meta.violations.length > 0;
  const strategyViolation = meta?.strategy === "ml_only" && (summary?.confirmed_probe > 0 || meta?.probe_attempts > 0);
  
  // Calculate confirmed breakdown using new decision taxonomy
  const confirmedProbe = assessmentResult.results?.filter(r => 
    r.decision === "positive" && r.rank_source === "probe_only"
  ).length || 0;
  
  const confirmedMLInject = assessmentResult.results?.filter(r => 
    r.decision === "positive" && r.rank_source === "ml"
  ).length || 0;
  
  const abstain = assessmentResult.results?.filter(r => 
    r.decision === "abstain"
  ).length || 0;
  
  const na = assessmentResult.results?.filter(r => 
    r.decision === "not_applicable"
  ).length || 0;

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
          Strategy: {strategy === "auto" ? "Auto" : 
                    strategy === "probe_only" ? "Probe-only" :
                    strategy === "ml_only" ? "ML-only" :
                    strategy === "hybrid" ? "Hybrid" : strategy}
        </span>
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

      {/* Totals Consistency Check */}
      {assessmentResult?.results && (
        (() => {
          const totalFromSummary = (summary?.positive || 0) + (summary?.suspected || 0) + (summary?.abstain || 0) + (summary?.na || 0);
          const totalFromResults = assessmentResult.results.length;
          const totalsMatch = totalFromSummary === totalFromResults;
          
          if (!totalsMatch) {
            return (
              <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                <div className="text-sm font-medium text-yellow-800 mb-1">
                  ⚠️ Totals Mismatch
                </div>
                <div className="text-xs text-yellow-700">
                  Summary total ({totalFromSummary}) ≠ Results count ({totalFromResults})
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
      
      {/* XSS Context Statistics */}
      {meta?.xss_reflections_total > 0 && (
        <div className="mt-6 pt-4 border-t">
          <h4 className="font-medium text-sm text-gray-700 mb-3">XSS Context Analysis</h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <div className="text-gray-600">XSS reflections</div>
              <div className="font-semibold">{meta.xss_reflections_total}</div>
            </div>
            
            <div>
              <div className="text-gray-600">Rule high-conf</div>
              <div className="font-semibold text-green-600">{meta.xss_rule_high_conf || 0}</div>
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
              <div className="font-semibold text-green-600">
                {meta.xss_first_hit_attempts_delta > 0 ? `+${meta.xss_first_hit_attempts_delta}` : '0'}
              </div>
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
