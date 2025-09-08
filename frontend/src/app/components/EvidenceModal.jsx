"use client";
import { useEffect, useState } from "react";
import MLScoreDisplay from "./MLScoreDisplay";
import { API_BASE } from "../../lib/api";

export default function EvidenceModal({ open, onClose, evidenceId, jobId, meta }) {
  const [evidence, setEvidence] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  
  useEffect(()=>{ document.body.style.overflow = open ? "hidden" : ""; }, [open]);
  
  // Fetch evidence when modal opens
  useEffect(() => {
    if (open && evidenceId && jobId) {
      setLoading(true);
      fetch(`${API_BASE}/evidence/${jobId}/${evidenceId}`)
        .then(res => res.json())
        .then(data => {
          setEvidence(data);
          setLoading(false);
        })
        .catch(err => {
          console.error('Failed to fetch evidence:', err);
          setLoading(false);
        });
    }
  }, [open, evidenceId, jobId]);
  
  if (!open) return null;

  // Build real cURL command
  const buildCurl = (evidence) => {
    if (!evidence) return "";
    
    const url = new URL(evidence.url);
    const method = evidence.method.toUpperCase();
    let curl = `curl -i`;
    
    // Add method if not GET
    if (method !== "GET") {
      curl += ` -X ${method}`;
    }
    
    // Add headers with redaction for sensitive values
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'x-auth-token'];
    if (evidence.request_headers) {
      Object.entries(evidence.request_headers).forEach(([key, value]) => {
        const lowerKey = key.toLowerCase();
        const redactedValue = sensitiveHeaders.includes(lowerKey) ? "***" : value;
        curl += ` -H "${key}: ${redactedValue}"`;
      });
    }
    
    // Add Content-Type and parameters based on param_in
    if (evidence.param_in === "query") {
      url.searchParams.set(evidence.param, evidence.payload);
      curl += ` "${url.toString()}"`;
    } else if (evidence.param_in === "form") {
      curl += ` -H "Content-Type: application/x-www-form-urlencoded"`;
      curl += ` "${url.toString()}"`;
      const encodedParam = encodeURIComponent(evidence.param);
      const encodedPayload = encodeURIComponent(evidence.payload);
      curl += ` -d "${encodedParam}=${encodedPayload}"`;
    } else if (evidence.param_in === "json") {
      curl += ` -H "Content-Type: application/json"`;
      curl += ` "${url.toString()}"`;
      const jsonData = { [evidence.param]: evidence.payload };
      curl += ` --data-raw '${JSON.stringify(jsonData)}'`;
    } else {
      curl += ` "${url.toString()}"`;
    }
    
    return curl;
  };

  // Build .http file content
  const buildHttpFile = (evidence) => {
    if (!evidence) return "";
    
    const url = new URL(evidence.url);
    const method = evidence.method.toUpperCase();
    let http = `${method} ${url.pathname}${url.search} HTTP/1.1\n`;
    http += `Host: ${url.host}\n`;
    
    // Add headers
    if (evidence.request_headers) {
      Object.entries(evidence.request_headers).forEach(([key, value]) => {
        http += `${key}: ${value}\n`;
      });
    }
    
    // Add content
    if (evidence.param_in === "form") {
      http += `Content-Type: application/x-www-form-urlencoded\n`;
      http += `\n${evidence.param}=${evidence.payload}`;
    } else if (evidence.param_in === "json") {
      http += `Content-Type: application/json\n`;
      const jsonData = { [evidence.param]: evidence.payload };
      http += `\n${JSON.stringify(jsonData, null, 2)}`;
    } else if (evidence.param_in === "query") {
      url.searchParams.set(evidence.param, evidence.payload);
      http = http.replace(url.pathname + url.search, url.pathname + url.search);
    }
    
    return http;
  };

  const curl = buildCurl(evidence);
  const httpContent = buildHttpFile(evidence);

  const downloadHttp = () => {
    const blob = new Blob([httpContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `evidence-${evidence?.family || 'unknown'}.http`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyHeaders = () => {
    if (!evidence?.request_headers) return;
    const headersText = Object.entries(evidence.request_headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join('\n');
    navigator.clipboard.writeText(headersText);
  };

  // Provenance chips for evidence
  const EvidenceProvenanceChips = ({ why }) => {
    const chips = [];
    if (why?.includes("probe_proof")) {
      chips.push(
        <span key="probe" className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-700">
          Probe
        </span>
      );
    }
    if (why?.includes("ml_ranked")) {
      chips.push(
        <span key="ml" className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700">
          ML+Inject
        </span>
      );
    }
    return <div className="flex gap-1">{chips}</div>;
  };

  // Probe signals as pills
  const ProbeSignalsPills = ({ probe_signals }) => {
    if (!probe_signals || Object.keys(probe_signals).length === 0) return null;
    
    return (
      <div className="flex flex-wrap gap-1">
        {Object.entries(probe_signals).map(([key, value]) => (
          <span key={key} className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
            {key}={String(value)}
          </span>
        ))}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-white rounded-2xl shadow p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-lg font-semibold">Evidence</h3>
          <button onClick={onClose} className="px-2 py-1 rounded bg-zinc-100 hover:bg-zinc-200">Close</button>
        </div>
        
        {loading && (
          <div className="text-center py-8">
            <div className="text-sm text-gray-500">Loading evidence...</div>
          </div>
        )}
        
        {!loading && !evidence && (
          <div className="text-center py-8">
            <div className="text-sm text-red-500">Failed to load evidence</div>
          </div>
        )}
        
        {!loading && evidence && (
          <>
            <div className="mb-2">
              <div className="text-xs text-zinc-500 mb-1">Reproduce</div>
              <div className="flex gap-2">
                <code className="flex-1 bg-zinc-50 border rounded p-2 overflow-x-auto text-xs">{curl}</code>
                <button className="px-2 py-1 rounded bg-zinc-900 text-white text-xs" onClick={()=>navigator.clipboard.writeText(curl)}>Copy</button>
                <button className="px-2 py-1 rounded bg-blue-600 text-white text-xs" onClick={downloadHttp}>Download .http</button>
                <button className="px-2 py-1 rounded bg-gray-600 text-white text-xs" onClick={copyHeaders}>Copy headers</button>
              </div>
            </div>

            {/* Evidence Details */}
            <div className="my-4 space-y-3">
              {/* CVSS and Model Confidence */}
              <div className="flex items-center gap-4">
                <div>
                  <div className="text-xs text-zinc-500">CVSS</div>
                  <div className="font-semibold">{evidence?.cvss?.base ?? "-"}</div>
                </div>
                {evidence?.p_cal != null && (
                  <div>
                    <div className="text-xs text-zinc-500">Model confidence (p_cal)</div>
                    <div className="font-semibold">{evidence.p_cal.toFixed(2)}</div>
                  </div>
                )}
              </div>

              {/* Provenance */}
              <div>
                <div className="text-xs text-zinc-500 mb-1">Provenance</div>
                <EvidenceProvenanceChips why={evidence?.why} />
              </div>

              {/* Probe Signals */}
              <div>
                <div className="text-xs text-zinc-500 mb-1">Probe signals</div>
                <ProbeSignalsPills probe_signals={evidence?.probe_signals} />
              </div>

              {/* Telemetry */}
              <div>
                <div className="text-xs text-zinc-500 mb-1">Telemetry</div>
                <div className="flex gap-2 text-xs">
                  <span className="px-2 py-0.5 rounded bg-gray-100 text-gray-700">
                    Attempt: {evidence?.attempt_idx ?? 0}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-gray-100 text-gray-700">
                    Top-K: {evidence?.top_k_used ?? 0}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-gray-100 text-gray-700">
                    Rank: {evidence?.rank_source ?? "—"}
                  </span>
                </div>
              </div>

              {/* XSS Context/Escaping or SQLi Dialect */}
              {(evidence?.xss_context || evidence?.xss_escaping) && (
                <div>
                  <div className="text-xs text-zinc-500 mb-1">XSS Context</div>
                  <div className="flex gap-2 text-xs">
                    {evidence.xss_context && (
                      <span className="px-2 py-0.5 rounded bg-orange-100 text-orange-700">
                        Context: {evidence.xss_context}
                      </span>
                    )}
                    {evidence.xss_escaping && (
                      <span className="px-2 py-0.5 rounded bg-orange-100 text-orange-700">
                        Escaping: {evidence.xss_escaping}
                      </span>
                    )}
                  </div>
                </div>
              )}

              {evidence?.dialect && (
                <div>
                  <div className="text-xs text-zinc-500 mb-1">SQLi Dialect</div>
                  <div className="flex gap-2 text-xs">
                    <span className="px-2 py-0.5 rounded bg-green-100 text-green-700">
                      {evidence.dialect}
                    </span>
                    {evidence.dialect_confident && (
                      <span className="px-2 py-0.5 rounded bg-green-100 text-green-700">
                        (confident)
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
            
            {/* ML Scores */}
            {(() => {
              const isProbeOnly = evidence?.rank_source === "probe_only";
              const noMLAttempts = meta?.ml_inject_attempts === 0;
              const hasMLScores = evidence?.score !== undefined || evidence?.p_cal !== undefined;
              
              if (isProbeOnly || noMLAttempts) {
                return (
                  <div className="my-4">
                    <div className="text-xs text-zinc-500 mb-2">ML Ranking</div>
                    <div className="text-xs text-gray-500 italic">
                      No ML injection attempted.
                    </div>
                  </div>
                );
              } else if (hasMLScores) {
                return (
                  <div className="my-4">
                    <div className="text-xs text-zinc-500 mb-2">ML Ranking</div>
                    <MLScoreDisplay 
                      score={evidence?.score}
                      p_cal={evidence?.p_cal}
                      family={evidence?.family}
                    />
                  </div>
                );
              }
              return null;
            })()}
            
            <div className="text-xs text-zinc-500 my-2 flex items-center justify-between">
              <span>Response snippet</span>
              <div className="flex gap-2">
                <button 
                  onClick={() => setShowRaw(!showRaw)}
                  className="px-2 py-1 rounded bg-gray-600 text-white text-xs"
                >
                  {showRaw ? "View Safe" : "View Raw"}
                </button>
                {showRaw && evidence?.response_snippet_raw && (
                  <button 
                    onClick={() => {
                      const blob = new Blob([atob(evidence.response_snippet_raw)], { type: "text/plain" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = `evidence-${evidence?.family || 'unknown'}-raw.txt`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="px-2 py-1 rounded bg-blue-600 text-white text-xs"
                  >
                    Download Raw
                  </button>
                )}
              </div>
            </div>
            <pre className="bg-zinc-50 border rounded p-3 max-h-80 overflow-auto whitespace-pre-wrap text-xs">
{showRaw && evidence?.response_snippet_raw ? atob(evidence.response_snippet_raw) : (evidence?.response_snippet_text || evidence?.response_snippet || "")}
            </pre>
          </>
        )}
      </div>
    </div>
  );
}
