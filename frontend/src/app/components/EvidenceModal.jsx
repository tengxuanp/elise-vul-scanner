"use client";
import { useEffect, useState } from "react";
import MLScoreDisplay from "./MLScoreDisplay";
import { API_BASE } from "../../lib/api";

export default function EvidenceModal({ open, onClose, evidenceId, jobId, meta }) {
  const [evidence, setEvidence] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const [activeTab, setActiveTab] = useState("request");
  
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
  const ProbeSignalsPills = ({ probe_signals, family }) => {
    if (!probe_signals || Object.keys(probe_signals).length === 0) return null;
    
    // Filter signals based on family
    const filteredSignals = {};
    if (family === 'sqli') {
      // Only show SQL-related signals for SQLi
      Object.entries(probe_signals).forEach(([key, value]) => {
        if (key.includes('sql') || key.includes('sqli') || key.includes('boolean') || key.includes('error')) {
          filteredSignals[key] = value;
        }
      });
    } else if (family === 'xss') {
      // Only show XSS-related signals for XSS
      Object.entries(probe_signals).forEach(([key, value]) => {
        if (key.includes('xss') || key.includes('context') || key.includes('reflection') || key.includes('escaping')) {
          filteredSignals[key] = value;
        }
      });
    } else {
      // Show all signals for other families
      Object.assign(filteredSignals, probe_signals);
    }
    
    if (Object.keys(filteredSignals).length === 0) {
      return <div className="text-xs text-slate-600">No relevant signals for {family} family</div>;
    }
    
    return (
      <div className="flex flex-wrap gap-1">
        {Object.entries(filteredSignals).map(([key, value]) => (
          <span key={key} className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
            {key}={String(value)}
          </span>
        ))}
      </div>
    );
  };

  // Tab components
  const TabButton = ({ id, label, active, onClick }) => (
    <button
      onClick={() => onClick(id)}
      className={`px-3 py-2 text-sm font-medium rounded-t-lg border-b-2 ${
        active
          ? "border-blue-500 text-blue-600 bg-blue-50"
          : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
      }`}
    >
      {label}
    </button>
  );

  const ProbeSignalTab = ({ evidence }) => {
    if (!evidence?.marker && !evidence?.reflection_details && !evidence?.redirect_details && !evidence?.sqli_details) {
      return <div className="text-sm text-gray-500">No probe signal data available</div>;
    }

    return (
      <div className="space-y-4">
        {/* XSS Marker - Only show for XSS family */}
        {evidence?.family === 'xss' && evidence?.marker && (
          <div>
            <div className="text-sm font-medium mb-2">XSS Marker</div>
            <div className="space-y-2">
              <div>
                <div className="text-xs text-gray-500">Raw</div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-gray-50 p-2 rounded text-xs font-mono">{evidence.marker.raw}</code>
                  <button 
                    onClick={() => navigator.clipboard.writeText(evidence.marker.raw)}
                    className="px-2 py-1 bg-blue-600 text-white text-xs rounded"
                  >
                    Copy
                  </button>
                </div>
              </div>
              <div>
                <div className="text-xs text-gray-500">URL Encoded</div>
                <code className="block bg-gray-50 p-2 rounded text-xs font-mono">{evidence.marker.url}</code>
              </div>
              <div>
                <div className="text-xs text-gray-500">HTML Escaped</div>
                <code className="block bg-gray-50 p-2 rounded text-xs font-mono">{evidence.marker.html}</code>
              </div>
            </div>
          </div>
        )}

        {/* Reflection Details */}
        {evidence?.reflection_details && (
          <div>
            <div className="text-sm font-medium mb-2">Reflection Context</div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-xs text-gray-500">Context</div>
                <div className="font-mono">{evidence.reflection_details.context}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Escaping</div>
                <div className="font-mono">{evidence.reflection_details.escaping}</div>
              </div>
              {evidence.reflection_details.path_hint && (
                <div className="col-span-2">
                  <div className="text-xs text-gray-500">Path Hint</div>
                  <div className="font-mono text-xs">{evidence.reflection_details.path_hint}</div>
                </div>
              )}
            </div>
            {(evidence.reflection_details.left64 || evidence.reflection_details.right64) && (
              <div className="mt-3">
                <div className="text-xs text-gray-500 mb-1">Context Fragments</div>
                <div className="space-y-1">
                  {evidence.reflection_details.left64 && (
                    <div>
                      <div className="text-xs text-gray-500">Left (64 chars)</div>
                      <code className="block bg-gray-50 p-2 rounded text-xs font-mono">{evidence.reflection_details.left64}</code>
                    </div>
                  )}
                  {evidence.reflection_details.right64 && (
                    <div>
                      <div className="text-xs text-gray-500">Right (64 chars)</div>
                      <code className="block bg-gray-50 p-2 rounded text-xs font-mono">{evidence.reflection_details.right64}</code>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Redirect Details */}
        {evidence?.redirect_details && (
          <div>
            <div className="text-sm font-medium mb-2">Redirect Oracle</div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-xs text-gray-500">Location</div>
                <div className="font-mono text-xs break-all">{evidence.redirect_details.location}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Status</div>
                <div className="font-mono">{evidence.redirect_details.status}</div>
              </div>
            </div>
          </div>
        )}

        {/* SQLi Details */}
        {evidence?.sqli_details && (
          <div>
            <div className="text-sm font-medium mb-2">SQL Error</div>
            <div className="space-y-2">
              <div>
                <div className="text-xs text-gray-500">Error Excerpt</div>
                <code className="block bg-red-50 p-2 rounded text-xs font-mono text-red-800">{evidence.sqli_details.error_excerpt}</code>
              </div>
              <div>
                <div className="text-xs text-gray-500">Dialect Hint</div>
                <div className="font-mono">{evidence.sqli_details.dialect_hint}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  const RankingTab = ({ evidence }) => {
    // Handle both old format (object with topk array) and new format (direct array)
    const rankingTopk = evidence?.ranking_topk;
    const topkArray = Array.isArray(rankingTopk) ? rankingTopk : rankingTopk?.topk;
    
    if (!topkArray || topkArray.length === 0) {
      return <div className="text-sm text-gray-500">No ranking data available</div>;
    }

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-4">
          <div>
            <div className="text-xs text-gray-500">Rank Source</div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">{evidence.telemetry?.xss?.rank_source || evidence.ranking_source || "unknown"}</span>
              <span className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                {evidence?.ranking?.source || evidence?.rank_source || "n/a"}
              </span>
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Context (final)</div>
            <div className="text-sm font-medium">{evidence.telemetry?.xss?.context_final || "none"}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Top-K (effective)</div>
            <div className="text-sm font-medium">{evidence.telemetry?.xss?.topk_effective || evidence.ranking_pool_size || 0}</div>
          </div>
          {evidence.ranking_model && (
            <div>
              <div className="text-xs text-gray-500">Model</div>
              <div className="text-sm font-medium">{evidence.ranking_model.name}</div>
            </div>
          )}
        </div>

        <div>
          <div className="text-sm font-medium mb-2">Top-K Payloads</div>
          
          {/* Family Mismatch Banner */}
          {evidence?.probe_signals?.family_mismatch && (
            <div className="mb-3 p-3 bg-yellow-50 border border-yellow-200 rounded">
              <div className="text-sm font-medium text-yellow-800">
                ⚠️ Family Mismatch Detected
              </div>
              <div className="text-xs text-yellow-700 mt-1">
                {evidence.probe_signals.family_mismatch.banner}
              </div>
            </div>
          )}
          
          <div className="space-y-2">
            {topkArray?.map((payload, idx) => {
              const isMismatch = evidence?.family && payload.family && evidence.family !== payload.family;
              return (
                <div key={idx} className={`flex items-center justify-between p-3 rounded ${
                  isMismatch ? 'bg-gray-100 opacity-60' : 'bg-gray-50'
                }`}>
                  <div className="flex-1">
                    <div className="text-sm font-mono">{payload.payload_id}</div>
                    <div className="flex items-center gap-2">
                      <div className="text-xs text-gray-500">{payload.family}</div>
                      {isMismatch && (
                        <span className="px-2 py-0.5 bg-yellow-100 text-yellow-700 text-xs rounded">
                          Mismatch
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="text-sm font-medium">{payload.score.toFixed(3)}</div>
                    {idx === 0 && (
                      <span className="px-2 py-0.5 bg-green-100 text-green-700 text-xs rounded">✓ Used</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  const AttemptTimelineTab = ({ evidence }) => {
    if (!evidence?.attempts_timeline || evidence.attempts_timeline.length === 0) {
      return <div className="text-sm text-gray-500">No attempt timeline available</div>;
    }

    return (
      <div className="space-y-3">
        {evidence.attempts_timeline.map((attempt, idx) => (
          <div key={idx} className="border rounded p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm font-medium">Attempt #{attempt.attempt_idx}</div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 text-xs rounded ${
                  attempt.hit ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-700"
                }`}>
                  {attempt.hit ? "✓ Hit" : "✗ Miss"}
                </span>
                <span className="text-xs text-gray-500">{attempt.rank_source}</span>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-xs text-gray-500">Payload</div>
                <div className="font-mono text-xs break-all">{attempt.payload_id || attempt.payload}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Request</div>
                <div className="font-mono text-xs">
                  {attempt.request?.method || attempt.method} {attempt.request?.path || attempt.path}
                </div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Response</div>
                <div className="font-mono text-xs">
                  {attempt.response?.status || attempt.status} ({attempt.response?.latency_ms || attempt.latency_ms}ms)
                </div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Parameter</div>
                <div className="font-mono text-xs">
                  {attempt.request?.param_in || attempt.param_in}:{attempt.request?.param || attempt.param}
                </div>
              </div>
            </div>
            
            {attempt.why && attempt.why.length > 0 && (
              <div className="mt-2">
                <div className="text-xs text-gray-500">Why</div>
                <div className="flex gap-1 mt-1">
                  {attempt.why.map((reason, reasonIdx) => (
                    <span key={reasonIdx} className="px-2 py-0.5 bg-blue-100 text-blue-700 text-xs rounded">
                      {reason}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  // Reason text mapping
  const reasonText = {
    ctx_guided: "Context-guided injection (payload seeded by ML context).",
    ml_ranked: "Payload chosen by the ML ranker from the Top-K candidates.",
    xss_reflection: "Canary reflection observed; context & escaping inferred.",
  };

  const WhyList = ({ reasons }) => {
    return (
      <ul className="space-y-1">
        {reasons?.map((r) => (
          <li key={r} className="text-sm text-slate-700">
            • {reasonText[r] ?? r}
          </li>
        ))}
      </ul>
    );
  };

  const WhyVulnerableTab = ({ evidence }) => {
    if (!evidence?.vuln_proof) {
      return <div className="text-sm text-gray-500">No vulnerability proof available</div>;
    }

    return (
      <div className="space-y-4">
        <div>
          <div className="text-xs text-gray-500 mb-1">Proof Type</div>
          <span className="px-2 py-0.5 bg-red-100 text-red-700 text-xs rounded">
            {evidence.vuln_proof.type}
          </span>
        </div>
        
        <div>
          <div className="text-sm font-medium mb-2">Summary</div>
          <div className="text-sm text-gray-700">{evidence.vuln_proof.summary}</div>
        </div>
        
        {evidence.why && evidence.why.length > 0 && (
          <div>
            <div className="text-sm font-medium mb-2">Detection Method</div>
            <WhyList reasons={evidence.why} />
          </div>
        )}
        
        {evidence.vuln_proof.details && evidence.vuln_proof.details.length > 0 && (
          <div>
            <div className="text-sm font-medium mb-2">Details</div>
            <ul className="space-y-1">
              {evidence.vuln_proof.details.map((detail, idx) => (
                <li key={idx} className="text-sm text-gray-700 flex items-start">
                  <span className="text-blue-500 mr-2">•</span>
                  {detail}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-white rounded-2xl shadow p-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold">Evidence</h3>
            {evidence?.telemetry?.ctx_invoke && (
              <span className="px-2 py-1 rounded text-xs bg-gray-100 text-gray-700 border">
                {evidence.telemetry.ctx_invoke}
              </span>
            )}
            {meta?.strategy && (
              <span className="px-2 py-1 rounded text-xs bg-blue-100 text-blue-700 border">
                Strategy: {meta.strategy === "rules_only" ? "Rules-Only" :
                          meta.strategy === "smart_xss" ? "Smart-XSS" :
                          meta.strategy === "full_smart" ? "Full-Smart" :
                          meta.strategy === "exhaustive" ? "Exhaustive" : meta.strategy}
              </span>
            )}
          </div>
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
            {/* Tab Navigation */}
            <div className="border-b border-gray-200 mb-4">
              <nav className="flex space-x-8">
                <TabButton
                  id="request"
                  label="Request/Response"
                  active={activeTab === "request"}
                  onClick={setActiveTab}
                />
                <TabButton
                  id="probe"
                  label="Probe Signal"
                  active={activeTab === "probe"}
                  onClick={setActiveTab}
                />
                <TabButton
                  id="ranking"
                  label="Ranking & Top-K"
                  active={activeTab === "ranking"}
                  onClick={setActiveTab}
                />
                <TabButton
                  id="timeline"
                  label="Attempt Timeline"
                  active={activeTab === "timeline"}
                  onClick={setActiveTab}
                />
                <TabButton
                  id="why"
                  label="Why Vulnerable"
                  active={activeTab === "why"}
                  onClick={setActiveTab}
                />
              </nav>
            </div>

            {/* Tab Content */}
            <div className="min-h-[400px]">
              {activeTab === "request" && (
                <div className="space-y-4">
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">Reproduce</div>
                    <div className="flex gap-2">
                      <code className="flex-1 bg-zinc-50 border rounded p-2 overflow-x-auto text-xs">{curl}</code>
                      <button className="px-2 py-1 rounded bg-zinc-900 text-white text-xs" onClick={()=>navigator.clipboard.writeText(curl)}>Copy</button>
                      <button className="px-2 py-1 rounded bg-blue-600 text-white text-xs" onClick={downloadHttp}>Download .http</button>
                      <button className="px-2 py-1 rounded bg-gray-600 text-white text-xs" onClick={copyHeaders}>Copy headers</button>
                    </div>
                  </div>

                  {/* Evidence Details */}
                  <div className="space-y-3">
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
                      <ProbeSignalsPills probe_signals={evidence?.probe_signals} family={evidence?.family} />
                    </div>

                    {/* Telemetry */}
                    <div>
                      <div className="text-xs text-zinc-500 mb-1">Telemetry</div>
                      <div className="flex gap-2 text-xs">
                        <span className="px-2 py-0.5 rounded bg-gray-100 text-gray-700">
                          Attempt: {evidence?.telemetry?.attempt_idx ?? evidence?.attempt_idx ?? 0}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-gray-100 text-gray-700">
                          Top-K: {evidence?.telemetry?.top_k_used ?? evidence?.top_k_used ?? 0}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-gray-100 text-gray-700">
                          Rank: {evidence?.telemetry?.rank_source ?? evidence?.rank_source ?? "—"}
                        </span>
                      </div>
                    </div>

                    {/* Effective Top-K */}
                    {evidence?.telemetry?.top_k_used && (
                      <div>
                        <div className="text-xs text-zinc-500 mb-1">Effective Top-K</div>
                        <span className="px-2 py-0.5 rounded bg-green-100 text-green-700 text-xs">
                          {evidence.telemetry.top_k_used} payloads used
                        </span>
                      </div>
                    )}

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
                    const rsrc = evidence?.ranking?.source || evidence?.rank_source;
                    const showRankerBox = rsrc === "ml_ranked";
                    
                    if (isProbeOnly || noMLAttempts) {
                      return (
                        <div className="my-4">
                          <div className="text-xs text-zinc-500 mb-2">ML Ranking</div>
                          <div className="text-xs text-gray-500 italic">
                            No ML injection attempted.
                          </div>
                        </div>
                      );
                    } else if (hasMLScores && showRankerBox) {
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
                  
                  {/* Response Headers and Length */}
                  {(evidence?.response_headers || evidence?.response_len) && (
                    <div className="my-4">
                      <div className="text-xs text-zinc-500 mb-2">Response Information</div>
                      <div className="bg-zinc-50 border rounded p-3 text-xs">
                        {evidence?.response_len && (
                          <div className="mb-2">
                            <span className="font-semibold">Length:</span> {evidence.response_len.toLocaleString()} bytes
                          </div>
                        )}
                        {evidence?.response_headers && Object.keys(evidence.response_headers).length > 0 && (
                          <div>
                            <span className="font-semibold">Headers:</span>
                            <div className="mt-1 space-y-1">
                              {Object.entries(evidence.response_headers).map(([key, value]) => (
                                <div key={key} className="font-mono">
                                  <span className="text-blue-600">{key}:</span> {value}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                  
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
                </div>
              )}

            {activeTab === "probe" && (
              <ProbeSignalTab evidence={evidence} />
            )}

            {activeTab === "ranking" && (
              <RankingTab evidence={evidence} />
            )}

            {activeTab === "timeline" && (
              <AttemptTimelineTab evidence={evidence} />
            )}

            {activeTab === "why" && (
              <WhyVulnerableTab evidence={evidence} />
            )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
