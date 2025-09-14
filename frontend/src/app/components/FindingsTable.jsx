"use client";
import { useState } from "react";
import { TriangleAlert, ShieldCheck, Database, Link as LinkIcon, ChevronDown, ChevronRight } from "lucide-react";
import { humanizeWhyCodes } from "../../lib/microcopy";

const famIcon = (f) => f==="xss" ? <TriangleAlert className="icon" /> : f==="sqli" ? <Database className="icon" /> : <LinkIcon className="icon" />;

const badge = (t) => <span className={`px-2 py-0.5 rounded text-xs ${t==="positive"?"bg-green-100 text-green-700":t==="suspected"?"bg-amber-100 text-amber-700":t==="error"?"bg-red-100 text-red-700":"bg-zinc-100 text-zinc-700"}`}>{t}</span>;

// Use centralized microcopy mapping from lib/microcopy.js

// Provenance chips
const ProvenanceChips = ({ why }) => {
  const chips = [];
  if (why?.includes("probe_proof")) {
    chips.push(
      <span key="probe" className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-700" title="Found by low-cost probe (oracle).">
        Probe
      </span>
    );
  }
  if (why?.includes("ml_ranked")) {
    chips.push(
      <span key="ml" className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700" title="Ranked by ML and confirmed by injection.">
        ML+Inject
      </span>
    );
  }
  return <div className="flex gap-1">{chips}</div>;
};

// P_cal badge
const PCalBadge = ({ p_cal }) => {
  if (p_cal == null) return null;
  return (
    <span className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700 font-mono">
      p={p_cal.toFixed(2)}
    </span>
  );
};

// Proof Type badge
const ProofTypeBadge = ({ vuln_proof }) => {
  if (!vuln_proof?.type) return null;
  const typeMap = {
    "xss_reflection": "XSS",
    "redirect_header": "Redirect", 
    "sqli_error": "SQLi",
    "other": "Other"
  };
  return (
    <span className="px-2 py-0.5 rounded text-xs bg-red-100 text-red-700" title={`Proof: ${vuln_proof.type}`}>
      Proof: {typeMap[vuln_proof.type] || vuln_proof.type}
    </span>
  );
};

// Decision Source badge (shows probe ML)
const DecisionSourceBadge = ({ family, xssContextSource, sqliDialectSource }) => {
  
  // Map probe ML sources to more specific descriptions with model names
  const getProbeMLSource = (family, xssContextSource, sqliDialectSource) => {
    if (family === "xss") {
      if (xssContextSource === "ml") {
        return "XSS Context Classifier";
      } else if (xssContextSource === "rule") {
        return "XSS Rules";
      } else {
        return "XSS Probe";
      }
    } else if (family === "sqli") {
      if (sqliDialectSource === "ml") {
        return "SQLi Dialect Classifier";
      } else if (sqliDialectSource === "rule") {
        return "SQLi Rules";
      } else {
        return "SQLi Probe";
      }
    } else if (family === "redirect") {
      return "Redirect Probe";
    }
    return "Probe";
  };
  
  // For Decision Source, we want to show probe ML, not payload ranking ML
  const specificSource = getProbeMLSource(family, xssContextSource, sqliDialectSource);
  
  const colors = {
    "XSS Context Classifier": "bg-purple-100 text-purple-700",
    "XSS Rules": "bg-blue-100 text-blue-700",
    "XSS Probe": "bg-green-100 text-green-700",
    "SQLi Dialect Classifier": "bg-purple-100 text-purple-700", 
    "SQLi Rules": "bg-blue-100 text-blue-700",
    "SQLi Probe": "bg-green-100 text-green-700",
    "Redirect Probe": "bg-yellow-100 text-yellow-700",
    "Probe": "bg-gray-100 text-gray-700"
  };
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs ${colors[specificSource] || "bg-gray-100 text-gray-700"}`}
      title={`Probe ML source: ${specificSource}`}
    >
      {specificSource}
    </span>
  );
};

// Rank Source badge (shows payload ranking ML - for Evidence Modal)
const RankSourceBadge = ({ rank_source, family, model_tag }) => {
  if (!rank_source) return null;
  
  // Map rank_source to more specific descriptions
  const getSpecificSource = (source, family, modelTag) => {
    if (source === "ml") {
      if (family === "xss") {
        return modelTag === "family_xss" ? "XSS Ranker" : "XSS ML";
      } else if (family === "sqli") {
        return modelTag === "family_sqli" ? "SQLi Ranker" : "SQLi ML";
      } else if (family === "redirect") {
        return modelTag === "family_redirect" ? "Redirect Ranker" : "Redirect ML";
      }
      return "ML Ranker";
    } else if (source === "probe_only") {
      return "Probe Only";
    } else if (source === "defaults") {
      return "Default Payloads";
    }
    return source;
  };
  
  const specificSource = getSpecificSource(rank_source, family, model_tag);
  
  const colors = {
    "ml": "bg-purple-100 text-purple-700",
    "probe_only": "bg-blue-100 text-blue-700", 
    "defaults": "bg-gray-100 text-gray-700"
  };
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs ${colors[rank_source] || "bg-gray-100 text-gray-700"}`}
      title={`Ranking source: ${rank_source}${model_tag ? ` (${model_tag})` : ''}`}
    >
      {specificSource}
    </span>
  );
};

// ML chip with honest state
const MLChip = ({ rank_source, ml_proba, ml }) => {
  // Use ML state if available, otherwise fallback to rank_source
  const rankerActive = ml?.ranker_active ?? (rank_source === "ml");
  const classifierUsed = ml?.classifier_used ?? (rank_source === "ml" && ml_proba != null);
  
  // Only show p_cal when classifier actually ran
  if (rankerActive && classifierUsed && ml_proba != null) {
    return (
      <span 
        className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700 font-mono"
        title="ML prioritized payload; decision from probe proof."
      >
        ML p={ml_proba.toFixed(2)}
      </span>
    );
  } else if (!rankerActive) {
    return (
      <span 
        className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700"
        title="ML ranker inactive; using default payloads."
      >
        Rank: defaults • ML inactive
      </span>
    );
  } else if (rankerActive && !classifierUsed) {
    // Ranker active but classifier didn't run - don't show p_cal
    return (
      <span 
        className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700"
        title="ML ranker active but classifier not used."
      >
        Rank: model
      </span>
    );
  }
  
  if (rank_source === "ctx_pool") {
    return (
      <span 
        className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-700 font-mono"
        title="Context-aware payload pool used for XSS"
      >
        CTX
      </span>
    );
  }
  
  return null;
};

// SQLi dialect badge
const SQLiDialectBadge = ({ family, result }) => {
  if (family !== "sqli") return null;
  
  if (!result?.sqli_dialect) {
    return (
      <span className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700" title="No SQLi dialect detected">
        —
      </span>
    );
  }
  
  const dialect = result.sqli_dialect;
  const confident = result.sqli_dialect_source === "ml" && result.sqli_dialect_ml_proba > 0.7;
  
  const dialectColors = {
    "mysql": "bg-blue-100 text-blue-700",
    "postgresql": "bg-green-100 text-green-700", 
    "mssql": "bg-red-100 text-red-700",
    "sqlite": "bg-yellow-100 text-yellow-700",
    "oracle": "bg-purple-100 text-purple-700",
    "unknown": "bg-gray-100 text-gray-700"
  };
  
  const colorClass = dialectColors[dialect] || "bg-gray-100 text-gray-700";
  const confidenceIcon = confident ? "✓" : "?";
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs ${colorClass}`}
      title={`SQLi dialect: ${dialect} (${confident ? 'confident' : 'uncertain'})`}
    >
      {dialect} {confidenceIcon}
    </span>
  );
};

// XSS Context/Escaping chips
const XSSContextChips = ({ family, xss_context, xss_escaping, xss_context_source, xss_context_ml_proba }) => {
  if (family !== "xss" || !xss_context || !xss_escaping) return null;
  
  const contextMap = {
    "html_body": "html",
    "attr": "attr", 
    "js_string": "js",
    "url": "url",
    "css": "css",
    "unknown": "?"
  };
  
  const escapingMap = {
    "raw": "raw",
    "html": "html",
    "url": "url", 
    "js": "js",
    "unknown": "?"
  };
  
  return (
    <div className="flex gap-1 items-center">
      <span 
        className="px-2 py-0.5 rounded text-xs bg-orange-100 text-orange-700 font-mono"
        title={`XSS Context: ${xss_context}, Escaping: ${xss_escaping}`}
      >
        {contextMap[xss_context] || "?"}/{escapingMap[xss_escaping] || "?"}
      </span>
    </div>
  );
};

// SQLi Dialect chip
const SQLiDialectChip = ({ family, telemetry }) => {
  if (family !== "sqli") return null;
  
  if (!telemetry?.sqli_dialect_hint) {
    return (
      <span className="px-2 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-700" title="No SQLi dialect detected">
        —
      </span>
    );
  }
  
  const dialect = telemetry.sqli_dialect_hint;
  const confident = telemetry.sqli_dialect_confident;
  
  const dialectMap = {
    "mysql": "MySQL",
    "postgres": "PostgreSQL", 
    "mssql": "SQL Server",
    "sqlite": "SQLite"
  };
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs font-mono ${
        confident 
          ? "bg-green-100 text-green-700" 
          : "bg-yellow-100 text-yellow-700"
      }`}
      title={`Detected Dialect: ${dialect}${confident ? " (confident)" : " (weak signal)"}`}
    >
      {dialectMap[dialect] || dialect}
    </span>
  );
};

// Microcopy display
const Microcopy = ({ why }) => {
  const messages = humanizeWhyCodes(why || []);
  if (!messages.length) return null;
  return (
    <div className="text-xs text-gray-500 mt-1">
      {messages.join(" ")}
    </div>
  );
};

export default function FindingsTable({ results=[], onView }) {
  if (!results.length) return <div className="text-sm text-zinc-500 p-4">No results yet.</div>;

  // Group results by decision
  const grouped = results.reduce((acc, result) => {
    const decision = result.decision;
    if (!acc[decision]) acc[decision] = [];
    acc[decision].push(result);
    return acc;
  }, {});

  const [expandedSections, setExpandedSections] = useState({
    positive: true,
    clean: true,
    na: false
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const renderResultRow = (result, index) => (
    <tr key={index} className="border-t">
      <td className="p-2 flex items-center gap-2">
        {famIcon(result.family)}
        <span className="uppercase text-xs">{result.family}</span>
      </td>
      <td className="p-2 break-all">
        <div>{result.target?.method || result.method} {result.target?.url || result.url}</div>
        <Microcopy why={result.why} />
        {result.error_message && (
          <div className="mt-1 text-xs text-red-600 bg-red-50 px-2 py-1 rounded">
            Error: {result.error_message}
          </div>
        )}
      </td>
      <td className="p-2">
        {(() => {
          // Fallback order: param_in:param -> header:location for redirect -> none:none
          const paramIn = result.target?.param_in || result.param_in;
          const param = result.target?.param || result.param;
          const hasValidParams = paramIn && param && 
                                 paramIn !== 'none' && param !== 'none' &&
                                 paramIn !== '' && param !== '';
          
          if (hasValidParams) {
            return `${paramIn}:${param}`;
          } else if (result.family === 'redirect') {
            return 'header:location';
          } else {
            return <span className="text-gray-500">none:none</span>;
          }
        })()}
      </td>
      <td className="p-2">
        <div className="space-y-1">
          {badge(result.decision)}
          <ProvenanceChips why={result.why} />
          <ProofTypeBadge vuln_proof={result.vuln_proof} />
          <XSSContextChips 
            family={result.family} 
            xss_context={result.xss_context} 
            xss_escaping={result.xss_escaping}
            xss_context_source={result.xss_context_source}
            xss_context_ml_proba={result.xss_context_ml_proba}
          />
          <SQLiDialectChip 
            family={result.family} 
            telemetry={result.telemetry}
          />
        </div>
      </td>
      <td className="p-2">
        <DecisionSourceBadge 
          family={result.family}
          xssContextSource={result.xss_context_source}
          sqliDialectSource={result.sqli_dialect_source}
        />
      </td>
      <td className="p-2 text-right tabular-nums">
        {result.family === "xss" && result.xss_context_source === "ml" && result.xss_context_ml_proba ? 
          `${Math.round(result.xss_context_ml_proba * 100)}%` :
          result.family === "sqli" && result.sqli_dialect_source === "ml" && result.sqli_dialect_ml_proba ?
          `${Math.round(result.sqli_dialect_ml_proba * 100)}%` :
          result.ml?.classifier_used && result.ml_proba != null ? result.ml_proba.toFixed(2) : "—"}
      </td>
      <td className="p-2">
        <SQLiDialectBadge family={result.family} result={result} />
      </td>
      <td className="p-2 font-semibold">
        {result.cvss?.base ?? "—"}
      </td>
      <td className="p-2 text-right">
        <button 
          onClick={()=>onView?.(result.evidence_id)} 
          className="px-3 py-1 rounded bg-zinc-900 text-white hover:bg-zinc-800"
        >
          Evidence
        </button>
      </td>
    </tr>
  );

  const renderSection = (title, results, sectionKey, defaultExpanded = true) => {
    const isExpanded = expandedSections[sectionKey] ?? defaultExpanded;
    const count = results.length;
    
    return (
      <div key={sectionKey} className="mb-4">
        <button
          onClick={() => toggleSection(sectionKey)}
          className="flex items-center gap-2 text-sm font-semibold text-gray-700 mb-2 hover:text-gray-900"
        >
          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          {title} ({count})
        </button>
        
        {isExpanded && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-zinc-500">
                  <th className="p-2">Family</th>
                  <th className="p-2">Target</th>
                  <th className="p-2">Param</th>
                  <th className="p-2">Decision</th>
                  <th className="p-2">Decision Source</th>
                  <th className="p-2">ML Proba</th>
                  <th className="p-2">SQLi Dialect</th>
                  <th className="p-2">CVSS</th>
                  <th className="p-2"></th>
                </tr>
              </thead>
              <tbody>
                {results.map((result, index) => renderResultRow(result, index))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  };

  return (
    <div>
      {grouped.positive && renderSection("Positive", grouped.positive, "positive")}
      {grouped.suspected && renderSection("Suspected", grouped.suspected, "suspected")}
      {grouped.clean && renderSection("Clean", grouped.clean, "clean")}
      {grouped.not_applicable && renderSection("No parameters (NA)", grouped.not_applicable, "na", false)}
      {grouped.error && renderSection("Errors", grouped.error, "error", false)}
    </div>
  );
}
