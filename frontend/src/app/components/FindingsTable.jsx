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

// Rank Source badge
const RankSourceBadge = ({ rank_source }) => {
  if (!rank_source) return null;
  const colors = {
    "ml": "bg-purple-100 text-purple-700",
    "probe_only": "bg-blue-100 text-blue-700", 
    "defaults": "bg-gray-100 text-gray-700"
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs ${colors[rank_source] || "bg-gray-100 text-gray-700"}`}>
      {rank_source}
    </span>
  );
};

// ML chip with probability
const MLChip = ({ rank_source, ml_proba }) => {
  if (rank_source !== "ml" || ml_proba == null) return null;
  return (
    <span 
      className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700 font-mono"
      title="ML prioritized payload; decision from probe proof."
    >
      ML p={ml_proba.toFixed(2)}
    </span>
  );
};

// XSS Context/Escaping chips
const XSSContextChips = ({ family, xss_context, xss_escaping }) => {
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
    <span 
      className="px-2 py-0.5 rounded text-xs bg-orange-100 text-orange-700 font-mono"
      title={`XSS Context: ${xss_context}, Escaping: ${xss_escaping}`}
    >
      {contextMap[xss_context] || "?"}/{escapingMap[xss_escaping] || "?"}
    </span>
  );
};

// SQLi Dialect chip
const SQLiDialectChip = ({ family, dialect, dialect_confident }) => {
  if (family !== "sqli" || !dialect || dialect === "unknown") return null;
  
  const dialectMap = {
    "mysql": "MySQL",
    "postgresql": "PostgreSQL", 
    "mssql": "SQL Server",
    "sqlite": "SQLite"
  };
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs font-mono ${
        dialect_confident 
          ? "bg-green-100 text-green-700" 
          : "bg-yellow-100 text-yellow-700"
      }`}
      title={`Detected Dialect: ${dialect}${dialect_confident ? " (confident)" : " (weak signal)"}`}
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
        <div>{result.method} {result.url}</div>
        <Microcopy why={result.why} />
      </td>
      <td className="p-2">
        {result.param_in}:{result.param}
      </td>
      <td className="p-2">
        <div className="space-y-1">
          {badge(result.decision)}
          <ProvenanceChips why={result.why} />
          <MLChip rank_source={result.rank_source} ml_proba={result.ml_proba} />
          <XSSContextChips 
            family={result.family} 
            xss_context={result.xss_context} 
            xss_escaping={result.xss_escaping} 
          />
          <SQLiDialectChip 
            family={result.family} 
            dialect={result.dialect} 
            dialect_confident={result.dialect_confident} 
          />
        </div>
      </td>
      <td className="p-2">
        <RankSourceBadge rank_source={result.rank_source} />
      </td>
      <td className="p-2">
        {result.ml_proba != null ? result.ml_proba.toFixed(2) : "—"}
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
                  <th className="p-2">Rank Source</th>
                  <th className="p-2">ML Proba</th>
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
