"use client";
import { useState } from "react";
import { TriangleAlert, ShieldCheck, Database, Link as LinkIcon, ChevronDown, ChevronRight } from "lucide-react";

const famIcon = (f) => f==="xss" ? <TriangleAlert className="icon" /> : f==="sqli" ? <Database className="icon" /> : <LinkIcon className="icon" />;

const badge = (t) => <span className={`px-2 py-0.5 rounded text-xs ${t==="confirmed"?"bg-green-100 text-green-700":t==="suspected"?"bg-amber-100 text-amber-700":"bg-zinc-100 text-zinc-700"}`}>{t}</span>;

// Human-readable microcopy mapping
const microcopyMap = {
  "no_confirm_after_topk": "Tried top-K ranked payloads, none confirmed.",
  "ml_attempted": "ML suggested payloads were attempted.",
  "no_parameters_detected": "Endpoint has no testable parameters."
};

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

// Microcopy display
const Microcopy = ({ why }) => {
  const messages = why?.map(code => microcopyMap[code]).filter(Boolean) || [];
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
    confirmed: true,
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
        <div>{result.target?.method} {result.target?.url}</div>
        <Microcopy why={result.why} />
      </td>
      <td className="p-2">
        {result.target?.param_in}:{result.target?.param}
      </td>
      <td className="p-2 font-semibold">
        {result.evidence?.cvss?.base ?? "-"}
      </td>
      <td className="p-2">
        <div className="space-y-1">
          {badge(result.decision)}
          <ProvenanceChips why={result.why} />
        </div>
      </td>
      <td className="p-2 text-right">
        <div className="flex items-center gap-2">
          <PCalBadge p_cal={result.p_cal} />
          <button 
            onClick={()=>onView?.(result.evidence)} 
            className="px-3 py-1 rounded bg-zinc-900 text-white hover:bg-zinc-800"
          >
            Evidence
          </button>
        </div>
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
                  <th className="p-2">CVSS</th>
                  <th className="p-2">Status</th>
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
      {grouped.confirmed && renderSection("Confirmed", grouped.confirmed, "confirmed")}
      {grouped.tested_negative && renderSection("Clean", grouped.tested_negative, "clean")}
      {grouped.not_applicable && renderSection("No parameters (NA)", grouped.not_applicable, "na", false)}
    </div>
  );
}
