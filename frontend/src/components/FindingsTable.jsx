"use client";
import { useState } from "react";

function CVSSChip({ score, vector, assumptions }) {
  const s = typeof score === "number" ? score : null;
  const color =
    s == null ? "bg-gray-200 text-gray-800" :
    s < 4 ? "bg-green-100 text-green-800" :
    s < 7 ? "bg-amber-100 text-amber-800" :
    s < 9 ? "bg-orange-100 text-orange-800" :
            "bg-red-100 text-red-800";
  
  const tooltipContent = [
    vector && `Vector: ${vector}`,
    assumptions?.length > 0 && `Assumptions:\n${assumptions.join("\n")}`
  ].filter(Boolean).join("\n\n");
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs cursor-help ${color}`} 
      title={tooltipContent}
    >
      {s == null ? "—" : s.toFixed(1)}
    </span>
  );
}

function InfoPopover({ why, children }) {
  const [isOpen, setIsOpen] = useState(false);
  
  if (!why || why.length === 0) return children;
  
  return (
    <div className="relative inline-block">
      <button
        className="text-blue-600 hover:text-blue-800"
        onMouseEnter={() => setIsOpen(true)}
        onMouseLeave={() => setIsOpen(false)}
      >
        {children}
      </button>
      {isOpen && (
        <div className="absolute z-10 w-64 p-3 mt-1 bg-white border border-gray-200 rounded-lg shadow-lg">
          <div className="text-sm">
            <div className="font-medium text-gray-900 mb-2">Why this was flagged:</div>
            <ul className="space-y-1">
              {why.map((reason, i) => (
                <li key={i} className="text-gray-700">• {reason}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default function FindingsTable({ report }) {
  const f = Array.isArray(report?.findings) ? report.findings : [];
  const s = report?.summary || {};
  return (
    <div className="bg-white rounded-xl shadow p-4">
      <h2 className="font-semibold mb-2">Findings ({f.length})</h2>
      <div className="text-sm text-gray-700 mb-2">
        total targets: {s.targets_total ?? "—"} · positive: {s.positive ?? f.length} · abstain: {s.abstain ?? "—"} · NA: {s.not_applicable ?? "—"} · suspected: {s.suspected ?? "—"}
      </div>
      {f.length === 0 ? (
        <div className="text-sm text-gray-600">No confirmed vulnerabilities yet.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b">
                <th className="pb-2">Family</th>
                <th className="pb-2">CVSS Score</th>
                <th className="pb-2">CVSS Vector</th>
                <th className="pb-2">Target</th>
                <th className="pb-2">Info</th>
              </tr>
            </thead>
            <tbody>
              {f.map((x,i)=>(
                <tr key={i} className="border-t">
                  <td className="py-2 capitalize font-medium">{x.family}</td>
                  <td className="py-2">
                    <CVSSChip score={x?.cvss?.score} vector={x?.cvss?.vector} assumptions={x?.cvss?.assumptions} />
                  </td>
                  <td className="py-2">
                    <span className="font-mono text-xs text-gray-600" title={x?.cvss?.vector}>
                      {x?.cvss?.vector ? x.cvss.vector.split('/').slice(0, 3).join('/') + '...' : '—'}
                    </span>
                  </td>
                  <td className="py-2 font-mono text-xs">
                    {x.method} {x.url} ({x.in_}:{x.param})
                  </td>
                  <td className="py-2">
                    <InfoPopover why={x.why}>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </InfoPopover>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
