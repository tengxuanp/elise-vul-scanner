"use client";
import { useMemo, useState } from "react";
import useDebouncedValue from "../hooks/useDebouncedValue";

export default function EndpointTable({ endpoints, meta }) {
  const [q, setQ] = useState("");
  const [hasParams, setHasParams] = useState(false);
  const debouncedQ = useDebouncedValue(q, 100);
  
  // Map rows from API shape directly
  const rows = useMemo(() => {
    return (endpoints || []).map(e => ({
      path: e.path || new URL(e.url).pathname,
      method: e.method,
      params: e.params,               // array of strings
      status: e.status ?? "",
      type: e.content_type ?? "",
      source: e.source ?? "",
      seen: e.seen ?? 1,
      url: e.url
    }));
  }, [endpoints]);
  
  const filtered = useMemo(() => {
    return rows.filter(e => {
      const hit = (e.path||"").includes(debouncedQ) || (e.params||[]).join(",").includes(debouncedQ);
      const hp = !hasParams || (e.params && e.params.length > 0);
      return hit && hp;
    });
  }, [rows, debouncedQ, hasParams]);
  
  // Cap rendering to 300 items for performance
  const shown = filtered.slice(0, 300);

  return (
    <div className="bg-white rounded-xl shadow p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-semibold">Observed Endpoints ({filtered.length})</h2>
        <div className="flex items-center gap-2">
          <input className="border rounded p-1 px-2" placeholder="filter…" value={q} onChange={e=>setQ(e.target.value)} />
          <label className="text-sm flex items-center gap-1">
            <input type="checkbox" checked={hasParams} onChange={e=>setHasParams(e.target.checked)} /> has params
          </label>
        </div>
      </div>
      
      {/* Meta badges */}
      {meta && (
        <div className="mb-4 p-3 bg-gray-50 rounded-lg">
          <div className="flex items-center gap-4 text-sm">
            <span className="font-medium">Visited: {meta.pagesVisited}</span>
            <span className="font-medium">XHR: {meta.xhrCount}</span>
            <span className="font-medium">Endpoints: {meta.emitted}</span>
            <span className="font-medium">With params: {meta.withParams}</span>
            <span className={`px-2 py-1 rounded text-xs font-medium ${
              meta.engine === 'playwright-strict' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
            }`}>
              Engine: {meta.engine}
            </span>
          </div>
        </div>
      )}
      {filtered.length === 0 ? (
        <div className="text-sm text-gray-600">
          No observed endpoints. We only show **capture-only** network results. Increase depth, add seed paths, or ensure the app is interactive.
        </div>
      ) : (
        <>
          {filtered.length > 300 && (
            <div className="text-xs text-gray-500 mb-2">
              Showing {shown.length} of {filtered.length} endpoints
            </div>
          )}
          <table className="w-full text-sm">
            <thead><tr className="text-left text-gray-500"><th>Path</th><th>Method</th><th>Params</th><th>Status</th><th>Type</th><th>Source</th><th>Prov.</th></tr></thead>
            <tbody>
              {shown.map((e,i)=>(
                <tr key={i} className="border-t">
                  <td className="py-1">{e.path}</td>
                  <td>{e.method}</td>
                  <td>{e.params.length ? e.params.join(", ") : ""}</td>
                  <td>{e.status || ""}</td>
                  <td>{e.type}</td>
                  <td>{e.source}</td>
                  <td><span className="px-2 py-0.5 rounded bg-gray-100">{e.seen}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
