"use client";
import { useMemo, useState } from "react";

export default function EndpointTable({ endpoints }) {
  const [q, setQ] = useState("");
  const [hasParams, setHasParams] = useState(false);
  const filtered = useMemo(() => {
    return (endpoints || []).filter(e => {
      const hit = (e.path||"").includes(q) || (e.param_names||[]).join(",").includes(q);
      const hp = !hasParams || (Array.isArray(e.param_names) && e.param_names.length>0);
      return hit && hp;
    });
  }, [endpoints, q, hasParams]);

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
      {filtered.length === 0 ? (
        <div className="text-sm text-gray-600">
          No observed endpoints. We only show **capture-only** network results. Increase depth, add seed paths, or ensure the app is interactive.
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead><tr className="text-left text-gray-500"><th>Path</th><th>Method</th><th>Params</th><th>Status</th><th>Type</th><th>Source</th><th>Prov.</th></tr></thead>
          <tbody>
            {filtered.map((e,i)=>(
              <tr key={i} className="border-t">
                <td className="py-1">{e.path || "/"}</td>
                <td>{e.method}</td>
                <td>{(e.param_names||[]).join(", ")}</td>
                <td>{e.status ?? ""}</td>
                <td>{e.content_type?.split(";")[0] || ""}</td>
                <td>{e.source}</td>
                <td><span className="px-2 py-0.5 rounded bg-gray-100">{(e.prov_event_ids||[]).length||0}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
