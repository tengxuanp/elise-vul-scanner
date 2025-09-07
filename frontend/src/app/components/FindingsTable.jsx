"use client";
import { TriangleAlert, ShieldCheck, Database, Link as LinkIcon } from "lucide-react";
const famIcon = (f) => f==="xss" ? <TriangleAlert className="icon" /> : f==="sqli" ? <Database className="icon" /> : <LinkIcon className="icon" />;
const badge = (t) => <span className={`px-2 py-0.5 rounded text-xs ${t==="confirmed"?"bg-green-100 text-green-700":t==="suspected"?"bg-amber-100 text-amber-700":"bg-zinc-100 text-zinc-700"}`}>{t}</span>;

export default function FindingsTable({ findings=[], onView }) {
  if (!findings.length) return <div className="text-sm text-zinc-500 p-4">No findings yet.</div>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-zinc-500">
            <th className="p-2">Family</th><th className="p-2">Target</th><th className="p-2">Param</th><th className="p-2">CVSS</th><th className="p-2">Status</th><th className="p-2"></th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f,i)=>(
            <tr key={i} className="border-t">
              <td className="p-2 flex items-center gap-2">{famIcon(f.family)}<span className="uppercase text-xs">{f.family}</span></td>
              <td className="p-2 break-all">{f.method} {f.url}</td>
              <td className="p-2">{f.param_in}:{f.param}</td>
              <td className="p-2 font-semibold">{f.cvss?.base ?? "-"}</td>
              <td className="p-2">{badge("confirmed")}</td>
              <td className="p-2 text-right">
                <button onClick={()=>onView?.(f)} className="px-3 py-1 rounded bg-zinc-900 text-white hover:bg-zinc-800">Evidence</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
