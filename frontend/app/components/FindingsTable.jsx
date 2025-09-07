"use client";
import { TriangleAlert, Database, Link as LinkIcon } from "lucide-react";

const FamIcon = ({f}) => f==="xss"? <TriangleAlert className="icon"/> : f==="sqli"? <Database className="icon"/> : <LinkIcon className="icon"/>;

export default function FindingsTable({ findings=[], results=[], onView }) {
  if (!findings.length) return <div className="text-sm text-zinc-500 p-4">No findings yet.</div>;
  
  // Helper function to determine origin from why array
  const getOrigin = (why) => {
    if (why?.includes("probe_proof")) return "Probe";
    if (why?.includes("ml_ranked") && why?.includes("inject_confirmed")) return "ML+Inject";
    return "Unknown";
  };
  
  // Helper function to get the corresponding result for a finding
  const getResultForFinding = (finding) => {
    return results.find(r => 
      r.target.url === finding.url && 
      r.target.method === finding.method && 
      r.target.param_in === finding.param_in && 
      r.target.param === finding.param
    );
  };
  
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-zinc-500">
            <th className="p-2">Origin</th>
            <th className="p-2">Family</th>
            <th className="p-2">Target</th>
            <th className="p-2">Param</th>
            <th className="p-2">CVSS</th>
            <th className="p-2"></th>
          </tr>
        </thead>
        <tbody>
        {findings.map((f,i)=>{
          const result = getResultForFinding(f);
          const origin = getOrigin(result?.why);
          return (
            <tr key={i} className="border-t">
              <td className="p-2">
                <span className={`px-2 py-1 rounded text-xs font-medium ${
                  origin === "Probe" 
                    ? "bg-gray-100 text-gray-700" 
                    : "bg-blue-100 text-blue-700"
                }`}>
                  {origin}
                </span>
              </td>
              <td className="p-2 flex items-center gap-2"><FamIcon f={f.family}/><span className="uppercase text-xs">{f.family}</span></td>
              <td className="p-2 break-all">{f.method} {f.url}</td>
              <td className="p-2">{f.param_in}:{f.param}</td>
              <td className="p-2 font-semibold">{f.cvss?.base ?? "-"}</td>
              <td className="p-2 text-right"><button onClick={()=>onView?.(f)} className="px-3 py-1 rounded bg-zinc-900 text-white hover:bg-zinc-800">Evidence</button></td>
            </tr>
          );
        })}
        </tbody>
      </table>
    </div>
  );
}
