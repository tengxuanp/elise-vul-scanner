"use client";
import { useEffect } from "react";

export default function EvidenceModal({ open, onClose, evidence }) {
  useEffect(()=>{ document.body.style.overflow = open ? "hidden" : ""; }, [open]);
  if (!open) return null;
  const curl = evidence ? `curl -i -X ${evidence.method} ${JSON.stringify(evidence.url)}` : "";
  return (
    <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-white rounded-2xl shadow p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-lg font-semibold">Evidence</h3>
          <button onClick={onClose} className="px-2 py-1 rounded bg-zinc-100 hover:bg-zinc-200">Close</button>
        </div>
        <div className="mb-2">
          <div className="text-xs text-zinc-500 mb-1">Reproduce</div>
          <div className="flex gap-2">
            <code className="flex-1 bg-zinc-50 border rounded p-2 overflow-x-auto">{curl}</code>
            <button className="px-2 py-1 rounded bg-zinc-900 text-white" onClick={()=>navigator.clipboard.writeText(curl)}>Copy</button>
          </div>
        </div>
        <div className="text-xs text-zinc-500 my-2">Response snippet</div>
        <pre className="bg-zinc-50 border rounded p-3 max-h-80 overflow-auto whitespace-pre-wrap">
{evidence?.response_snippet || ""}
        </pre>
      </div>
    </div>
  );
}
