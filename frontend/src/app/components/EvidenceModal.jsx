"use client";
import { useEffect } from "react";

export default function EvidenceModal({ open, onClose, evidence, results = [] }) {
  useEffect(()=>{ document.body.style.overflow = open ? "hidden" : ""; }, [open]);
  if (!open) return null;

  // Build real cURL command
  const buildCurl = (evidence) => {
    if (!evidence) return "";
    
    const url = new URL(evidence.url);
    const method = evidence.method.toUpperCase();
    let curl = `curl -i -X ${method}`;
    
    // Add headers
    if (evidence.request_headers) {
      Object.entries(evidence.request_headers).forEach(([key, value]) => {
        curl += ` -H "${key}: ${value}"`;
      });
    }
    
    // Add parameters based on param_in
    if (evidence.param_in === "query") {
      url.searchParams.set(evidence.param, evidence.payload);
      curl += ` "${url.toString()}"`;
    } else if (evidence.param_in === "form") {
      curl += ` "${url.toString()}"`;
      curl += ` -d "${evidence.param}=${evidence.payload}"`;
    } else if (evidence.param_in === "json") {
      curl += ` "${url.toString()}"`;
      const jsonData = { [evidence.param]: evidence.payload };
      curl += ` -d '${JSON.stringify(jsonData)}'`;
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
            <code className="flex-1 bg-zinc-50 border rounded p-2 overflow-x-auto text-xs">{curl}</code>
            <button className="px-2 py-1 rounded bg-zinc-900 text-white text-xs" onClick={()=>navigator.clipboard.writeText(curl)}>Copy</button>
            <button className="px-2 py-1 rounded bg-blue-600 text-white text-xs" onClick={downloadHttp}>Download .http</button>
          </div>
        </div>
        <div className="text-xs text-zinc-500 my-2">Response snippet</div>
        <pre className="bg-zinc-50 border rounded p-3 max-h-80 overflow-auto whitespace-pre-wrap text-xs">
{evidence?.response_snippet || ""}
        </pre>
      </div>
    </div>
  );
}
