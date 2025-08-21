"use client";
import { useState, useMemo } from "react";
import CrawlForm from "../components/CrawlForm";
import { fuzzByJob, fuzzSelected, getReport } from "../api/api";
import { toast } from "react-toastify";

/** === Stable key per endpoint SHAPE (method + url + params + body_keys) === */
const shapeKey = (ep) => {
  const method = (ep.method || "GET").toUpperCase();
  const url = ep.url || "";
  const p = ep.params?.length ? [...ep.params].sort().join(",") : "_";
  const b = ep.body_keys?.length ? [...ep.body_keys].sort().join(",") : "_";
  return `${method} ${url} |p:${p}|b:${b}`;
};

/** Family guess for UI-only grouping (backend has its own router) */
const guessFamily = (ep) => {
  const pset = new Set((ep.params || []).map((s) => s.toLowerCase()));
  const path = (ep.url || "").toLowerCase();
  if (
    ["to", "return_to", "redirect", "url", "next", "callback", "continue"].some(
      (p) => pset.has(p)
    ) ||
    path.includes("redirect")
  )
    return "redirect";
  if (
    ["q", "search", "comment", "message", "content"].some((p) => pset.has(p)) &&
    (path.endsWith(".html") || !path.includes("/api/"))
  )
    return "xss";
  return "sqli";
};

/** Lightweight priority score for UI sort/selection (server has ML; this is a hint) */
const uiPriority = (ep) => {
  const params = (ep.params || []).map((x) => x.toLowerCase());
  const url = (ep.url || "").toLowerCase();
  let s = 0;
  if (params.some((p) => ["id", "uid", "pid", "productid", "user", "q", "search", "query", "to", "return_to", "redirect", "url"].includes(p))) s += 0.6;
  if (/(^|\/)(login|auth|admin|search|redirect|report|download)(\/|$)/.test(url)) s += 0.2;
  if ((ep.method || "GET").toUpperCase() === "GET") s += 0.1;
  return Math.min(1, s);
};

/** Small helpers */
const pct = (x) => (x * 100).toFixed(1) + "%";
const cn = (...xs) => xs.filter(Boolean).join(" ");

export default function CrawlAndFuzzPage() {
  const [jobId, setJobId] = useState(null);
  const [targetUrl, setTargetUrl] = useState("");
  const [endpointsRaw, setEndpointsRaw] = useState([]);
  const [captured, setCaptured] = useState([]);
  const [fuzzSummary, setFuzzSummary] = useState(null);
  const [loadingFuzz, setLoadingFuzz] = useState(false);
  const [filter, setFilter] = useState("");
  const [selectedKeys, setSelectedKeys] = useState(() => new Set());
  const [familyFilter, setFamilyFilter] = useState("all"); // all | sqli | xss | redirect

  /** De-dup endpoints by shape; annotate with UI-only family/priority */
  const endpoints = useMemo(() => {
    const seen = new Set();
    const out = [];
    for (const ep of endpointsRaw || []) {
      const k = shapeKey(ep);
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({
        ...ep,
        _shape: k,
        _family: guessFamily(ep),
        _priority: uiPriority(ep),
      });
    }
    // sort by priority (desc) then method/url for stability
    out.sort((a, b) => (b._priority || 0) - (a._priority || 0) || String(a.method).localeCompare(String(b.method)) || String(a.url).localeCompare(String(b.url)));
    return out;
  }, [endpointsRaw]);

  /** Filtering */
  const filtered = useMemo(() => {
    const q = filter.toLowerCase().trim();
    return endpoints.filter((ep) => {
      if (familyFilter !== "all" && ep._family !== familyFilter) return false;
      if (!q) return true;
      const hay = [
        ep.method || "",
        ep.url || "",
        ...(ep.params || []),
        ...(ep.body_keys || []),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [endpoints, filter, familyFilter]);

  const counts = useMemo(
    () => ({
      endpoints: endpoints.length,
      captured: captured.length,
      selected: selectedKeys.size,
      visible: filtered.length,
    }),
    [endpoints, captured, selectedKeys, filtered]
  );

  /** Crawl results in */
  const onResults = ({ job_id, target_url, endpoints, captured_requests }) => {
    setJobId(job_id);
    setTargetUrl(target_url);
    setEndpointsRaw(endpoints || []);
    setCaptured(captured_requests || []);
    setSelectedKeys(new Set());
    setFuzzSummary(null);
  };

  /** Selection helpers */
  const toggle = (ep) => {
    const k = ep._shape || shapeKey(ep);
    const next = new Set(selectedKeys);
    next.has(k) ? next.delete(k) : next.add(k);
    setSelectedKeys(next);
  };
  const selectAllVisible = () => {
    const next = new Set(selectedKeys);
    filtered.forEach((ep) => next.add(ep._shape));
    setSelectedKeys(next);
  };
  const selectTopNVisible = (n) => {
    const next = new Set(selectedKeys);
    filtered.slice(0, n).forEach((ep) => next.add(ep._shape));
    setSelectedKeys(next);
  };
  const selectFamilyVisible = (fam) => {
    const next = new Set(selectedKeys);
    filtered.filter((ep) => ep._family === fam).forEach((ep) => next.add(ep._shape));
    setSelectedKeys(next);
  };
  const clearSelection = () => setSelectedKeys(new Set());

  /** Actions */
  const runFuzzAll = async () => {
    if (!jobId) return toast.error("No job. Crawl first.");
    setLoadingFuzz(true);
    try {
      const data = await fuzzByJob(jobId); // backend defaults top_n/threshold
      setFuzzSummary(data);
      toast.success("Fuzzed all endpoints");
    } catch (e) {
      console.error(e);
      toast.error("Fuzz ALL failed");
    } finally {
      setLoadingFuzz(false);
    }
  };

  const runFuzzSelected = async () => {
    if (!jobId) return toast.error("No job. Crawl first.");
    if (selectedKeys.size === 0) return toast.warn("Select at least one endpoint");
    setLoadingFuzz(true);
    try {
      const lookup = new Set(selectedKeys);
      const selection = endpoints
        .filter((ep) => lookup.has(ep._shape))
        .map(({ method, url, params = [], body_keys = [] }) => ({
          method,
          url,
          params,
          body_keys,
        }));
      const data = await fuzzSelected(jobId, selection); // POST /fuzz/by_job/{job_id} with {selection}
      setFuzzSummary(data);
      toast.success(`Fuzzed ${selection.length} selected endpoint(s)`);
    } catch (e) {
      console.error(e);
      toast.error("Fuzz Selected failed");
    } finally {
      setLoadingFuzz(false);
    }
  };

  const downloadReport = async () => {
    if (!jobId) return toast.error("No job. Crawl first.");
    try {
      const blob = await getReport(jobId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `elise_report_${jobId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error(e);
      toast.error("Report download failed");
    }
  };

  /** Render helpers for fuzz summary */
  const results = useMemo(() => {
    // API may return { results: [...] } or { job_id, results: [...] }
    const r = (fuzzSummary && (fuzzSummary.results || fuzzSummary)) || [];
    return Array.isArray(r) ? r : [];
  }, [fuzzSummary]);

  const ConfBadge = ({ v }) => (
    <span
      className={cn(
        "px-2 py-0.5 rounded text-xs",
        v >= 0.8 ? "bg-green-600 text-white" : v >= 0.5 ? "bg-amber-500 text-white" : "bg-gray-300 text-gray-900"
      )}
      title={`confidence ${v.toFixed(2)}`}
    >
      {v.toFixed(2)}
    </span>
  );

  const FamilyBadge = ({ fam }) => (
    <span
      className={cn(
        "px-2 py-0.5 rounded text-xs",
        fam === "redirect" ? "bg-purple-600 text-white" : fam === "xss" ? "bg-pink-600 text-white" : "bg-blue-600 text-white"
      )}
    >
      {fam || "—"}
    </span>
  );

  const DeltaCell = ({ d }) => {
    if (!d) return <span className="text-gray-400">—</span>;
    const bits = [];
    if (d.status_changed) bits.push("status");
    if (typeof d.len_delta === "number") bits.push(`Δlen ${d.len_delta}`);
    if (typeof d.len_ratio === "number" && isFinite(d.len_ratio)) bits.push(`×${d.len_ratio.toFixed(2)}`);
    return <span>{bits.join(" · ") || "—"}</span>;
  };

  const RedirectCell = ({ one }) => {
    const ext = one?.signals?.external_redirect;
    const loc = one?.verify?.location;
    if (!ext) return <span className="text-gray-400">—</span>;
    return (
      <span className="inline-flex items-center gap-2">
        <span className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-900">external</span>
        <code className="text-xs break-all">{loc || ""}</code>
      </span>
    );
  };

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-2xl font-semibold">Crawl &amp; Fuzz</h1>

      <CrawlForm onJobReady={setJobId} onResults={onResults} />

      {jobId && (
        <div className="text-sm text-gray-600">
          <span className="font-mono">job_id:</span>{" "}
          <span className="font-mono">{jobId}</span>
        </div>
      )}

      {/* Quick stats */}
      <div className="grid grid-cols-5 gap-3">
        <div className="border rounded p-3">
          <div className="text-gray-500">Target</div>
          <div className="font-mono break-all">{targetUrl || "—"}</div>
        </div>
        <div className="border rounded p-3">
          <div className="text-gray-500">Endpoints</div>
          <div className="text-xl font-semibold">{counts.endpoints}</div>
        </div>
        <div className="border rounded p-3">
          <div className="text-gray-500">Visible</div>
          <div className="text-xl font-semibold">{counts.visible}</div>
        </div>
        <div className="border rounded p-3">
          <div className="text-gray-500">Selected</div>
          <div className="text-xl font-semibold">{counts.selected}</div>
        </div>
        <div className="border rounded p-3">
          <div className="text-gray-500">Captured</div>
          <div className="text-xl font-semibold">{counts.captured}</div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-2 items-center">
        <button
          className="bg-purple-600 text-white px-4 py-2 rounded disabled:opacity-60"
          onClick={runFuzzAll}
          disabled={!jobId || loadingFuzz}
        >
          {loadingFuzz ? "Fuzzing…" : "Fuzz ALL"}
        </button>
        <button
          className="bg-blue-600 text-white px-4 py-2 rounded disabled:opacity-60"
          onClick={runFuzzSelected}
          disabled={!jobId || loadingFuzz || selectedKeys.size === 0}
        >
          Fuzz Selected
        </button>
        <button
          className="bg-gray-800 text-white px-4 py-2 rounded disabled:opacity-60"
          onClick={downloadReport}
          disabled={!jobId}
        >
          Download Report
        </button>

        <div className="ml-auto flex items-center gap-2">
          <select
            className="border p-2 rounded"
            value={familyFilter}
            onChange={(e) => setFamilyFilter(e.target.value)}
            title="Filter by inferred family"
          >
            <option value="all">All families</option>
            <option value="sqli">SQLi</option>
            <option value="xss">XSS</option>
            <option value="redirect">Redirect</option>
          </select>
          <input
            className="border p-2 rounded min-w-[220px]"
            placeholder="Filter (method, path, params)"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button className="border px-3 py-2 rounded" onClick={selectAllVisible}>
            Select all (visible)
          </button>
          <button
            className="border px-3 py-2 rounded"
            onClick={() => selectTopNVisible(20)}
            title="Select top 20 visible by priority"
          >
            Select top 20
          </button>
          <button className="border px-3 py-2 rounded" onClick={() => selectFamilyVisible("redirect")}>
            Select redirects
          </button>
          <button className="border px-3 py-2 rounded" onClick={() => selectFamilyVisible("xss")}>
            Select XSS
          </button>
          <button className="border px-3 py-2 rounded" onClick={() => selectFamilyVisible("sqli")}>
            Select SQLi
          </button>
          <button className="border px-3 py-2 rounded" onClick={clearSelection}>
            Clear
          </button>
        </div>
      </div>

      {/* Endpoint list with checkboxes */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold">Endpoints</h2>
        <div className="border rounded max-h-80 overflow-auto">
          {filtered.length === 0 ? (
            <div className="p-3 text-gray-500">No endpoints</div>
          ) : (
            filtered.map((ep) => {
              const checked = selectedKeys.has(ep._shape);
              return (
                <label
                  key={ep._shape}
                  className="p-3 border-b flex items-start gap-3 cursor-pointer hover:bg-gray-50"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggle(ep)}
                    className="mt-1"
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm">{(ep.method || "").toUpperCase()}</span>
                      <span className="font-mono text-sm break-all">{ep.url}</span>
                      <span className="ml-auto flex items-center gap-2">
                        <span className="text-xs text-gray-500">prio:</span>
                        <span className="text-xs font-mono">{(ep._priority || 0).toFixed(2)}</span>
                        <span className={cn(
                          "px-2 py-0.5 rounded text-xs",
                          ep._family === "redirect" ? "bg-purple-100 text-purple-900" :
                          ep._family === "xss" ? "bg-pink-100 text-pink-900" :
                          "bg-blue-100 text-blue-900"
                        )}>
                          {ep._family}
                        </span>
                      </span>
                    </div>
                    {ep.params?.length ? (
                      <div className="text-xs text-gray-600">params: {ep.params.join(", ")}</div>
                    ) : null}
                    {ep.body_keys?.length ? (
                      <div className="text-xs text-gray-600">body: {ep.body_keys.join(", ")}</div>
                    ) : null}
                  </div>
                </label>
              );
            })
          )}
        </div>
      </section>

      {/* Captured requests (compact) */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold">Captured Requests</h2>
        <div className="border rounded max-h-80 overflow-auto">
          {captured.length === 0 ? (
            <div className="p-3 text-gray-500">No captured requests</div>
          ) : (
            captured.map((r, i) => (
              <div key={i} className="p-3 border-b">
                <div className="font-mono text-sm break-all">
                  {(r.method || "").toUpperCase()} {r.url}
                </div>
                {r.post_data ? (
                  <pre className="text-xs mt-1 bg-gray-50 p-2 rounded overflow-auto">
                    {JSON.stringify(r.post_data, null, 2)}
                  </pre>
                ) : null}
              </div>
            ))
          )}
        </div>
      </section>

      {/* Fuzz summary */}
      {results.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-lg font-semibold">Fuzz Results</h2>
          <div className="overflow-auto border rounded">
            <table className="min-w-full text-sm">
              <thead className="bg-gray-50">
                <tr className="text-left">
                  <th className="p-2">Method</th>
                  <th className="p-2">URL</th>
                  <th className="p-2">Param</th>
                  <th className="p-2">Family</th>
                  <th className="p-2">Confidence</th>
                  <th className="p-2">Delta</th>
                  <th className="p-2">Redirect</th>
                  <th className="p-2">Payload</th>
                </tr>
              </thead>
              <tbody>
                {results.map((one, i) => (
                  <tr key={`${one.method}-${one.url}-${one.param}-${i}`} className="border-t align-top">
                    <td className="p-2 font-mono">{(one.method || "").toUpperCase()}</td>
                    <td className="p-2 font-mono break-all">{one.url}</td>
                    <td className="p-2 font-mono">{one.param}</td>
                    <td className="p-2"><FamilyBadge fam={one.family} /></td>
                    <td className="p-2"><ConfBadge v={Number(one.confidence || 0)} /></td>
                    <td className="p-2"><DeltaCell d={one.delta} /></td>
                    <td className="p-2"><RedirectCell one={one} /></td>
                    <td className="p-2">
                      <code className="text-xs break-all">{one.payload}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Raw JSON dump (debug) */}
          <details className="border rounded p-3 bg-gray-50">
            <summary className="cursor-pointer text-sm text-gray-700">Raw JSON</summary>
            <pre className="overflow-auto text-xs">{JSON.stringify(fuzzSummary, null, 2)}</pre>
          </details>
        </section>
      )}
    </div>
  );
}
