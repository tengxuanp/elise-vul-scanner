"use client";
import { useState, useMemo } from "react";
import CrawlForm from "../components/CrawlForm";
import { fuzzByJob, fuzzSelected, getReport } from "../api/api";
import { toast } from "react-toastify";

/** === helpers === */
const isNonEmptyArray = (v) => Array.isArray(v) && v.length > 0;
const cn = (...xs) => xs.filter(Boolean).join(" ");

/** === Normalize raw endpoint into a consistent shape for UI/selection === */
const normalizeEndpoint = (ep) => {
  const url = ep.url || "";
  const method = (ep.method || "GET").toUpperCase();
  const pl = ep.param_locs || {};

  // Infer query keys from URL (works for ?q= blank values too)
  let qFromUrl = [];
  try {
    const u = new URL(url);
    qFromUrl = Array.from(new Set([...u.searchParams.keys()])).filter(Boolean);
  } catch {}

  // Prefer non-empty param_locs.query, else legacy ep.params, else URL inference
  const q =
    (isNonEmptyArray(pl.query) && pl.query) ||
    (isNonEmptyArray(ep.params) && ep.params) ||
    qFromUrl;

  // Prefer non-empty param_locs.body, else legacy body_keys, else from parsed body
  const b =
    (isNonEmptyArray(pl.body) && pl.body) ||
    (isNonEmptyArray(ep.body_keys) && ep.body_keys) ||
    (ep.body_parsed && typeof ep.body_parsed === "object"
      ? Object.keys(ep.body_parsed)
      : []);

  return { ...ep, method, url, params: q, body_keys: b };
};

/** === Stable key per endpoint SHAPE (method + url + params + body_keys) === */
const shapeKey = (ep) => {
  const method = (ep.method || "GET").toUpperCase();
  const url = ep.url || "";
  const p = isNonEmptyArray(ep.params) ? [...ep.params].sort().join(",") : "_";
  const b = isNonEmptyArray(ep.body_keys) ? [...ep.body_keys].sort().join(",") : "_";
  return `${method} ${url} |p:${p}|b:${b}`;
};

/** Family guess for UI-only grouping (backend has its own router) */
const guessFamily = (ep) => {
  const pset = new Set((ep.params || []).map((s) => String(s).toLowerCase()));
  const path = (ep.url || "").toLowerCase();

  if (
    ["to", "return_to", "redirect", "url", "next", "callback", "continue"].some(
      (p) => pset.has(p)
    ) ||
    path.includes("redirect")
  )
    return "redirect";

  if (["q", "query", "search"].some((p) => pset.has(p))) {
    return path.includes("/api/") || path.includes("/rest/") ? "sqli" : "xss";
  }

  if (
    ["comment", "message", "content", "text", "title", "name"].some((p) =>
      pset.has(p)
    )
  )
    return "xss";

  return "sqli";
};

/** Infer family from signals if available (preferred over path/param guess) */
const familyFromSignals = (sig) => {
  const s = sig || {};
  const redir = s.open_redirect || {};
  const refl = s.reflection || {};
  if (redir.open_redirect) return "redirect";
  if (refl.raw || refl.js_context) return "xss";
  if (s.sql_error === true || s.type === "sqli") return "sqli";
  if ((s.login || {}).login_success) return "sqli";
  if (typeof s.type === "string" && ["redirect", "xss", "sqli"].includes(s.type))
    return s.type;
  return null;
};

/** Lightweight priority score for UI sort/selection (server has ML; this is a hint) */
const uiPriority = (ep) => {
  const params = (ep.params || []).map((x) => x.toLowerCase());
  const url = (ep.url || "").toLowerCase();
  let s = 0;
  if (
    params.some((p) =>
      [
        "id",
        "uid",
        "pid",
        "productid",
        "user",
        "q",
        "search",
        "query",
        "to",
        "return_to",
        "redirect",
        "url",
      ].includes(p)
    )
  )
    s += 0.6;
  if (/(^|\/)(login|auth|admin|search|redirect|report|download)(\/|$)/.test(url))
    s += 0.2;
  if ((ep.method || "GET").toUpperCase() === "GET") s += 0.1;
  return Math.min(1, s);
};

/** Derive a stable "row" shape from heterogeneous fuzzer outputs */
const normalizeResultRow = (one = {}) => {
  const req = one.request || {};
  const sig = one.signals || {};
  const method = (one.method || req.method || "GET").toUpperCase();
  const url = one.url || req.url || "";
  const param = one.param || one.target_param || req.param || "";
  const confidence = Number(one.confidence || 0);

  const statusDelta =
    typeof one.status_delta === "number" ? one.status_delta : undefined;
  const lenDelta = typeof one.len_delta === "number" ? one.len_delta : undefined;
  const msDelta =
    typeof one.latency_ms_delta === "number" ? one.latency_ms_delta : undefined;

  const redir = sig.open_redirect || {};
  const location =
    redir.location ||
    (one.response_headers || {}).location ||
    (sig.verify || {}).location;
  const external = redir.open_redirect || sig.external_redirect || false;
  const locationHost = redir.location_host || sig.redirect_host || null;

  const login = sig.login || {};
  const loginSuccess = !!login.login_success;
  const tokenPresent = !!login.token_present;

  const refl = sig.reflection || {};
  const xssReflected = !!(refl.raw || refl.js_context);

  const sqlErr = sig.sql_error === true;
  const verify = sig.verify || {};

  const payload = one.payload || req.payload || "";

  const fam =
    familyFromSignals(sig) || one.family || (one.signals && one.signals.type) || null;

  return {
    method,
    url,
    param,
    confidence,
    payload,
    family: fam,
    delta: {
      status_changed:
        typeof statusDelta === "number" ? statusDelta !== 0 : undefined,
      len_delta: lenDelta,
      len_ratio:
        typeof lenDelta === "number" &&
        typeof one.baseline_len === "number" &&
        one.baseline_len > 0
          ? (one.baseline_len + lenDelta) / one.baseline_len
          : undefined,
      ms_delta: msDelta,
    },
    signals: {
      sql_error: sqlErr,
      xss_reflected: xssReflected,
      login_success: loginSuccess,
      token_present: tokenPresent,
      external_redirect: !!external,
      location,
      location_host: locationHost,
      verify,
    },
  };
};

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
  const [fuzzBearer, setFuzzBearer] = useState(""); // optional bearer for core engine

  /** De-dup endpoints by shape; annotate with UI-only family/priority */
  const endpoints = useMemo(() => {
    const seen = new Set();
    const out = [];
    for (const raw of endpointsRaw || []) {
      const ep = normalizeEndpoint(raw);
      const k = shapeKey(ep);
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({
        ...ep,
        _shape: k,
        _family: familyFromSignals(raw?.signals) || guessFamily(ep),
        _priority: uiPriority(ep),
      });
    }
    out.sort(
      (a, b) =>
        (b._priority || 0) - (a._priority || 0) ||
        String(a.method).localeCompare(String(b.method)) ||
        String(a.url).localeCompare(String(b.url))
    );
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
    setEndpointsRaw(Array.isArray(endpoints) ? endpoints : []);
    setCaptured(Array.isArray(captured_requests) ? captured_requests : []);
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
    filtered
      .filter((ep) => ep._family === fam)
      .forEach((ep) => next.add(ep._shape));
    setSelectedKeys(next);
  };
  const clearSelection = () => setSelectedKeys(new Set());

  /** Actions (force core engine) */
  const runFuzzAll = async () => {
    if (!jobId) return toast.error("No job. Crawl first.");
    setLoadingFuzz(true);
    try {
      const data = await fuzzByJob(jobId, {
        engine: "core",
        bearer_token: fuzzBearer || undefined,
      });
      setFuzzSummary(data);
      toast.success("Fuzzed all endpoints (core engine)");
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
      const baseSelection = endpoints
        .filter((ep) => lookup.has(ep._shape))
        .map(({ method, url, params = [], body_keys = [] }) => ({
          method,
          url,
          params,
          body_keys,
        }));

      // Pre-send inference: if params/body are empty, try to infer from URL/body again
      const selection = baseSelection.map((item) => {
        let params = item.params || [];
        if (!isNonEmptyArray(params) && item.url && item.url.includes("?")) {
          try {
            const u = new URL(item.url);
            params = Array.from(new Set([...u.searchParams.keys()])).filter(Boolean);
          } catch {}
        }
        return { ...item, params };
      });

      const allEmpty = selection.every(
        (s) =>
          (!isNonEmptyArray(s.params)) &&
          (!isNonEmptyArray(s.body_keys))
      );
      if (allEmpty) {
        toast.warn("Selected endpoints have no params/body keys to fuzz.");
      }

      const data = await fuzzSelected(jobId, selection, {
        engine: "core",
        bearer_token: fuzzBearer || undefined,
      });
      setFuzzSummary(data);
      toast.success(
        `Fuzzed ${selection.length} selected endpoint(s) (core engine)`
      );
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
  const rawResults = useMemo(() => {
    if (!fuzzSummary) return [];
    if (Array.isArray(fuzzSummary)) return fuzzSummary;
    if (Array.isArray(fuzzSummary.results)) return fuzzSummary.results;
    return [];
  }, [fuzzSummary]);

  const results = useMemo(() => rawResults.map(normalizeResultRow), [rawResults]);

  const ConfBadge = ({ v }) => (
    <span
      className={cn(
        "px-2 py-0.5 rounded text-xs",
        v >= 0.8 ? "bg-green-600 text-white" : v >= 0.5 ? "bg-amber-500 text-white" : "bg-gray-300 text-gray-900"
      )}
      title={`confidence ${Number(v || 0).toFixed(2)}`}
    >
      {Number(v || 0).toFixed(2)}
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
    if (typeof d.ms_delta === "number") bits.push(`Δms ${d.ms_delta}`);
    if (typeof d.len_ratio === "number" && isFinite(d.len_ratio)) bits.push(`×${Number(d.len_ratio).toFixed(2)}`);
    return bits.length ? <span>{bits.join(" · ")}</span> : <span className="text-gray-400">—</span>;
  };

  const RedirectCell = ({ row }) => {
    const ext = row?.signals?.external_redirect;
    const loc = row?.signals?.location;
    const host = row?.signals?.location_host;
    if (!ext && !loc) return <span className="text-gray-400">—</span>;
    return (
      <span className="inline-flex items-center gap-2">
        {ext ? <span className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-900">external</span> : null}
        {host ? <span className="px-2 py-0.5 rounded text-xs bg-purple-50 text-purple-900">{host}</span> : null}
        {loc ? <code className="text-xs break-all">{loc}</code> : null}
      </span>
    );
  };

  const SqlCell = ({ row }) => {
    const s = row?.signals || {};
    if (s.sql_error) return <span className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-900">sql error</span>;
    const ms = row?.delta?.ms_delta;
    const len = row?.delta?.len_delta;
    if (typeof ms === "number" && ms >= 1500) return <span className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-900">timing Δ{ms}ms</span>;
    if (typeof len === "number" && Math.abs(len) >= 200) return <span className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-900">boolean Δlen {len}</span>;
    return <span className="text-gray-400">—</span>;
  };

  const XssCell = ({ row }) => {
    return row?.signals?.xss_reflected
      ? <span className="px-2 py-0.5 rounded text-xs bg-pink-100 text-pink-900">reflected</span>
      : <span className="text-gray-400">—</span>;
  };

  const LoginCell = ({ row }) => {
    const s = row?.signals || {};
    if (s.login_success || s.token_present) {
      return (
        <span className="inline-flex items-center gap-2">
          {s.login_success ? <span className="px-2 py-0.5 rounded text-xs bg-green-100 text-green-900">bypass</span> : null}
          {s.token_present ? <span className="px-2 py-0.5 rounded text-xs bg-green-50 text-green-900">token</span> : null}
        </span>
      );
    }
    return <span className="text-gray-400">—</span>;
  };

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-2xl font-semibold">Crawl &amp; Fuzz</h1>

      <CrawlForm onJobReady={setJobId} onResults={onResults} />

      {jobId && (
        <div className="text-sm text-gray-600 flex items-center gap-2 flex-wrap">
          <span className="font-mono">job_id:</span>
          <span className="font-mono">{jobId}</span>
          <span className="ml-4 text-gray-500">Core engine uses cookies from crawl and optional bearer:</span>
          <input
            className="border p-1 rounded min-w-[260px]"
            placeholder="Optional bearer token for fuzz (Authorization: Bearer ...)"
            value={fuzzBearer}
            onChange={(e) => setFuzzBearer(e.target.value)}
          />
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
          {loadingFuzz ? "Fuzzing…" : "Fuzz ALL (core)"}
        </button>
        <button
          className="bg-blue-600 text-white px-4 py-2 rounded disabled:opacity-60"
          onClick={runFuzzSelected}
          disabled={!jobId || loadingFuzz || selectedKeys.size === 0}
        >
          Fuzz Selected (core)
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
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-xs",
                            ep._family === "redirect"
                              ? "bg-purple-100 text-purple-900"
                              : ep._family === "xss"
                              ? "bg-pink-100 text-pink-900"
                              : "bg-blue-100 text-blue-900"
                          )}
                        >
                          {ep._family}
                        </span>
                      </span>
                    </div>
                    {isNonEmptyArray(ep.params) ? (
                      <div className="text-xs text-gray-600">params: {ep.params.join(", ")}</div>
                    ) : null}
                    {isNonEmptyArray(ep.body_keys) ? (
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
                {r.body_parsed ? (
                  <pre className="text-xs mt-1 bg-gray-50 p-2 rounded overflow-auto">
                    {JSON.stringify(r.body_parsed, null, 2)}
                  </pre>
                ) : r.post_data ? (
                  <pre className="text-xs mt-1 bg-gray-50 p-2 rounded overflow-auto">
                    {typeof r.post_data === "string" ? r.post_data : JSON.stringify(r.post_data, null, 2)}
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
                  <th className="p-2">Δ</th>
                  <th className="p-2">SQLi</th>
                  <th className="p-2">XSS</th>
                  <th className="p-2">Login</th>
                  <th className="p-2">Redirect</th>
                  <th className="p-2">Payload</th>
                </tr>
              </thead>
              <tbody>
                {results.map((row, i) => (
                  <tr key={`${row.method}-${row.url}-${row.param}-${i}`} className="border-t align-top">
                    <td className="p-2 font-mono">{row.method}</td>
                    <td className="p-2 font-mono break-all">{row.url}</td>
                    <td className="p-2 font-mono">{row.param}</td>
                    <td className="p-2"><FamilyBadge fam={row.family || "sqli"} /></td>
                    <td className="p-2"><ConfBadge v={Number(row.confidence || 0)} /></td>
                    <td className="p-2"><DeltaCell d={row.delta} /></td>
                    <td className="p-2"><SqlCell row={row} /></td>
                    <td className="p-2"><XssCell row={row} /></td>
                    <td className="p-2"><LoginCell row={row} /></td>
                    <td className="p-2"><RedirectCell row={row} /></td>
                    <td className="p-2">
                      <code className="text-xs break-all">{row.payload || ""}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <details className="border rounded p-3 bg-gray-50">
            <summary className="cursor-pointer text-sm text-gray-700">Raw JSON</summary>
            <pre className="overflow-auto text-xs">{JSON.stringify(fuzzSummary, null, 2)}</pre>
          </details>
        </section>
      )}
    </div>
  );
}
