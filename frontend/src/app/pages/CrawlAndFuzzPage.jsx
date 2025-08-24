// frontend/app/pages/CrawlAndFuzzPage.jsx
"use client";
import { useState, useMemo } from "react";
import CrawlForm from "../components/CrawlForm";
import { fuzzByJob, fuzzSelected, getReport } from "../api/api";
import { toast } from "react-toastify";

/** === helpers === */
const isNonEmptyArray = (v) => Array.isArray(v) && v.length > 0;
const cn = (...xs) => xs.filter(Boolean).join(" ");

/** Extract plain names from arrays that can contain strings or {name: "..."} dicts */
const namesFrom = (xs) => {
  if (!Array.isArray(xs)) return [];
  const out = [];
  const seen = new Set();
  for (const it of xs) {
    let n = "";
    if (typeof it === "string") n = it;
    else if (it && typeof it === "object") n = it.name || it.param || it.key || "";
    if (n && !seen.has(n)) {
      seen.add(n);
      out.push(String(n));
    }
  }
  return out;
};

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

  // param_locs can be strings or {name:"…"}
  const qParamLocs = namesFrom(pl.query);
  const formParamLocs = namesFrom(pl.form);
  const jsonParamLocs = namesFrom(pl.json);

  // Legacy fallbacks
  const legacyQuery = isNonEmptyArray(ep.query_keys) ? ep.query_keys : isNonEmptyArray(ep.params) ? ep.params : [];
  const legacyBody = isNonEmptyArray(ep.body_keys) ? ep.body_keys : (ep.body_parsed && typeof ep.body_parsed === "object" ? Object.keys(ep.body_parsed) : []);

  // Prefer new schema; then legacy; then URL inference
  const queryParams = isNonEmptyArray(qParamLocs) ? qParamLocs : isNonEmptyArray(legacyQuery) ? legacyQuery : qFromUrl;

  // Body params = form ∪ json (new schema) else legacy body hints
  const formParams = formParamLocs;
  const jsonParams = jsonParamLocs;
  const bodyParams = isNonEmptyArray(formParams) || isNonEmptyArray(jsonParams) ? [...new Set([...(formParams || []), ...(jsonParams || [])])] : legacyBody;

  // For selection, the backend trims across all locations → send union
  const allParams = [...new Set([...(queryParams || []), ...(bodyParams || [])])];

  return {
    ...ep,
    method,
    url,
    // keep original breakdown for display (UI uses .params and .body_keys below)
    params: queryParams,
    body_keys: bodyParams,
    _form_params: formParams,
    _json_params: jsonParams,
    _all_params: allParams,
  };
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
  const pset = new Set(
    (ep._all_params || ep.params || []).map((s) => String(s).toLowerCase())
  );
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
  const params = (ep._all_params || ep.params || []).map((x) => x.toLowerCase());
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

  // derive a severity that’s easier for humans to scan
  const severityScore =
    (external ? 0.4 : 0) +
    (sqlErr ? 0.4 : 0) +
    (xssReflected ? 0.4 : 0) +
    Math.min(0.5, confidence / 2);

  let severity = "low";
  if (severityScore >= 0.8) severity = "high";
  else if (severityScore >= 0.5) severity = "med";

  return {
    method,
    url,
    param,
    confidence,
    payload,
    family: fam,
    severity,
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

/** Small UI bits */
const Badge = ({ children, tone = "default", title }) => {
  const map = {
    default: "bg-gray-100 text-gray-900",
    blue: "bg-blue-100 text-blue-900",
    pink: "bg-pink-100 text-pink-900",
    purple: "bg-purple-100 text-purple-900",
    green: "bg-green-100 text-green-900",
    amber: "bg-amber-100 text-amber-900",
    red: "bg-red-100 text-red-900",
  };
  return (
    <span className={cn("px-2 py-0.5 rounded text-xs", map[tone] || map.default)} title={title}>
      {children}
    </span>
  );
};

const ConfBadge = ({ v }) => (
  <span
    className={cn(
      "px-2 py-0.5 rounded text-xs font-mono",
      v >= 0.8 ? "bg-green-600 text-white" : v >= 0.5 ? "bg-amber-500 text-white" : "bg-gray-300 text-gray-900"
    )}
    title={`confidence ${Number(v || 0).toFixed(2)}`}
  >
    {Number(v || 0).toFixed(2)}
  </span>
);

const FamilyBadge = ({ fam }) => (
  <Badge tone={fam === "redirect" ? "purple" : fam === "xss" ? "pink" : "blue"}>
    {fam || "—"}
  </Badge>
);

const SeverityBadge = ({ sev }) => {
  const map = { high: ["red", "High"], med: ["amber", "Medium"], low: ["green", "Low"] };
  const [tone, label] = map[sev] || map.low;
  return <Badge tone={tone}>{label}</Badge>;
};

const DeltaCell = ({ d }) => {
  if (!d) return <span className="text-gray-400">—</span>;
  const bits = [];
  if (d.status_changed) bits.push("status");
  if (typeof d.len_delta === "number") bits.push(`Δlen ${d.len_delta}`);
  if (typeof d.ms_delta === "number") bits.push(`Δms ${d.ms_delta}`);
  if (typeof d.len_ratio === "number" && isFinite(d.len_ratio)) bits.push(`×${Number(d.len_ratio).toFixed(2)}`);
  return bits.length ? <span>{bits.join(" · ")}</span> : <span className="text-gray-400">—</span>;
};

const RedirectBits = ({ row }) => {
  const ext = row?.signals?.external_redirect;
  const loc = row?.signals?.location;
  const host = row?.signals?.location_host;
  if (!ext && !loc) return <span className="text-gray-400">—</span>;
  return (
    <span className="inline-flex items-center gap-2">
      {ext ? <Badge tone="purple">external</Badge> : null}
      {host ? <Badge tone="purple">{host}</Badge> : null}
      {loc ? <code className="text-xs break-all">{loc}</code> : null}
    </span>
  );
};

const SqlBits = ({ row }) => {
  const s = row?.signals || {};
  if (s.sql_error) return <Badge tone="blue">sql error</Badge>;
  const ms = row?.delta?.ms_delta;
  const len = row?.delta?.len_delta;
  if (typeof ms === "number" && ms >= 1500) return <Badge tone="blue">timing Δ{ms}ms</Badge>;
  if (typeof len === "number" && Math.abs(len) >= 200) return <Badge tone="blue">boolean Δlen {len}</Badge>;
  return <span className="text-gray-400">—</span>;
};

const XssBits = ({ row }) => {
  return row?.signals?.xss_reflected ? <Badge tone="pink">reflected</Badge> : <span className="text-gray-400">—</span>;
};

const LoginBits = ({ row }) => {
  const s = row?.signals || {};
  if (s.login_success || s.token_present) {
    return (
      <span className="inline-flex items-center gap-2">
        {s.login_success ? <Badge tone="green">bypass</Badge> : null}
        {s.token_present ? <Badge tone="green">token</Badge> : null}
      </span>
    );
  }
  return <span className="text-gray-400">—</span>;
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
  const [fuzzBearer, setFuzzBearer] = useState("");

  // New UX state
  const [familiesSelected, setFamiliesSelected] = useState(new Set(["sqli", "xss", "redirect"]));
  const [minConf, setMinConf] = useState(0.0);
  const [onlySqlError, setOnlySqlError] = useState(false);
  const [onlyXssRef, setOnlyXssRef] = useState(false);
  const [onlyExtRedir, setOnlyExtRedir] = useState(false);
  const [onlyWithDelta, setOnlyWithDelta] = useState(false);
  const [sortBy, setSortBy] = useState("conf_desc"); // conf_desc | sev_conf | len_abs | url_asc
  const [expanded, setExpanded] = useState(() => new Set()); // row expand toggles

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

  /** Filtering of endpoints list */
  const filtered = useMemo(() => {
    const q = filter.toLowerCase().trim();
    return endpoints.filter((ep) => {
      if (!familiesSelected.has(ep._family)) return false;
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
  }, [endpoints, filter, familiesSelected]);

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
        .map(({ method, url, _all_params = [], params = [], body_keys = [] }) => ({
          method,
          url,
          // Backend trims across all locations; provide best union.
          params: isNonEmptyArray(_all_params) ? _all_params : [...new Set([...(params || []), ...(body_keys || [])])],
        }));

      // Pre-send inference: if params empty, try to infer from URL again
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

      const allEmpty = selection.every((s) => !isNonEmptyArray(s.params));
      if (allEmpty) {
        toast.warn("Selected endpoints have no parameters to fuzz.");
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

  // === New: filtered + sorted results for user-friendly review ===
  const filteredResults = useMemo(() => {
    const fams = familiesSelected;
    const out = results.filter((r) => {
      if (r.confidence < minConf) return false;
      if (!fams.has(r.family || "sqli")) return false;
      if (onlySqlError && !r.signals.sql_error) return false;
      if (onlyXssRef && !r.signals.xss_reflected) return false;
      if (onlyExtRedir && !r.signals.external_redirect) return false;
      if (onlyWithDelta) {
        const d = r.delta || {};
        const hasDelta =
          d.status_changed ||
          (typeof d.len_delta === "number" && d.len_delta !== 0) ||
          (typeof d.ms_delta === "number" && d.ms_delta !== 0);
        if (!hasDelta) return false;
      }
      return true;
    });

    const byLenAbs = (r) => Math.abs(r?.delta?.len_delta || 0);
    const bySev = (r) => (r.severity === "high" ? 2 : r.severity === "med" ? 1 : 0);

    out.sort((a, b) => {
      if (sortBy === "len_abs") return byLenAbs(b) - byLenAbs(a) || (b.confidence - a.confidence);
      if (sortBy === "url_asc") return String(a.url).localeCompare(String(b.url)) || (b.confidence - a.confidence);
      if (sortBy === "sev_conf") return bySev(b) - bySev(a) || (b.confidence - a.confidence);
      // default conf_desc
      return b.confidence - a.confidence || byLenAbs(b) - byLenAbs(a);
    });

    return out;
  }, [results, familiesSelected, minConf, onlySqlError, onlyXssRef, onlyExtRedir, onlyWithDelta, sortBy]);

  // Summary tiles
  const summary = useMemo(() => {
    const total = results.length;
    const famCounts = { sqli: 0, xss: 0, redirect: 0 };
    const signals = { sql: 0, xss: 0, redir: 0 };
    let hi = 0;
    for (const r of results) {
      const fam = r.family || "sqli";
      if (fam in famCounts) famCounts[fam]++;
      if (r.signals.sql_error) signals.sql++;
      if (r.signals.xss_reflected) signals.xss++;
      if (r.signals.external_redirect) signals.redir++;
      if (r.confidence >= 0.8) hi++;
    }
    return { total, famCounts, signals, hi };
  }, [results]);

  // Export helpers
  const copyJson = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(filteredResults, null, 2));
      toast.success("Copied filtered results JSON");
    } catch {
      toast.error("Copy failed");
    }
  };
  const downloadCsv = () => {
    const rows = [
      ["method", "url", "param", "family", "severity", "confidence", "status_changed", "len_delta", "ms_delta", "sql_error", "xss_reflected", "external_redirect", "location", "payload"],
      ...filteredResults.map((r) => [
        r.method,
        r.url,
        r.param,
        r.family || "",
        r.severity || "",
        r.confidence,
        r?.delta?.status_changed ? "1" : "0",
        r?.delta?.len_delta ?? "",
        r?.delta?.ms_delta ?? "",
        r.signals.sql_error ? "1" : "0",
        r.signals.xss_reflected ? "1" : "0",
        r.signals.external_redirect ? "1" : "0",
        r.signals.location || "",
        (r.payload || "").replace(/\n/g, "\\n"),
      ]),
    ];
    const csv = rows.map((row) =>
      row
        .map((cell) => {
          const s = String(cell ?? "");
          return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        })
        .join(",")
    ).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fuzz_results_filtered.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  // UI toggles
  const toggleFamily = (fam) => {
    const next = new Set(familiesSelected);
    if (next.has(fam)) next.delete(fam);
    else next.add(fam);
    if (next.size === 0) {
      // prevent all-off
      toast.warn("At least one family should be selected");
      return;
    }
    setFamiliesSelected(next);
  };

  const toggleExpand = (key) => {
    const next = new Set(expanded);
    next.has(key) ? next.delete(key) : next.add(key);
    setExpanded(next);
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
          {/* Family filters */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-gray-500">Family:</label>
            <button
              className={cn("px-2 py-1 rounded text-xs border", familiesSelected.has("sqli") ? "bg-blue-50 border-blue-200" : "bg-white")}
              onClick={() => toggleFamily("sqli")}
              title="Toggle SQLi rows"
            >
              SQLi
            </button>
            <button
              className={cn("px-2 py-1 rounded text-xs border", familiesSelected.has("xss") ? "bg-pink-50 border-pink-200" : "bg-white")}
              onClick={() => toggleFamily("xss")}
              title="Toggle XSS rows"
            >
              XSS
            </button>
            <button
              className={cn("px-2 py-1 rounded text-xs border", familiesSelected.has("redirect") ? "bg-purple-50 border-purple-200" : "bg-white")}
              onClick={() => toggleFamily("redirect")}
              title="Toggle Redirect rows"
            >
              Redirect
            </button>
          </div>

          {/* Confidence slider */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-gray-500">Min conf:</label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={minConf}
              onChange={(e) => setMinConf(Number(e.target.value))}
              className="w-28"
            />
            <span className="text-xs font-mono">{minConf.toFixed(2)}</span>
          </div>

          {/* Signal toggles */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-gray-500">Signals:</label>
            <label className="text-xs flex items-center gap-1">
              <input type="checkbox" checked={onlySqlError} onChange={(e) => setOnlySqlError(e.target.checked)} /> SQL err
            </label>
            <label className="text-xs flex items-center gap-1">
              <input type="checkbox" checked={onlyXssRef} onChange={(e) => setOnlyXssRef(e.target.checked)} /> XSS refl
            </label>
            <label className="text-xs flex items-center gap-1">
              <input type="checkbox" checked={onlyExtRedir} onChange={(e) => setOnlyExtRedir(e.target.checked)} /> Ext redir
            </label>
            <label className="text-xs flex items-center gap-1">
              <input type="checkbox" checked={onlyWithDelta} onChange={(e) => setOnlyWithDelta(e.target.checked)} /> Has Δ
            </label>
          </div>

          {/* Sort */}
          <select
            className="border p-2 rounded text-sm"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            title="Sort results"
          >
            <option value="conf_desc">Sort: Confidence ↓</option>
            <option value="sev_conf">Sort: Severity → Confidence</option>
            <option value="len_abs">Sort: |Δlen| ↓</option>
            <option value="url_asc">Sort: URL ↑</option>
          </select>

          {/* Free-text filter */}
          <input
            className="border p-2 rounded min-w-[220px]"
            placeholder="Filter (method, path, params)"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />

          {/* Export */}
          <button className="border px-3 py-2 rounded" onClick={copyJson} title="Copy filtered JSON">
            Copy JSON
          </button>
          <button className="border px-3 py-2 rounded" onClick={downloadCsv} title="Download filtered CSV">
            CSV
          </button>
        </div>
      </div>

      {/* Endpoint selection list */}
      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Endpoints</h2>
          <div className="flex items-center gap-2">
            <button className="border px-3 py-1.5 rounded" onClick={selectAllVisible}>
              Select all (visible)
            </button>
            <button
              className="border px-3 py-1.5 rounded"
              onClick={() => selectTopNVisible(20)}
              title="Select top 20 visible by priority"
            >
              Select top 20
            </button>
            <button className="border px-3 py-1.5 rounded" onClick={() => selectFamilyVisible("redirect")}>
              Select redirects
            </button>
            <button className="border px-3 py-1.5 rounded" onClick={() => selectFamilyVisible("xss")}>
              Select XSS
            </button>
            <button className="border px-3 py-1.5 rounded" onClick={() => selectFamilyVisible("sqli")}>
              Select SQLi
            </button>
            <button className="border px-3 py-1.5 rounded" onClick={clearSelection}>
              Clear
            </button>
          </div>
        </div>

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
                      <a href={ep.url} target="_blank" rel="noreferrer" className="font-mono text-sm break-all underline decoration-dotted">
                        {ep.url}
                      </a>
                      <span className="ml-auto flex items-center gap-2">
                        <span className="text-xs text-gray-500">prio:</span>
                        <span className="text-xs font-mono">{(ep._priority || 0).toFixed(2)}</span>
                        <FamilyBadge fam={ep._family} />
                      </span>
                    </div>
                    {isNonEmptyArray(ep.params) ? (
                      <div className="text-xs text-gray-600">query: {ep.params.join(", ")}</div>
                    ) : null}
                    {isNonEmptyArray(ep._form_params) ? (
                      <div className="text-xs text-gray-600">form: {ep._form_params.join(", ")}</div>
                    ) : null}
                    {isNonEmptyArray(ep._json_params) ? (
                      <div className="text-xs text-gray-600">json: {ep._json_params.join(", ")}</div>
                    ) : null}
                    {isNonEmptyArray(ep.body_keys) && !(isNonEmptyArray(ep._form_params) || isNonEmptyArray(ep._json_params)) ? (
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

      {/* Results summary strip */}
      {results.length > 0 && (
        <section className="space-y-2">
          <div className="grid grid-cols-5 gap-3">
            <div className="border rounded p-3">
              <div className="text-gray-500">Results (total)</div>
              <div className="text-xl font-semibold">{summary.total}</div>
            </div>
            <div className="border rounded p-3">
              <div className="flex items-center justify-between text-gray-500">
                <span>By family</span>
              </div>
              <div className="mt-1 text-sm flex gap-2 flex-wrap">
                <Badge tone="blue">SQLi: {summary.famCounts.sqli}</Badge>
                <Badge tone="pink">XSS: {summary.famCounts.xss}</Badge>
                <Badge tone="purple">Redirect: {summary.famCounts.redirect}</Badge>
              </div>
            </div>
            <div className="border rounded p-3">
              <div className="text-gray-500">Signals</div>
              <div className="mt-1 text-sm flex gap-2 flex-wrap">
                <Badge tone="blue" title="Server error contains SQL error text">SQL err: {summary.signals.sql}</Badge>
                <Badge tone="pink">XSS refl: {summary.signals.xss}</Badge>
                <Badge tone="purple">Ext redir: {summary.signals.redir}</Badge>
              </div>
            </div>
            <div className="border rounded p-3">
              <div className="text-gray-500">High confidence (≥0.8)</div>
              <div className="text-xl font-semibold">{summary.hi}</div>
            </div>
            <div className="border rounded p-3">
              <div className="text-gray-500">Visible after filters</div>
              <div className="text-xl font-semibold">{filteredResults.length}</div>
            </div>
          </div>
        </section>
      )}

      {/* Fuzz summary */}
      {results.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-lg font-semibold">Fuzz Results</h2>
          <div className="overflow-auto border rounded">
            <table className="min-w-full text-sm">
              <thead className="bg-gray-50 sticky top-0 z-10">
                <tr className="text-left">
                  <th className="p-2">Severity</th>
                  <th className="p-2">Conf</th>
                  <th className="p-2">Family</th>
                  <th className="p-2">Method</th>
                  <th className="p-2">URL</th>
                  <th className="p-2">Param</th>
                  <th className="p-2">Δ</th>
                  <th className="p-2">SQLi</th>
                  <th className="p-2">XSS</th>
                  <th className="p-2">Redirect</th>
                  <th className="p-2">Payload</th>
                  <th className="p-2"></th>
                </tr>
              </thead>
              <tbody>
                {filteredResults.map((row, i) => {
                  const key = `${row.method}-${row.url}-${row.param}-${i}`;
                  const isOpen = expanded.has(key);
                  return (
                    <tr key={key} className="border-t align-top hover:bg-gray-50">
                      <td className="p-2"><SeverityBadge sev={row.severity} /></td>
                      <td className="p-2"><ConfBadge v={Number(row.confidence || 0)} /></td>
                      <td className="p-2"><FamilyBadge fam={row.family || "sqli"} /></td>
                      <td className="p-2 font-mono">{row.method}</td>
                      <td className="p-2 font-mono break-all">
                        <a href={row.url} target="_blank" rel="noreferrer" className="underline decoration-dotted">
                          {row.url}
                        </a>
                      </td>
                      <td className="p-2 font-mono">{row.param}</td>
                      <td className="p-2"><DeltaCell d={row.delta} /></td>
                      <td className="p-2"><SqlBits row={row} /></td>
                      <td className="p-2"><XssBits row={row} /></td>
                      <td className="p-2"><RedirectBits row={row} /></td>
                      <td className="p-2">
                        <code className="text-xs break-all">{row.payload || ""}</code>
                      </td>
                      <td className="p-2">
                        <button
                          className="text-xs border px-2 py-1 rounded"
                          onClick={() => toggleExpand(key)}
                          aria-expanded={isOpen}
                        >
                          {isOpen ? "Hide" : "Details"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {filteredResults.length === 0 && (
              <div className="p-4 text-sm text-gray-500">No results match the current filters.</div>
            )}
          </div>

          {/* Expanded rows below the table for readability on narrow screens */}
          <div className="space-y-2">
            {filteredResults.map((row, i) => {
              const key = `${row.method}-${row.url}-${row.param}-${i}`;
              if (!expanded.has(key)) return null;
              const v = row.signals?.verify || {};
              return (
                <div key={`detail-${key}`} className="border rounded p-3 bg-white">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="text-sm">
                        <SeverityBadge sev={row.severity} /> <FamilyBadge fam={row.family || "sqli"} />{" "}
                        <ConfBadge v={row.confidence} />
                      </div>
                      <div className="text-sm font-mono">
                        {row.method} {row.url}
                      </div>
                      <div className="text-xs text-gray-600">param: <code>{row.param}</code></div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        className="text-xs border px-2 py-1 rounded"
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(row.payload || "");
                            toast.success("Payload copied");
                          } catch {
                            toast.error("Copy failed");
                          }
                        }}
                      >
                        Copy payload
                      </button>
                      <button
                        className="text-xs border px-2 py-1 rounded"
                        onClick={() => {
                          const a = document.createElement("a");
                          const blob = new Blob([JSON.stringify(row, null, 2)], { type: "application/json" });
                          const url = URL.createObjectURL(blob);
                          a.href = url;
                          a.download = "fuzz_row.json";
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                      >
                        Save row
                      </button>
                      <button className="text-xs border px-2 py-1 rounded" onClick={() => toggleExpand(key)}>
                        Close
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
                    <div className="border rounded p-2">
                      <div className="text-xs text-gray-500 mb-1">Delta</div>
                      <div className="text-sm"><DeltaCell d={row.delta} /></div>
                    </div>
                    <div className="border rounded p-2">
                      <div className="text-xs text-gray-500 mb-1">Verify</div>
                      <div className="text-xs space-y-1 font-mono">
                        {"status" in v ? <div>status: {v.status}</div> : null}
                        {"length" in v ? <div>length: {v.length}</div> : null}
                        {"location" in v ? <div>location: <span className="break-all">{v.location}</span></div> : null}
                      </div>
                    </div>
                    <div className="border rounded p-2">
                      <div className="text-xs text-gray-500 mb-1">Signals</div>
                      <div className="text-xs space-x-2">
                        {row.signals.sql_error ? <Badge tone="blue">sql error</Badge> : null}
                        {row.signals.xss_reflected ? <Badge tone="pink">xss reflected</Badge> : null}
                        {row.signals.external_redirect ? <Badge tone="purple">external redirect</Badge> : null}
                        {row.signals.login_success ? <Badge tone="green">login bypass</Badge> : null}
                        {row.signals.token_present ? <Badge tone="green">token present</Badge> : null}
                      </div>
                    </div>
                  </div>

                  <div className="mt-3">
                    <div className="text-xs text-gray-500 mb-1">Payload</div>
                    <pre className="text-xs bg-gray-50 p-2 rounded overflow-auto">
                      {row.payload || ""}
                    </pre>
                  </div>
                </div>
              );
            })}
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
