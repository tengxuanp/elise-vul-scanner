// frontend/src/app/pages/CrawlAndFuzzPage.jsx
"use client";
import { useState, useMemo, useEffect } from "react";
import CrawlForm from "../components/CrawlForm";
import {
  fuzzByJob,
  fuzzSelected,
  getReport,
  getReportMarkdown,
  getCategorizedEndpoints,
} from "../api/api";
import { toast } from "react-toastify";

/** === helpers === */
const isNonEmptyArray = (v) => Array.isArray(v) && v.length > 0;
const isNonEmptyObj = (o) => !!o && typeof o === "object" && Object.keys(o).length > 0;
const hasNum = (v) => typeof v === "number" && isFinite(v);
const cn = (...xs) => xs.filter(Boolean).join(" ");

/** Stable key per result row (independent of pagination/order) */
const rowKey = (row) => {
  const p = typeof row.payload === "string" ? row.payload.slice(0, 64) : "";
  return `${row.method}|${row.url}|${row.param}|${p}`;
};

/** Consider more ML path spellings; explicitly exclude heuristic/none */
const isMLUsedPath = (usedPath = "") => {
  const parts = Array.isArray(usedPath) ? usedPath : [usedPath];
  const s = parts.map((x) => String(x || "").toLowerCase()).join("|");
  if (!s) return false;
  if (/\b(heuristic|none)\b/.test(s)) return false;
  // Check for ml:family patterns (e.g., ml:sqli, ml:xss)
  if (/ml:[a-z]+/.test(s)) return true;
  return /(family[-_ ]?ranker|family[-_ ]?router|ml[-_ ]?ranker|ml[-_ ]?router|generic[-_ ]?ranker|plugin|ranker|router)/.test(s);
};

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

  // Infer query keys from URL
  let qFromUrl = [];
  try {
    const u = new URL(url, typeof window !== "undefined" ? window.location.origin : "http://localhost");
    qFromUrl = Array.from(new Set([...u.searchParams.keys()])).filter(Boolean);
  } catch {}

  // param_locs can be strings or {name:"…"}
  const qParamLocs = namesFrom(pl.query);
  const formParamLocs = namesFrom(pl.form);
  const jsonParamLocs = namesFrom(pl.json);

  // Legacy fallbacks
  const legacyQuery = isNonEmptyArray(ep.query_keys) ? ep.query_keys : isNonEmptyArray(ep.params) ? ep.params : [];
  const legacyBody = isNonEmptyArray(ep.body_keys)
    ? ep.body_keys
    : ep.body_parsed && typeof ep.body_parsed === "object"
    ? Object.keys(ep.body_parsed)
    : [];

  // Prefer new schema; then legacy; then URL inference
  const queryParams = isNonEmptyArray(qParamLocs) ? qParamLocs : isNonEmptyArray(legacyQuery) ? legacyQuery : qFromUrl;

  // Body params = form ∪ json (new schema) else legacy body hints
  const formParams = formParamLocs;
  const jsonParams = jsonParamLocs;
  const bodyParams =
    isNonEmptyArray(formParams) || isNonEmptyArray(jsonParams)
      ? [...new Set([...(formParams || []), ...(jsonParams || [])])]
      : legacyBody;

  // For selection, the backend trims across all locations → union
  const allParams = [...new Set([...(queryParams || []), ...(bodyParams || [])])];

  return {
    ...ep,
    method,
    url,
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
  const pset = new Set((ep._all_params || ep.params || []).map((s) => String(s).toLowerCase()));
  const path = (ep.url || "").toLowerCase();

  if (
    ["to", "return_to", "redirect", "url", "next", "callback", "continue"].some((p) => pset.has(p)) ||
    path.includes("redirect")
  ) return "redirect";

  if (["q", "query", "search"].some((p) => pset.has(p))) {
    return path.includes("/api/") || path.includes("/rest/") ? "sqli" : "xss";
  }

  if (["comment", "message", "content", "text", "title", "name"].some((p) => pset.has(p))) return "xss";

  return "sqli";
};

/** Infer family from signals if available (preferred over path/param guess) */
const familyFromSignals = (sig) => {
  const s = sig || {};
  const redir = s.open_redirect || {};
  const refl = s.reflection || {};
  if (s.open_redirect === true || redir.open_redirect === true || s.external_redirect === true) return "redirect";
  if (refl.raw || refl.js_context) return "xss";
  if (s.sql_error === true || s.type === "sqli") return "sqli";
  if ((s.login || {}).login_success) return "sqli";
  if (typeof s.type === "string" && ["redirect", "xss", "sqli"].includes(s.type)) return s.type;
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
        "id","uid","pid","productid","user","q","search","query","to","return_to","redirect","url",
      ].includes(p)
    )
  ) s += 0.6;
  if (/(^|\/)(login|auth|admin|search|redirect|report|download)(\/|$)/.test(url)) s += 0.2;
  if ((ep.method || "GET").toUpperCase() === "GET") s += 0.1;
  return Math.min(1, s);
};

/** Robust origin derivation across different backends/result shapes */
function deriveOrigin(one = {}) {
  // Prefer explicit used_path from backend if present
  const usedPath =
    one?.ranker_meta?.used_path ||
    one?.ranker_meta?.ranker?.used_path ||
    one?.ml?.used_path ||
    one?.used_path ||
    null;
  if (usedPath) {
    if (isMLUsedPath(usedPath)) return "ml";
    if (String(usedPath).toLowerCase() === "heuristic" || String(usedPath).toLowerCase() === "none") return "curated";
  }

  // Simple flags
  if (one.is_ml === true || one.ml === true || one?.payload?.ml === true) return "ml";

  // Nested ML object hints
  if (one && typeof one === "object" && one.ml && typeof one.ml === "object") {
    const s = String(one.ml.source || one.ml.origin || one.ml.provenance || "").trim().toLowerCase();
    if (/(^|[^a-z])ml([^a-z]|$)/.test(s) || /(ranker|model|ai)/.test(s)) return "ml";
    if (one.ml.enabled === true || hasNum(one.ml.p) || hasNum(one.ml.score)) return "ml";
    if (isNonEmptyObj(one.ml.ranker_meta || one.ml.ranker)) return "ml";
  }

  // Explicit string-ish fields if present
  const candidates = [
    one.payload_origin,one.payloadOrigin,one.payload_source,one.payloadSource,
    one.ranker_origin,one.origin,one.source,one.provenance,one.generator,one.kind,one.payload_kind,
    one?.meta?.origin,one?.meta?.source,one?.payload_meta?.origin,one?.payload_meta?.source,
    one?.payload?.origin,one?.payload?.source,
  ].map((v) => (v == null ? "" : String(v).trim().toLowerCase())).filter(Boolean);

  for (const v of candidates) {
    if (/(^|[^a-z])ml([^a-z]|$)/.test(v) || /(ranker|model|ai)/.test(v)) return "ml";
    if (/(curated|manual|baseline|core|hand|seed)/.test(v)) return "curated";
  }

  // Heuristics: presence of ranker metadata implies ML
  const rm =
    one.ranker_meta ||
    one.ranker ||
    one.ml_meta ||
    (one.ml && (one.ml.ranker_meta || one.ml.ranker)) ||
    {};
  const probs =
    rm.family_probs ||
    rm.probs ||
    rm.family_probabilities ||
    rm.probabilities;

  // NEW: treat array **or object** model_ids as ML
  const hasModelIds =
    !!rm.model_ids &&
    ((Array.isArray(rm.model_ids) && rm.model_ids.length > 0) ||
     (rm.model_ids && typeof rm.model_ids === "object" && Object.keys(rm.model_ids).length > 0));

  if (
    (isNonEmptyObj(rm) &&
      (hasNum(rm.ranker_score) || isNonEmptyObj(probs) || hasModelIds)) ||
    hasNum(one.ranker_score) ||
    isNonEmptyObj(one.ranker_probs) ||
    isNonEmptyObj(one.ml_probs)
  ) {
    return "ml";
  }

  // Payload id prefix sometimes encodes provenance
  if (typeof one.payload_id === "string" && /^ml[-_]/i.test(one.payload_id)) return "ml";

  // Default: assume curated
  return "curated";
}

/** Gather probabilities from many possible shapes */
function extractFamilyProbs(container = {}) {
  const tryObjs = [
    container.family_probs,
    container.probs,
    container.family_probabilities,
    container.probabilities,
    container.per_family,
    container.perFamily,
  ].filter(isNonEmptyObj);
  for (const obj of tryObjs) return obj;

  // Root-level variants
  const rootKeys = ["family_probs", "probs", "family_probabilities", "probabilities", "ranker_probs", "ml_probs"];
  for (const k of rootKeys) if (isNonEmptyObj(container[k])) return container[k];

  // Flat shapes like {prob_sqli: 0.8, prob_xss: 0.1, prob_redirect: 0.1}
  const flat = {};
  for (const [k, v] of Object.entries(container)) {
    if (!hasNum(Number(v))) continue;
    const m = String(k).toLowerCase();
    if (m.includes("sqli")) flat.sqli = Number(v);
    if (m.includes("xss")) flat.xss = Number(v);
    if (m.includes("redir")) flat.redirect = Number(v);
  }
  if (Object.keys(flat).length) return flat;

  return {};
}

/** If there is no ML meta, synthesize a useful fallback for the Ranker column */
function synthesizeRankerMetaFromSignals(signals = {}, famGuess = null, confidence = 0) {
  const strong = {
    sqli: (signals.sql_error || signals.boolean_sqli || signals.time_sqli) ? 1 : 0,
    xss: signals.xss_reflected ? 1 : 0,
    redirect: signals.external_redirect ? 1 : 0,
  };
  const anyStrong = strong.sqli || strong.xss || strong.redirect;
  if (!anyStrong && !famGuess) return null;

  // Start with weak prior, bump the detected ones
  let sqli = 0.2, xss = 0.2, redirect = 0.2;
  if (anyStrong) {
    if (strong.sqli) sqli += 0.6;
    if (strong.xss) xss += 0.6;
    if (strong.redirect) redirect += 0.6;
  } else if (famGuess) {
    if (famGuess === "sqli") sqli += Math.max(0.2, Math.min(0.7, confidence));
    if (famGuess === "xss") sqli += 0;
    if (famGuess === "xss") xss += Math.max(0.2, Math.min(0.7, confidence));
    if (famGuess === "redirect") redirect += Math.max(0.2, Math.min(0.7, confidence));
  }

  const sum = sqli + xss + redirect || 1;
  const probs = { sqli: sqli / sum, xss: xss / sum, redirect: redirect / sum };
  const chosen = Object.entries(probs).sort((a, b) => b[1] - a[1])[0][0];

  return {
    family_probs: probs,
    family_chosen: chosen,
    ranker_score: anyStrong ? 0.95 : Math.max(0.5, confidence || 0.5),
    model_ids: null,
    _synthetic: true,
  };
}

/** Extract feature dimensionality if present (avoid showing bogus "dim 0") */
function extractFeatureDim(container = {}) {
  const cands = [
    container.feature_dim_total,
    container.ranker_feature_dim_total,
    container.dim_total,
    container.total_dim,
    container.feat_dim,
    container?.ranker?.feature_dim_total,
    container?.ranker?.dim_total,
    container?.ml?.feature_dim_total,
  ].filter((x) => hasNum(x) && x > 0);
  return cands.length ? cands[0] : null;
}

/** Normalize ranker meta into a consistent shape */
function normalizeRankerMeta(mRaw = {}, oneRowRaw = {}, synthHints = null) {
  const fm = mRaw || {};
  const row = oneRowRaw || {};

  // search across many likely containers, INCLUDING the original row
  const containers = [
    fm,
    fm.ranker_meta,
    fm.ranker,
    fm.ml_meta,
    fm.meta,
    row.ranker_meta,
    row.ranker,
    row.ml_meta,
    row.meta,
    row.ml,
    row,
  ].filter((c) => c && typeof c === "object");

  let family_probs = {};
  let family_chosen = null;
  let ranker_score = null;
  let model_ids = null;
  let feature_dim_total = null;

  for (const c of containers) {
    // family probs under many names
    if (!isNonEmptyObj(family_probs)) {
      const cand =
        c.family_probs ||
        c.probs ||
        c.family_probabilities ||
        c.probabilities ||
        c.per_family ||
        c.perFamily ||
        null;
      if (isNonEmptyObj(cand)) family_probs = cand;
    }

    if (!family_chosen) family_chosen = c.family_chosen || c.family || c.chosen_family || c.chosen;

    if (!hasNum(ranker_score)) {
      ranker_score = hasNum(c.ranker_score) ? c.ranker_score : (hasNum(c.score) ? c.score : null);
    }

    // accept arrays, objects, or strings for model identifiers
    if (!model_ids) {
      const mid = c.model_ids || c.models || c.model_id || c.model || c.model_name || null;
      if (
        (Array.isArray(mid) && mid.length > 0) ||
        (mid && typeof mid === "object" && Object.keys(mid).length > 0) ||
        (typeof mid === "string" && mid.trim())
      ) {
        model_ids = mid;
      }
    }

    if (!hasNum(feature_dim_total)) {
      const dims =
        c.feature_dim_total ??
        c.ranker_feature_dim_total ??
        c.dim_total ??
        c.total_dim ??
        c.feat_dim ??
        (c.ranker && c.ranker.feature_dim_total) ??
        (c.ranker && c.ranker.dim_total) ??
        (c.ml && c.ml.feature_dim_total);
      if (hasNum(dims) && dims > 0) feature_dim_total = dims;
    }
  }

  // normalize probs to {sqli,xss,redirect} and 0..1
  const picked = {};
  for (const [k, v] of Object.entries(family_probs || {})) {
    const key = String(k).toLowerCase();
    if (["sqli", "xss", "redirect"].includes(key)) picked[key] = Number(v) || 0;
  }
  const sum = Object.values(picked).reduce((a, b) => a + b, 0);
  if (sum > 0) Object.keys(picked).forEach((k) => { picked[k] = picked[k] / sum; });

  const meta = {
    family_probs: picked,
    family_chosen: family_chosen || null,
    ranker_score: hasNum(ranker_score) ? ranker_score : null,
    model_ids: model_ids || null,
    feature_dim_total: hasNum(feature_dim_total) ? feature_dim_total : null,
  };

  // If still empty, synthesize a fallback so the column isn't blank
  const needSynthetic =
    !isNonEmptyObj(meta.family_probs) &&
    !hasNum(meta.ranker_score) &&
    !(meta.model_ids) &&
    !hasNum(meta.feature_dim_total);

  if (needSynthetic) {
    // pull hints (our already-computed signals) if provided
    const h = synthHints || {};
    const synthetic = synthesizeRankerMetaFromSignals(
      h.signals || {},
      h.family || null,
      h.confidence || 0
    );
    if (synthetic) return synthetic;
  }
  return meta;
}


/** ===== UI atoms ===== */
const Badge = ({ children, tone = "default", title }) => {
  const map = {
    default: "bg-gray-100 text-gray-900",
    blue: "bg-blue-100 text-blue-900",
    pink: "bg-pink-100 text-pink-900",
    purple: "bg-purple-100 text-purple-900",
    green: "bg-green-100 text-green-900",
    amber: "bg-amber-100 text-amber-900",
    red: "bg-red-100 text-red-900",
    indigo: "bg-indigo-100 text-indigo-900",
    slate: "bg-slate-200 text-slate-900",
    teal: "bg-teal-100 text-teal-900",
  };
  return (
    <span className={cn("px-2 py-0.5 rounded text-xs whitespace-nowrap", map[tone] || map.default)} title={title}>
      {children}
    </span>
  );
};

// Tailwind-safe tone mapping (no template class names)
const TogglePill = ({ active, onClick, children, toneActive = "indigo" }) => {
  const activeMap = {
    indigo: "bg-indigo-50 border-indigo-200",
    slate: "bg-slate-50 border-slate-200",
    teal: "bg-teal-50 border-teal-200",
    purple: "bg-purple-50 border-purple-200",
    blue: "bg-blue-50 border-blue-200",
    pink: "bg-pink-50 border-pink-200",
    red: "bg-red-50 border-red-200",
    amber: "bg-amber-50 border-amber-200",
    green: "bg-green-50 border-green-200",
  };
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "px-2 py-1 rounded text-xs border transition",
        active ? activeMap[toneActive] || activeMap.indigo : "bg-white hover:bg-gray-50"
      )}
    >
      {children}
    </button>
  );
};

const ConfMeter = ({ v }) => {
  const val = Math.max(0, Math.min(1, Number(v || 0)));
  const pct = Math.round(val * 100);
  const tone = val >= 0.8 ? "bg-green-600" : val >= 0.5 ? "bg-amber-500" : "bg-gray-400";
  return (
    <div className="w-24 h-4 rounded bg-gray-200 overflow-hidden relative" title={`confidence ${val.toFixed(2)}`}>
      <div className={cn("h-full", tone)} style={{ width: `${pct}%` }} />
      <div className="absolute inset-0 text-[10px] leading-4 text-white font-mono text-center">{val.toFixed(2)}</div>
    </div>
  );
};

const FamilyBadge = ({ fam }) => <Badge tone={fam === "redirect" ? "purple" : fam === "xss" ? "pink" : "blue"}>{fam || "—"}</Badge>;

const OriginBadge = ({ origin }) => {
  if (!origin) return <Badge tone="slate">—</Badge>;
  if (origin === "ml") return <Badge tone="indigo" title="Selected by ML ranker">ML</Badge>;
  return <Badge tone="slate" title="Curated/fallback payload">curated</Badge>;
};

const SeverityBadge = ({ sev }) => {
  const map = { high: ["red", "High"], med: ["amber", "Medium"], low: ["green", "Low"] };
  const [tone, label] = map[sev] || map.low;
  return <Badge tone={tone}>{label}</Badge>;
};

const DeltaCell = ({ d }) => {
  if (!d) return <span className="text-gray-400">—</span>;
  const bits = [];
  if (d.status_changed) bits.push("status");
  if (typeof d.len_delta === "number" && d.len_delta !== 0) bits.push(`Δlen ${d.len_delta}`);
  if (typeof d.ms_delta === "number" && d.ms_delta !== 0) bits.push(`Δms ${d.ms_delta}`);
  if (typeof d.len_ratio === "number" && isFinite(d.len_ratio)) bits.push(`×${Number(d.len_ratio).toFixed(2)}`);
  return bits.length ? <span>{bits.join(" · ")}</span> : <span className="text-gray-400">—</span>;
};

const FamilyProbsBar = ({ probs }) => {
  const entries = Object.entries(probs || {}).filter(([, v]) => v > 0);
  if (entries.length === 0) return <span className="text-gray-400">—</span>;
  const total = entries.reduce((a, [, v]) => a + v, 0) || 1;
  const seg = (k, v) => {
    const w = Math.max(4, Math.round((v / total) * 100));
    const tone =
      k === "xss" ? "bg-pink-400" : k === "redirect" ? "bg-purple-400" : k === "sqli" ? "bg-blue-400" : "bg-gray-400";
    return (
      <div key={k} className={cn("h-2", tone)} style={{ width: `${w}%` }} title={`${k}: ${(v * 100).toFixed(1)}%`} />
    );
  };
  return <div className="w-44 h-2 rounded overflow-hidden flex">{entries.sort((a,b)=>b[1]-a[1]).map(([k, v]) => seg(k, v))}</div>;
};

const StatCard = ({ label, value, children }) => (
  <div className="border rounded p-3 bg-white">
    <div className="text-gray-500">{label}</div>
    <div className="text-xl font-semibold">{value}</div>
    {children ? <div className="mt-2">{children}</div> : null}
  </div>
);

const SortHeader = ({ fieldKey, label, current, set }) => {
  const isActive = current.startsWith(fieldKey);
  const dir = isActive && current.endsWith("_asc") ? "asc" : "desc";
  const next = !isActive ? `${fieldKey}_desc` : dir === "desc" ? `${fieldKey}_asc` : `${fieldKey}_desc`;
  return (
    <button
      type="button"
      onClick={() => set(next)}
      className={cn("inline-flex items-center gap-1 hover:underline", isActive ? "text-gray-900" : "text-gray-600")}
      title={`Sort by ${label}`}
    >
      {label} {isActive ? (dir === "asc" ? "↑" : "↓") : ""}
    </button>
  );
};

/** ===== Page ===== */
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
  const [sortBy, setSortBy] = useState("conf_desc");
  const [expanded, setExpanded] = useState(() => new Set());
  const [originFilter, setOriginFilter] = useState("all"); // all | ml | curated
  const [compact, setCompact] = useState(false);
  const [strongOnly, setStrongOnly] = useState(false);

  // Engine selector (auto uses ML+curated on backend)
  const [engineMode, setEngineMode] = useState("auto"); // "auto" | "core" | "ffuf"

  // Extra filters / view / pagination
  const [methodFilter, setMethodFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [viewMode, setViewMode] = useState("table");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  // internal guard so we only try categorized-endpoints once per crawl
  const [triedCategorized, setTriedCategorized] = useState(false);

  // reset pagination when filters/sorts change
  useEffect(() => { setPage(1); }, [
    familiesSelected, originFilter, minConf, onlySqlError, onlyXssRef, onlyExtRedir,
    onlyWithDelta, strongOnly, filter, methodFilter, severityFilter, sortBy
  ]);

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
      const hay = [ep.method || "", ep.url || "", ...(ep.params || []), ...(ep.body_keys || [])]
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

  /** Helper: pluck the first present array by key path */
  const pickArray = (obj, keys) => {
    for (const k of keys) {
      const v = k.split(".").reduce((acc, part) => (acc && acc[part] !== undefined ? acc[part] : undefined), obj);
      if (Array.isArray(v)) return v;
    }
    return [];
  };

  /** Crawl results in (robust to multiple shapes from backend) */
  const onResults = (payload = {}) => {
    // Accept several possible shapes from various backends
    const job_id = payload.job_id || payload.job || null;
    const target_url = payload.target_url || payload.target || payload.url || "";

    // endpoints can live in many places depending on the backend
    const endpointsCandidates = pickArray(payload, [
      "endpoints",
      "result.endpoints",
      "items",
      "data.endpoints",
      "distinct_endpoints",
      "unique_endpoints",
      "payload.endpoints",
    ]);

    // captured requests also vary in naming
    const capturedCandidates = pickArray(payload, [
      "captured_requests",
      "captures",
      "requests",
      "result.captured_requests",
      "data.captured_requests",
      "payload.captured_requests",
      "replayed_requests",
    ]);

    setJobId(job_id);
    setTargetUrl(target_url);
    setEndpointsRaw(Array.isArray(endpointsCandidates) ? endpointsCandidates : []);
    setCaptured(Array.isArray(capturedCandidates) ? capturedCandidates : []);
    setSelectedKeys(new Set());
    setFuzzSummary(null);
    setTriedCategorized(false); // allow the categorized fallback once for this new payload
  };

  // Fallback: if we have a target URL but no endpoints in the crawl payload, try categorized endpoints
  useEffect(() => {
    const needFallback = targetUrl && (!isNonEmptyArray(endpointsRaw)) && !triedCategorized;
    if (!needFallback) return;
    (async () => {
      try {
        setTriedCategorized(true);
        const cats = await getCategorizedEndpoints(targetUrl);
        const arr =
          Array.isArray(cats) ? cats
          : Array.isArray(cats?.endpoints) ? cats.endpoints
          : Array.isArray(cats?.items) ? cats.items
          : [];
        if (arr.length) {
          setEndpointsRaw(arr);
          toast.info(`Loaded ${arr.length} endpoints from categorized-endpoints fallback`);
        }
      } catch (e) {
        // quiet fallback; users might not have this route
        console.warn("categorized-endpoints fallback failed", e);
      }
    })();
  }, [targetUrl, endpointsRaw, triedCategorized]);

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

  /** Actions — allow engine selection (auto|ml|core) */
  const mkFuzzOpts = () => {
    const opts = { bearer_token: fuzzBearer || undefined };
    if (engineMode !== "auto") opts.engine = engineMode;
    return opts;
  };

  const onFuzzAll = async () => {
    if (!jobId) return toast.error("No job. Crawl first.");
    setLoadingFuzz(true);
    try {
      const data = await fuzzByJob(jobId, mkFuzzOpts());
      setFuzzSummary(data);
      toast.success(`Fuzzed all endpoints (${engineMode === "core" ? "ML" : engineMode})`);
    } catch (e) {
      console.error(e);
      toast.error("Fuzz ALL failed");
    } finally {
      setLoadingFuzz(false);
    }
  };

  const onFuzzSelected = async () => {
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
          params: isNonEmptyArray(_all_params) ? _all_params : [...new Set([...(params || []), ...(body_keys || [])])],
        }));

      const selection = baseSelection.map((item) => {
        let params = item.params || [];
        if (!isNonEmptyArray(params) && item.url && item.url.includes("?")) {
          try {
            const u = new URL(item.url, typeof window !== "undefined" ? window.location.origin : "http://localhost");
            params = Array.from(new Set([...u.searchParams.keys()])).filter(Boolean);
          } catch {}
        }
        return { ...item, params };
      });

      const allEmpty = selection.every((s) => !isNonEmptyArray(s.params));
      if (allEmpty) toast.warn("Selected endpoints have no parameters to fuzz.");

      const data = await fuzzSelected(jobId, selection, mkFuzzOpts());
      setFuzzSummary(data);
      toast.success(`Fuzzed ${selection.length} selected endpoint(s) (${engineMode === "core" ? "ML" : engineMode})`);
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
      let blob = null;
      let filename = "";

      // Prefer Markdown endpoint if available
      try {
        const md = await getReportMarkdown(jobId);
        if (typeof md === "string" && md.trim()) {
          blob = new Blob([md], { type: "text/markdown" });
          filename = `elise_report_${jobId}.md`;
        }
      } catch (_) {}

      if (!blob) {
        const data = await getReport(jobId);
        if (data instanceof Blob) {
          blob = data;
          filename =
            data.type === "application/pdf"
              ? `elise_report_${jobId}.pdf`
              : data.type?.includes("markdown")
              ? `elise_report_${jobId}.md`
              : `elise_report_${jobId}.bin`;
        } else if (typeof data === "string") {
          blob = new Blob([data], { type: "text/markdown" });
          filename = `elise_report_${jobId}.md`;
        } else {
          const txt = JSON.stringify(data ?? {}, null, 2);
          blob = new Blob([txt], { type: "application/json" });
          filename = `elise_report_${jobId}.json`;
        }
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `elise_report_${jobId}.md`;
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
    if (Array.isArray(fuzzSummary.core_results)) return fuzzSummary.core_results;
    if (Array.isArray(fuzzSummary.items)) return fuzzSummary.items;
    return [];
  }, [fuzzSummary]);

  const results = useMemo(
    () => rawResults.map((one) => {
      const req = one.request || {};
      const sigLegacy = one.signals || {};
      const hits = one.detector_hits || {};
      const method = (one.method || req.method || "GET").toUpperCase();
      const url = one.url || req.url || "";
      const param = one.param || one.target_param || req.param || "";
      const confidence = Number(one.confidence || 0);

      // deltas
      const statusDelta = typeof one.status_delta === "number" ? one.status_delta : undefined;
      const lenDelta = typeof one.len_delta === "number" ? one.len_delta : undefined;
      const msDelta = typeof one.latency_ms_delta === "number" ? one.latency_ms_delta : undefined;

      // redirect bits
      const redirLegacy = sigLegacy.open_redirect || {};
      const location =
        redirLegacy.location ||
        (one.response_headers || {}).location ||
        (sigLegacy.verify || {}).location ||
        (sigLegacy.open_redirect && sigLegacy.open_redirect.location) ||
        null;
      const external =
        Boolean(hits.open_redirect) ||
        Boolean(sigLegacy.external_redirect) ||
        Boolean(redirLegacy.open_redirect === true);
      const locationHost =
        redirLegacy.location_host ||
        sigLegacy.redirect_host ||
        (hits.open_redirect_host || null);

      // login bits
      const login = sigLegacy.login || {};
      const loginSuccess = !!login.login_success;
      const tokenPresent = !!login.token_present;

      // XSS reflection signals
      const xssReflected = Boolean(
        hits.xss_js || hits.xss_raw || (sigLegacy.reflection && (sigLegacy.reflection.raw || sigLegacy.reflection.js_context))
      );

      // SQL signals
      const sqlErr = Boolean(hits.sql_error || sigLegacy.sql_error);
      const booleanSqli = Boolean(hits.boolean_sqli || sigLegacy.boolean_sqli);
      const timeSqli = Boolean(hits.time_sqli || sigLegacy.time_sqli);

      // payloads/classes
      const payload = one.payload_string || one.payload || req.payload || "";
      const inferredClass = one.inferred_vuln_class || null;
      const fam =
        inferredClass ||
        familyFromSignals(sigLegacy) ||
        one.family ||
        (typeof sigLegacy.type === "string" ? sigLegacy.type : null);

      // ML provenance (prefer backend used_path when present)
      const usedPath =
        one?.ranker_meta?.used_path ||
        one?.ranker_meta?.ranker?.used_path ||
        one?.ml?.used_path ||
        one?.used_path ||
        null;

      // normalize ranker meta (now we pass the FULL original row + hints)
      const ranker_meta = normalizeRankerMeta(
        one.ranker_meta || one.ranker || one.ml_meta || (one.ml && (one.ml.ranker_meta || one.ml.ranker)) || {},
        one,
        {
          signals: {
            sql_error: sqlErr,
            boolean_sqli: booleanSqli,
            time_sqli: timeSqli,
            xss_reflected: xssReflected,
            external_redirect: external,
          },
          family: fam || null,
          confidence,
        }
      );

      // infer origin again using what we learned
      const baseOrigin = deriveOrigin({ ...one, ranker_meta: one.ranker_meta || one.ranker || {}, ml: one.ml || {} });

      // treat model ids (array/object/string), probs/score/dims, or used_path as ML
      const metaHasModelIds =
        !!ranker_meta?.model_ids &&
        (
          (Array.isArray(ranker_meta.model_ids) && ranker_meta.model_ids.length > 0) ||
          (typeof ranker_meta.model_ids === "object" && Object.keys(ranker_meta.model_ids).length > 0) ||
          (typeof ranker_meta.model_ids === "string" && ranker_meta.model_ids.trim())
        );

      const metaSuggestsML =
        isMLUsedPath(usedPath) ||
        metaHasModelIds ||
        isNonEmptyObj(ranker_meta.family_probs) ||
        hasNum(ranker_meta.ranker_score) ||
        hasNum(ranker_meta.feature_dim_total);

      const origin = metaSuggestsML ? "ml" : baseOrigin;

      // severity (transparent math)
      const severityScore =
        (external ? 0.35 : 0) +
        (sqlErr ? 0.35 : 0) +
        (booleanSqli ? 0.35 : 0) +
        (timeSqli ? 0.35 : 0) +
        (xssReflected ? 0.35 : 0) +
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
        origin,                 // "ml" | "curated"
        ranker_meta,            // normalized (or synthesized) meta
        ranker_used_path: usedPath || null, // surfaced for UI/debug
        severity,
        delta: {
          status_changed: typeof statusDelta === "number" ? statusDelta !== 0 : undefined,
          len_delta: lenDelta,
          len_ratio:
            typeof lenDelta === "number" && typeof one.baseline_len === "number" && one.baseline_len > 0
              ? (one.baseline_len + lenDelta) / one.baseline_len
              : undefined,
          ms_delta: msDelta,
        },
        signals: {
          sql_error: sqlErr,
          boolean_sqli: booleanSqli,
          time_sqli: timeSqli,
          xss_reflected: xssReflected,
          external_redirect: external,
          location,
          location_host: locationHost,
          login_success: loginSuccess,
          token_present: tokenPresent,
          verify: sigLegacy.verify || {},
        },
      };
    }),
    [rawResults]
  );

  // === Filter, search, sort ===
  const filteredResults = useMemo(() => {
    const fams = familiesSelected;
    const q = (filter || "").toLowerCase().trim();

    const base = results.filter((r) => {
      if (originFilter !== "all" && (r.origin || "curated") !== originFilter) return false;
      if (r.confidence < minConf) return false;
      if (!fams.has(r.family || "sqli")) return false;
      if (methodFilter !== "all" && (r.method || "").toUpperCase() !== methodFilter) return false;
      if (severityFilter !== "all" && (r.severity || "low") !== severityFilter) return false;

      if (strongOnly && !(r.signals.sql_error || r.signals.boolean_sqli || r.signals.time_sqli || r.signals.external_redirect || r.signals.xss_reflected)) {
        return false;
      }
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

      if (q) {
        const hay = [
          r.method, r.url, r.param, r.family, r.origin,
          r?.payload || ""
        ].join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const bySevVal = (sev) => (sev === "high" ? 3 : sev === "med" ? 2 : 1);
    const bySev = (r) => bySevVal(r.severity);
    const byLenAbs = (r) => Math.abs(r?.delta?.len_delta || 0);
    const cmpStr = (a, b) => String(a || "").localeCompare(String(b || ""));

    const applySort = (a, b) => {
      switch (sortBy) {
        case "conf_asc": return a.confidence - b.confidence || byLenAbs(b) - byLenAbs(a);
        case "sev_conf": return bySev(b) - bySev(a) || b.confidence - a.confidence;
        case "severity_asc": return bySev(a) - bySev(b) || b.confidence - a.confidence;
        case "severity_desc": return bySev(b) - bySev(a) || b.confidence - a.confidence;
        case "origin_asc": return cmpStr(a.origin, b.origin) || b.confidence - a.confidence;
        case "origin_desc": return cmpStr(b.origin, a.origin) || b.confidence - a.confidence;
        case "family_asc": return cmpStr(a.family, b.family) || b.confidence - a.confidence;
        case "family_desc": return cmpStr(b.family, a.family) || b.confidence - a.confidence;
        case "method_asc": return cmpStr(a.method, b.method) || b.confidence - a.confidence;
        case "method_desc": return cmpStr(b.method, a.method) || b.confidence - a.confidence;
        case "url_asc": return cmpStr(a.url, b.url) || b.confidence - a.confidence;
        case "url_desc": return cmpStr(b.url, a.url) || b.confidence - a.confidence;
        case "param_asc": return cmpStr(a.param, b.param) || b.confidence - a.confidence;
        case "param_desc": return cmpStr(b.param, a.param) || b.confidence - a.confidence;
        case "len_abs": return byLenAbs(b) - byLenAbs(a) || b.confidence - a.confidence;
        case "len_abs_asc": return byLenAbs(a) - byLenAbs(b) || b.confidence - a.confidence;
        default: /* conf_desc */ return b.confidence - a.confidence || byLenAbs(b) - byLenAbs(a);
      }
    };

    return base.sort(applySort);
  }, [
    results, familiesSelected, minConf, onlySqlError, onlyXssRef, onlyExtRedir, onlyWithDelta,
    sortBy, originFilter, strongOnly, filter, methodFilter, severityFilter
  ]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filteredResults.length / pageSize));
  const pageClamped = Math.min(page, totalPages);
  const start = (pageClamped - 1) * pageSize;
  const end = Math.min(filteredResults.length, start + pageSize);
  const pageRows = filteredResults.slice(start, end);

  // Summary tiles (based on visible/filtered results)
  const summary = useMemo(() => {
    const src = filteredResults;
    const total = src.length;
    const famCounts = { sqli: 0, xss: 0, redirect: 0 };
    const signals = { sql: 0, xss: 0, redir: 0 };
    let hi = 0;
    let mlCount = 0;
    let curatedCount = 0;
    let avgRankerScore = 0;
    let mlWithScore = 0;

    const confBuckets = [0, 0, 0, 0, 0];

    for (const r of src) {
      const fam = r.family || "sqli";
      if (fam in famCounts) famCounts[fam]++;
      if (r.signals.sql_error || r.signals.boolean_sqli || r.signals.time_sqli) signals.sql++;
      if (r.signals.xss_reflected) signals.xss++;
      if (r.signals.external_redirect) signals.redir++;
      if (r.confidence >= 0.8) hi++;

      if ((r.origin || "curated") === "ml") {
        mlCount++;
        if (typeof r?.ranker_meta?.ranker_score === "number") {
          avgRankerScore += r.ranker_meta.ranker_score;
          mlWithScore++;
        }
      } else {
        curatedCount++;
      }

      const b = Math.min(4, Math.floor(Math.max(0, Math.min(0.999, r.confidence)) * 5));
      confBuckets[b] += 1;
    }

    const avgR = mlWithScore ? avgRankerScore / mlWithScore : 0;

    return { total, famCounts, signals, hi, mlCount, curatedCount, confBuckets, avgRankerScore: avgR };
  }, [filteredResults]);

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
      [
        "method","url","param","family","origin","ranker_score","ranker_family","feature_dim","severity","confidence",
        "status_changed","len_delta","ms_delta","sql_error","boolean_sqli","time_sqli","xss_reflected",
        "external_redirect","location","payload",
      ],
      ...filteredResults.map((r) => [
        r.method, r.url, r.param, r.family || "", r.origin || "",
        r?.ranker_meta?.ranker_score ?? "", r?.ranker_meta?.family_chosen ?? "",
        r?.ranker_meta?.feature_dim_total ?? "",
        r.severity || "", r.confidence,
        r?.delta?.status_changed ? "1" : "0",
        r?.delta?.len_delta ?? "",
        r?.delta?.ms_delta ?? "",
        r.signals.sql_error ? "1" : "0",
        r.signals.boolean_sqli ? "1" : "0",
        r.signals.time_sqli ? "1" : "0",
        r.signals.xss_reflected ? "1" : "0",
        r.signals.external_redirect ? "1" : "0",
        r.signals.location || "",
        (r.payload || "").replace(/\n/g, "\\n"),
      ]),
    ];
    const csv = rows.map(row =>
      row.map((cell) => {
        const s = String(cell ?? "");
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      }).join(",")
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

  const toggleFamily = (fam) => {
    const next = new Set(familiesSelected);
    if (next.has(fam)) next.delete(fam);
    else next.add(fam);
    if (next.size === 0) {
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
      <header className="flex items-center justify-between gap-2">
        <h1 className="text-2xl font-semibold">Crawl &amp; Fuzz</h1>
        <div className="flex items-center gap-2">
          <TogglePill active={compact} onClick={() => setCompact((v) => !v)} toneActive="slate">
            {compact ? "Compact: On" : "Compact: Off"}
          </TogglePill>
          <TogglePill
            active={strongOnly}
            onClick={() => setStrongOnly((v) => !v)}
            toneActive="teal"
            title="Only strong oracles (SQL error / boolean / time / external redirect / reflected XSS)"
          >
            Strong only
          </TogglePill>
        </div>
      </header>

      <CrawlForm onJobReady={setJobId} onResults={onResults} />

      {jobId && (
        <div className="text-sm text-gray-600 flex items-center gap-2 flex-wrap">
          <span className="font-mono">job_id:</span>
          <span className="font-mono">{jobId}</span>
          <span className="ml-4 text-gray-500">Engine:</span>
          {/* Note: "core" engine uses the ML ranker, "ffuf" is legacy without ML */}
          <select
            className="border p-1 rounded text-sm"
            value={engineMode}
            onChange={(e) => setEngineMode(e.target.value)}
            title="Engine selection: auto=ML+curated, core=ML only, ffuf=no ML"
          >
            <option value="auto">auto (ML + curated)</option>
            <option value="core">core (with ML)</option>
            <option value="ffuf">ffuf only (no ML)</option>
          </select>
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
        <StatCard label="Target" value={<span className="text-sm font-mono break-all">{targetUrl || "—"}</span>} />
        <StatCard label="Endpoints" value={counts.endpoints} />
        <StatCard label="Visible" value={counts.visible} />
        <StatCard label="Selected" value={counts.selected} />
        <StatCard label="Captured" value={counts.captured} />
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-2 items-center sticky top-0 z-20 bg-white/90 backdrop-blur border-b py-2 px-1">
        <button className="bg-purple-600 text-white px-4 py-2 rounded disabled:opacity-60" onClick={onFuzzAll} disabled={!jobId || loadingFuzz} type="button">
          {loadingFuzz ? "Fuzzing…" : `Fuzz ALL (${engineMode === "core" ? "ML" : engineMode})`}
        </button>
        <button
          className="bg-blue-600 text-white px-4 py-2 rounded disabled:opacity-60"
          onClick={onFuzzSelected}
          disabled={!jobId || loadingFuzz || selectedKeys.size === 0}
          type="button"
        >
          {`Fuzz Selected (${engineMode === "core" ? "ML" : engineMode})`}
        </button>
        <button className="bg-gray-800 text-white px-4 py-2 rounded disabled:opacity-60" onClick={downloadReport} disabled={!jobId} type="button">
          Download Report
        </button>

        <div className="ml-auto flex items-center gap-2 flex-wrap">
          {/* Family */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-gray-500">Family:</label>
            <TogglePill active={familiesSelected.has("sqli")} onClick={() => toggleFamily("sqli")}>SQLi</TogglePill>
            <TogglePill active={familiesSelected.has("xss")} onClick={() => toggleFamily("xss")}>XSS</TogglePill>
            <TogglePill active={familiesSelected.has("redirect")} onClick={() => toggleFamily("redirect")}>Redirect</TogglePill>
          </div>

          {/* Method */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-gray-500">Method:</label>
            <select className="border p-2 rounded text-sm" value={methodFilter} onChange={(e) => setMethodFilter(e.target.value)}>
              {["all","GET","POST","PUT","DELETE","PATCH"].map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>

          {/* Severity */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-gray-500">Severity:</label>
            <select className="border p-2 rounded text-sm" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
              <option value="all">all</option>
              <option value="high">high</option>
              <option value="med">medium</option>
              <option value="low">low</option>
            </select>
          </div>

          {/* Origin */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-gray-500">Origin:</label>
            <select
              className="border p-2 rounded text-sm"
              value={originFilter}
              onChange={(e) => setOriginFilter(e.target.value)}
              title="Filter by payload origin"
            >
              <option value="all">All</option>
              <option value="ml">ML only</option>
              <option value="curated">Curated only</option>
            </select>
          </div>

          {/* Confidence slider */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-gray-500">Min conf:</label>
            <input type="range" min="0" max="1" step="0.05" value={minConf} onChange={(e) => setMinConf(Number(e.target.value))} className="w-28" />
            <span className="text-xs font-mono">{minConf.toFixed(2)}</span>
          </div>

          {/* Signal toggles */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-gray-500">Signals:</label>
            <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={onlySqlError} onChange={(e) => setOnlySqlError(e.target.checked)} /> SQL err</label>
            <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={onlyXssRef} onChange={(e) => setOnlyXssRef(e.target.checked)} /> XSS refl</label>
            <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={onlyExtRedir} onChange={(e) => setOnlyExtRedir(e.target.checked)} /> Ext redir</label>
            <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={onlyWithDelta} onChange={(e) => setOnlyWithDelta(e.target.checked)} /> Has Δ</label>
          </div>

          {/* Sort */}
          <select className="border p-2 rounded text-sm" value={sortBy} onChange={(e) => setSortBy(e.target.value)} title="Sort results">
            <option value="conf_desc">Sort: Confidence ↓</option>
            <option value="conf_asc">Sort: Confidence ↑</option>
            <option value="sev_conf">Sort: Severity → Confidence</option>
            <option value="severity_desc">Sort: Severity ↓</option>
            <option value="severity_asc">Sort: Severity ↑</option>
            <option value="origin_asc">Sort: Origin A→Z</option>
            <option value="origin_desc">Sort: Origin Z→A</option>
            <option value="family_asc">Sort: Family A→Z</option>
            <option value="family_desc">Sort: Family Z→A</option>
            <option value="method_asc">Sort: Method A→Z</option>
            <option value="method_desc">Sort: Method Z→A</option>
            <option value="url_asc">Sort: URL A→Z</option>
            <option value="url_desc">Sort: URL Z→A</option>
            <option value="param_asc">Sort: Param A→Z</option>
            <option value="param_desc">Sort: Param Z→A</option>
            <option value="len_abs">Sort: |Δlen| ↓</option>
            <option value="len_abs_asc">Sort: |Δlen| ↑</option>
          </select>

          {/* Search + export */}
          <input className="border p-2 rounded min-w-[260px]" placeholder="Search (URL, param, payload, origin…)" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <button className="border px-3 py-2 rounded" onClick={copyJson} title="Copy filtered JSON" type="button">Copy JSON</button>
          <button className="border px-3 py-2 rounded" onClick={downloadCsv} title="Download filtered CSV" type="button">CSV</button>

          {/* Cards toggle */}
          <TogglePill active={viewMode === "cards"} onClick={() => setViewMode(v => v === "cards" ? "table" : "cards")} toneActive="teal">
            {viewMode === "cards" ? "Cards" : "Table"}
          </TogglePill>

          {/* Page size */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-gray-500">Page:</label>
            <select className="border p-2 rounded text-sm" value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))}>
              {[25,50,100,200].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
        </div>
      </div>

      {/* Endpoint selection list */}
      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Endpoints</h2>
          <div className="flex items-center gap-2">
            <button className="border px-3 py-1.5 rounded" onClick={selectAllVisible} type="button">Select all (visible)</button>
            <button className="border px-3 py-1.5 rounded" onClick={() => selectTopNVisible(20)} title="Select top 20 visible by priority" type="button">Select top 20</button>
            <button className="border px-3 py-1.5 rounded" onClick={() => selectFamilyVisible("redirect")} type="button">Select redirects</button>
            <button className="border px-3 py-1.5 rounded" onClick={() => selectFamilyVisible("xss")} type="button">Select XSS</button>
            <button className="border px-3 py-1.5 rounded" onClick={() => selectFamilyVisible("sqli")} type="button">Select SQLi</button>
            <button className="border px-3 py-1.5 rounded" onClick={clearSelection} type="button">Clear</button>
          </div>
        </div>

        <div className="border rounded max-h-80 overflow-auto">
          {filtered.length === 0 ? (
            <div className="p-3 text-gray-500">No endpoints</div>
          ) : (
            filtered.map((ep) => {
              const checked = selectedKeys.has(ep._shape);
              return (
                <label key={ep._shape} className="p-3 border-b flex items-start gap-3 cursor-pointer hover:bg-gray-50">
                  <input type="checkbox" checked={checked} onChange={() => toggle(ep)} className="mt-1" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm">{(ep.method || "").toUpperCase()}</span>
                      <a href={ep.url} target="_blank" rel="noreferrer" className="font-mono text-sm break-words [overflow-wrap:anywhere] underline decoration-dotted">
                        {ep.url}
                      </a>
                      <span className="ml-auto flex items-center gap-2">
                        <span className="text-xs text-gray-500">prio:</span>
                        <span className="text-xs font-mono">{(ep._priority || 0).toFixed(2)}</span>
                        <FamilyBadge fam={ep._family} />
                      </span>
                    </div>
                    {isNonEmptyArray(ep.params) ? <div className="text-xs text-gray-600">query: {ep.params.join(", ")}</div> : null}
                    {isNonEmptyArray(ep._form_params) ? <div className="text-xs text-gray-600">form: {ep._form_params.join(", ")}</div> : null}
                    {isNonEmptyArray(ep._json_params) ? <div className="text-xs text-gray-600">json: {ep._json_params.join(", ")}</div> : null}
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

      {/* Captured requests */}
      <section className="space-y-2">
        <h2 className="text-lg font-semibold">Captured Requests</h2>
        <div className="border rounded max-h-80 overflow-auto">
          {captured.length === 0 ? (
            <div className="p-3 text-gray-500">No captured requests</div>
          ) : (
            captured.map((r, i) => (
              <div key={i} className="p-3 border-b">
                <div className="font-mono text-sm break-words [overflow-wrap:anywhere]">
                  {(r.method || "").toUpperCase()} {r.url}
                </div>
                {r.body_parsed ? (
                  <pre className="text-xs mt-1 bg-gray-50 p-2 rounded overflow-auto">{JSON.stringify(r.body_parsed, null, 2)}</pre>
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

      {/* Results summary strip + ML insights */}
      {results.length > 0 && (
        <section className="space-y-2">
          <div className="grid grid-cols-5 gap-3">
            <StatCard label="Results (visible)" value={summary.total} />
            <StatCard label="By family" value={
              <div className="mt-1 text-sm flex gap-2 flex-wrap">
                <Badge tone="blue">SQLi: {summary.famCounts.sqli}</Badge>
                <Badge tone="pink">XSS: {summary.famCounts.xss}</Badge>
                <Badge tone="purple">Redirect: {summary.famCounts.redirect}</Badge>
              </div>
            } />
            <StatCard label="Signals" value={
              <div className="mt-1 text-sm flex gap-2 flex-wrap">
                <Badge tone="blue" title="SQL indicators (error, boolean, or time)">SQL: {summary.signals.sql}</Badge>
                <Badge tone="pink">XSS refl: {summary.signals.xss}</Badge>
                <Badge tone="purple">Ext redir: {summary.signals.redir}</Badge>
              </div>
            } />
            <StatCard label="High confidence (≥0.8)" value={summary.hi} />
            <StatCard label="Origin" value={
              <div className="mt-1 text-sm flex gap-2 flex-wrap items-center">
                <Badge tone="indigo">ML: {summary.mlCount}</Badge>
                <Badge tone="slate">Curated: {summary.curatedCount}</Badge>
                <span className="text-xs text-gray-500">avg ranker score (ML):&nbsp;
                  <span className="font-mono">{summary.avgRankerScore ? summary.avgRankerScore.toFixed(3) : "—"}</span>
                </span>
              </div>
            } />
          </div>

          {/* Confidence distribution mini-bar */}
          <div className="border rounded p-3">
            <div className="text-xs text-gray-500 mb-1">Confidence distribution</div>
            <div className="flex items-end gap-2 h-16">
              {summary.confBuckets.map((c, i) => {
                const lo = (i * 0.2).toFixed(1);
                const hi = ((i + 1) * 0.2).toFixed(1);
                return (
                  <div key={i} className="flex flex-col items-center">
                    <div className="w-8 bg-gray-300 rounded-t" style={{ height: `${Math.min(100, 8 + c * 6)}%` }} title={`${lo}–${hi}: ${c}`} />
                    <div className="text-[10px] font-mono mt-1">{lo}-{hi}</div>
                  </div>
                );
              })}
            </div>
          </div>
        </section>
      )}

      {/* Fuzz summary */}
      {results.length > 0 && (
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Fuzz Results</h2>
            <div className="text-xs text-gray-500">
              Showing <span className="font-mono">{start+1}</span>–<span className="font-mono">{end}</span> of <span className="font-mono">{filteredResults.length}</span>
            </div>
          </div>

          {/* Table view */}
          {viewMode === "table" && (
            <div className="overflow-auto border rounded relative">
              <table className="min-w-full text-sm">
                <thead className="bg-gray-50 sticky top-0 z-30">
                  <tr className="text-left">
                    <th className="p-2 w-24 sticky left-0 z-20 bg-gray-50"><SortHeader fieldKey="severity" label="Severity" current={sortBy} set={setSortBy} /></th>
                    <th className="p-2 w-28 sticky left-24 z-20 bg-gray-50"><SortHeader fieldKey="conf" label="Conf" current={sortBy} set={setSortBy} /></th>
                    <th className="p-2 w-24 whitespace-nowrap"><SortHeader fieldKey="origin" label="Origin" current={sortBy} set={setSortBy} /></th>
                    <th className="p-2 w-28"><SortHeader fieldKey="family" label="Family" current={sortBy} set={setSortBy} /></th>
                    <th className="p-2 w-16"><SortHeader fieldKey="method" label="Method" current={sortBy} set={setSortBy} /></th>
                    <th className="p-2 min-w-[480px]"><SortHeader fieldKey="url" label="URL" current={sortBy} set={setSortBy} /></th>
                    <th className="p-2 w-40"><SortHeader fieldKey="param" label="Param" current={sortBy} set={setSortBy} /></th>
                    <th className="p-2 w-44">Δ</th>
                    <th className="p-2 w-64">Signals</th>
                    <th className="p-2 w-56">Ranker</th>
                    <th className="p-2 min-w-[280px]">Payload</th>
                    <th className="p-2 w-20"></th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((row) => {
                    const k = rowKey(row);
                    const isOpen = expanded.has(k);
                    const chosen = row?.ranker_meta?.family_chosen || null;

                    const rowBg =
                      row.severity === "high" ? "bg-red-50" :
                      row.severity === "med" ? "bg-amber-50" :
                      row.origin === "ml" ? "bg-indigo-50/30" : "";

                    // derive ML vs heuristic label for ranker cell
                    const usedPath = String(row?.ranker_used_path || "").toLowerCase();
                    const mlSource = String(row?.ml?.source || "").toLowerCase();
                    const rankerMetaUsedPath = String(row?.ranker_meta?.used_path || "").toLowerCase();

                    // accept arrays/objects/strings for model ids
                    const hasModelIds =
                      !!row?.ranker_meta?.model_ids &&
                      (
                        (Array.isArray(row.ranker_meta.model_ids) && row.ranker_meta.model_ids.length > 0) ||
                        (typeof row.ranker_meta.model_ids === "object" && Object.keys(row.ranker_meta.model_ids).length > 0) ||
                        (typeof row.ranker_meta.model_ids === "string" && row.ranker_meta.model_ids.trim())
                      );

                    // Debug logging for ML detection
                    console.log("Debug ML detection:", {
                      usedPath: row?.ranker_used_path,
                      mlSource: row?.ml?.source,
                      rankerMetaUsedPath: row?.ranker_meta?.used_path,
                      hasModelIds,
                      familyProbs: row?.ranker_meta?.family_probs,
                      rankerScore: row?.ranker_meta?.ranker_score,
                      featureDim: row?.ranker_meta?.feature_dim_total
                    });
                    
                    const rankerIsML =
                      isMLUsedPath(usedPath) ||
                      isMLUsedPath(mlSource) ||
                      isMLUsedPath(rankerMetaUsedPath) ||
                      hasModelIds ||
                      // If we have family probabilities and ranker score, this is ML
                      (!!row?.ranker_meta?.family_probs && 
                       typeof row?.ranker_meta?.ranker_score === "number" &&
                       row?.ranker_meta?.ranker_score > 0) ||
                      // Fallback: if we have any ML-like data, consider it ML
                      (!!row?.ranker_meta && !row?.ranker_meta._synthetic && (
                        isNonEmptyObj(row.ranker_meta.family_probs) ||
                        hasNum(row.ranker_meta.ranker_score) ||
                        hasNum(row.ranker_meta.feature_dim_total)
                      ));
                    
                    console.log("rankerIsML result:", rankerIsML);

                    const rankerScore =
                      typeof row?.ranker_meta?.ranker_score === "number"
                        ? row.ranker_meta.ranker_score.toFixed(3)
                        : "—";

                    const featureDim =
                      hasNum(row?.ranker_meta?.feature_dim_total) ? row.ranker_meta.feature_dim_total : null;
                    const dimPrefix = featureDim ? `dim ${featureDim} · ` : "";

                    return (
                      <tr key={k} className={cn("border-t align-top hover:bg-gray-50", rowBg)}>
                        {/* sticky cols */}
                        <td className="p-2 w-24 sticky left-0 z-10 bg-white"><SeverityBadge sev={row.severity} /></td>
                        <td className="p-2 w-28 sticky left-24 z-10 bg-white"><ConfMeter v={Number(row.confidence || 0)} /></td>

                        <td className="p-2 w-24 whitespace-nowrap" data-origin={row.origin}>
                          <div className="inline-block min-w-[56px]">
                            <OriginBadge origin={row.origin} />
                          </div>
                        </td>
                        <td className="p-2 w-28">
                          <div className="flex items-center gap-2">
                            <Badge tone={row.family === "xss" ? "pink" : row.family === "redirect" ? "purple" : "blue"}>{row.family || "sqli"}</Badge>
                            {chosen && <Badge tone="indigo" title="Family chosen by ranker">chosen: {chosen}</Badge>}
                          </div>
                        </td>
                        <td className="p-2 w-16 font-mono">{row.method}</td>
                        <td className="p-2 font-mono whitespace-normal break-words [overflow-wrap:anywhere]">
                          <a href={row.url} target="_blank" rel="noreferrer" className="underline decoration-dotted">
                            {row.url}
                          </a>
                        </td>
                        <td className="p-2 w-40 font-mono truncate" title={row.param}>{row.param}</td>
                        <td className="p-2 w-44"><DeltaCell d={row.delta} /></td>

                        <td className="p-2 w-64">
                          <div className="flex flex-wrap items-center gap-2">
                            {row.signals.sql_error && <Badge tone="blue">sql error</Badge>}
                            {row.signals.boolean_sqli && <Badge tone="blue">boolean</Badge>}
                            {row.signals.time_sqli && <Badge tone="blue">time</Badge>}
                            {row.signals.xss_reflected && <Badge tone="pink">xss reflected</Badge>}
                            {row.signals.external_redirect && <Badge tone="purple">external</Badge>}
                            {row?.signals?.location_host && <Badge tone="purple">{row.signals.location_host}</Badge>}
                          </div>
                        </td>

                        <td className="p-2 w-56" data-ranker={rankerIsML ? "ML" : row?.ranker_meta?._synthetic ? "heuristic" : ""}>
                          {row?.ranker_meta?.family_probs ? <FamilyProbsBar probs={row.ranker_meta.family_probs} /> : <span className="text-gray-400">—</span>}
                          <div className="text-[10px] text-gray-500 mt-1">
                            {dimPrefix}score: <span className="font-mono">{rankerScore}</span>
                            <span className="ml-1 text-gray-400">
                              {rankerIsML ? "(ML)" : row?.ranker_meta?._synthetic ? "(heuristic)" : ""}
                            </span>
                          </div>
                        </td>
                        <td className="p-2 min-w-[280px]">
                          <code className="text-xs block truncate" title={row.payload || ""}>{row.payload || ""}</code>
                        </td>
                        <td className="p-2 w-20">
                          <button className="text-xs border px-2 py-1 rounded" onClick={() => toggleExpand(k)} aria-expanded={isOpen} type="button">
                            {isOpen ? "Hide" : "Details"}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {pageRows.length === 0 && (
                <div className="p-4 text-sm text-gray-500">
                  No results match the current filters.&nbsp;
                  <span className="text-xs">
                    (Origin: <span className="font-mono">{originFilter}</span>,
                    &nbsp;Families: <span className="font-mono">{[...familiesSelected].join(", ")}</span>,
                    &nbsp;Min conf: <span className="font-mono">{minConf.toFixed(2)}</span>)
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Expanded rows (optional) */}
          <div className="space-y-2">
            {filteredResults.map((row) => {
              const k = rowKey(row);
              if (!expanded.has(k)) return null;
              const v = row.signals?.verify || {};
              const fm = row.ranker_meta || {};
              return (
                <div key={`detail-${k}`} className="border rounded p-3 bg-white">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="text-sm">
                        <SeverityBadge sev={row.severity} />{" "}
                        <Badge tone={row.family === "xss" ? "pink" : row.family === "redirect" ? "purple" : "blue"}>
                          {row.family || "sqli"}
                        </Badge>{" "}
                        <OriginBadge origin={row.origin} />{" "}
                        <Badge tone="slate" title="confidence">
                          <span className="font-mono">{row.confidence.toFixed(2)}</span>
                        </Badge>
                      </div>
                      <div className="text-sm font-mono">
                        {row.method} {row.url}
                      </div>
                      <div className="text-xs text-gray-600">
                        param: <code>{row.param}</code>
                      </div>
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
                        type="button"
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
                          document.body.appendChild(a);
                          a.click();
                          a.remove();
                          URL.revokeObjectURL(url);
                        }}
                        type="button"
                      >
                        Save row
                      </button>
                      <button className="text-xs border px-2 py-1 rounded" onClick={() => toggleExpand(k)} type="button">
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
                        {"location" in v ? (<div>location: <span className="break-all">{v.location}</span></div>) : null}
                      </div>
                    </div>
                    <div className="border rounded p-2">
                      <div className="text-xs text-gray-500 mb-1">Signals</div>
                      <div className="text-xs space-x-2">
                        {row.signals.sql_error ? <Badge tone="blue">sql error</Badge> : null}
                        {row.signals.boolean_sqli ? <Badge tone="blue">boolean</Badge> : null}
                        {row.signals.time_sqli ? <Badge tone="blue">time</Badge> : null}
                        {row.signals.xss_reflected ? <Badge tone="pink">xss reflected</Badge> : null}
                        {row.signals.external_redirect ? <Badge tone="purple">external redirect</Badge> : null}
                        {row.signals.login_success ? <Badge tone="green">login bypass</Badge> : null}
                        {row.signals.token_present ? <Badge tone="green">token present</Badge> : null}
                      </div>
                    </div>
                  </div>

                  {/* Ranker meta */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
                    <div className="border rounded p-2">
                      <div className="text-xs text-gray-500 mb-1">Family probabilities</div>
                      <div className="flex items-center gap-2">
                        <FamilyProbsBar probs={fm.family_probs} />
                        <div className="text-xs font-mono">
                          {Object.entries(fm.family_probs || {})
                            .sort((a, b) => b[1] - a[1])
                            .slice(0, 3)
                            .map(([k, v]) => (
                              <div key={k}>{k}: {(v * 100).toFixed(1)}%</div>
                            ))}
                        </div>
                      </div>
                    </div>
                    <div className="border rounded p-2">
                      <div className="text-xs text-gray-500 mb-1">Chosen / Score</div>
                      <div className="text-xs">chosen: <code>{fm.family_chosen || "—"}</code></div>
                      <div className="text-xs">
                        {(hasNum(fm.feature_dim_total) ? `dim ${fm.feature_dim_total} · ` : "")}
                        score: <code>{typeof fm.ranker_score === "number" ? fm.ranker_score.toFixed(3) : "—"}</code>
                      </div>
                      {/* backend used_path (if available) */}
                      <div className="text-[10px] text-gray-400 mt-1">{row.ranker_used_path ? `used_path: ${row.ranker_used_path}` : ""}</div>
                    </div>
                    <div className="border rounded p-2">
                      <div className="text-xs text-gray-500 mb-1">Model IDs</div>
                      <div className="text-xs font-mono">
                        {fm.model_ids ? <pre className="whitespace-pre-wrap">{JSON.stringify(fm.model_ids, null, 2)}</pre> : "—"}
                      </div>
                    </div>
                  </div>

                  <div className="mt-3">
                    <div className="text-xs text-gray-500 mb-1">Payload</div>
                    <pre className="text-xs bg-gray-50 p-2 rounded overflow-auto">{row.payload || ""}</pre>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Pagination controls */}
          <div className="flex items-center justify-between text-sm text-gray-600 py-2">
            <div>Showing <span className="font-mono">{start+1}</span>–<span className="font-mono">{end}</span> of <span className="font-mono">{filteredResults.length}</span></div>
            <div className="flex items-center gap-2">
              <button className="border px-2 py-1 rounded disabled:opacity-50" disabled={pageClamped <= 1} onClick={() => setPage(p => Math.max(1, p-1))}>Prev</button>
              <span className="font-mono">{pageClamped}</span>/<span className="font-mono">{totalPages}</span>
              <button className="border px-2 py-1 rounded disabled:opacity-50" disabled={pageClamped >= totalPages} onClick={() => setPage(p => Math.min(totalPages, p+1))}>Next</button>
            </div>
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
