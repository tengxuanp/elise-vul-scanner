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
  // For grouped results, use method + baseUrl + param as the key
  if (row.baseUrl) {
    return `${row.method}|${row.baseUrl}|${row.param}`;
  }
  // Fallback for non-grouped results
  const p = typeof row.payload === "string" ? row.payload.slice(0, 64) : "";
  return `${row.method}|${row.url}|${row.param}|${p}`;
};

/** Consider more ML path spellings; explicitly exclude heuristic/none */
const isMLUsedPath = (usedPath = "") => {
  const parts = Array.isArray(usedPath) ? usedPath : [usedPath];
  const s = parts.map((x) => String(x || "").toLowerCase()).join("|");
  if (!s) return false;
  if (/\b(heuristic|none)\b/.test(s)) return false;
  // Check for enhanced_ml and ml:family patterns (e.g., enhanced_ml, ml:sqli, ml:xss)
  if (/enhanced_ml/.test(s) || /ml:[a-z]+/.test(s)) return true;
  return /(family[-_ ]?ranker|family[-_ ]?router|ml[-_ ]?ranker|ml[-_ ]?router|generic[-_ ]?ranker|plugin|ranker|router)/.test(s);
};

/** Extract plain names from arrays that can contain strings or {name: "…"} dicts */
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
    if (famGuess === "xss") xss += Math.max(0.2, Math.min(0.7, confidence));
    if (famGuess === "redirect") redirect += Math.max(0.2, Math.min(0.7, confidence));
  }

  const sum = sqli + xss + redirect || 1;
  const probs = { sqli: sqli / sum, xss: xss / sum, redirect: redirect / sum };
  const chosen = Object.entries(probs).sort((a, b) => b[1] - a[1])[0][0];

  // Use heuristic-based scoring instead of realistic random scores
  // This makes it clear that we're not using ML
  const heuristicScore = anyStrong ? 0.6 : 0.4;  // Fixed values, no randomness

  return {
    family_probs: probs,
    family_chosen: chosen,
    ranker_score: "Heuristic",  // Use string to indicate non-ML scoring
    model_ids: "Heuristic",
    _synthetic: true,
    _note: "Heuristic fallback - enhanced ML data not available",
    _heuristic_score: heuristicScore  // Store actual numeric value for sorting if needed
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
  // Prefer backend-provided ranker_meta, but search broadly for nested shapes
  const fm = mRaw || {};
  const row = oneRowRaw || {};
  


  const containers = [
    row.ranker_meta, row.ranker, row.ml_meta, row.meta,
    fm, fm.ranker_meta, fm.ranker, fm.ml_meta,
  ].filter(Boolean);

  // Accumulators (prefer earliest hit in priority order below)
  let used_path = null;
  let ranker_score = null;
  let family_probs = null;
  let family_chosen = null;
  let model_ids = null;
  let feature_dim_total = null;
  let enhancedFlag = false;
  let mlPredFlag = false;
  let ranker_raw = null;

  // Helper to set once
  const setOnce = (cur, val) => (cur == null ? val : cur);

  for (const c of containers) {
    if (!c || typeof c !== 'object') continue;

    // used_path can appear nested (e.g., ranker_raw.used_path)
    used_path = setOnce(used_path, c.used_path || c?.ranker?.used_path || c?.ranker_raw?.used_path);
    
    // Also check for used_path in the main row data
    if (!used_path && oneRowRaw) {
      used_path = setOnce(used_path, oneRowRaw.used_path || oneRowRaw?.ranker?.used_path || oneRowRaw?.ranker_raw?.used_path);
    }

    // capture any nested ranker_raw for enhanced ML
    if (!ranker_raw && (c.ranker_raw || c?.ranker?.ranker_raw)) {
      ranker_raw = c.ranker_raw || c?.ranker?.ranker_raw;
    }
    
    // Also check for ranker_raw in the main row data
    if (!ranker_raw && oneRowRaw) {
      ranker_raw = oneRowRaw.ranker_raw || oneRowRaw?.ranker?.ranker_raw;
    }

    // Prefer enhanced ML's internal confidence if present
    const scoreCands = [
      c?.ranker_raw?.confidence,
      c?.ranker?.ranker_raw?.confidence,
      c.ranker_score,
      c.score,
    ];
    for (const cand of scoreCands) {
      if (hasNum(cand)) { ranker_score = setOnce(ranker_score, Number(cand)); break; }
    }

    // family probs via flexible extractor
    if (!isNonEmptyObj(family_probs)) {
      const fp = extractFamilyProbs(c);
      if (isNonEmptyObj(fp)) family_probs = fp;
    }
    
    // Also check for family_probs in the main row data
    if (!isNonEmptyObj(family_probs) && oneRowRaw) {
      const fp = extractFamilyProbs(oneRowRaw);
      if (isNonEmptyObj(fp)) family_probs = fp;
    }

    // family chosen
    family_chosen = setOnce(family_chosen, c.family_chosen || c.family || c.chosen || c.chosen_family);
    
    // Also check for family_chosen in the main row data
    if (!family_chosen && oneRowRaw) {
      family_chosen = setOnce(family_chosen, oneRowRaw.family_chosen || oneRowRaw.family || oneRowRaw.chosen || oneRowRaw.chosen_family);
    }

    // model identifiers can be object/array/string
    if (!model_ids) {
      const mid = c.model_ids || c.models || c.model_id || c.model || c.model_name || null;
      if (
        (Array.isArray(mid) && mid.length > 0) ||
        (mid && typeof mid === 'object' && Object.keys(mid).length > 0) ||
        (typeof mid === 'string' && mid.trim())
      ) {
        model_ids = mid;
      }
    }
    
    // Also check for model_ids in the main row data
    if (!model_ids && oneRowRaw) {
      const mid = oneRowRaw.model_ids || oneRowRaw.models || oneRowRaw.model_id || oneRowRaw.model || oneRowRaw.model_name || null;
      if (
        (Array.isArray(mid) && mid.length > 0) ||
        (mid && typeof mid === 'object' && Object.keys(mid).length > 0) ||
        (typeof mid === 'string' && mid.trim())
      ) {
        model_ids = mid;
      }
    }

    // dims
    if (!hasNum(feature_dim_total)) {
      const dims = extractFeatureDim(c);
      if (hasNum(dims)) feature_dim_total = dims;
    }
    
    // Also check for feature dimensions in the main row data
    if (!hasNum(feature_dim_total) && oneRowRaw) {
      const dims = extractFeatureDim(oneRowRaw);
      if (hasNum(dims)) feature_dim_total = dims;
    }

    // flags
    if (c.enhanced_ml === true) enhancedFlag = true;
    if (c.is_ml_prediction === true) mlPredFlag = true;
    
    // Also check for flags in the main row data
    if (oneRowRaw?.enhanced_ml === true) enhancedFlag = true;
    if (oneRowRaw?.is_ml_prediction === true) mlPredFlag = true;
  }

  const isEnhancedML = String(used_path || '').toLowerCase() === 'enhanced_ml' || enhancedFlag || mlPredFlag;
  
  // Also check for ML indicators in the data structure
  const hasMLIndicators = isEnhancedML || 
                          String(used_path || '').toLowerCase().includes('ml') ||
                          String(used_path || '').toLowerCase().includes('ranker') ||
                          enhancedFlag || 
                          mlPredFlag;

  // Determine if we have enough to show real ML
  // Be more lenient - if we have any ML score, show it
  const hasModelIds = (
    (Array.isArray(model_ids) && model_ids.length > 0) ||
    (model_ids && typeof model_ids === 'object' && Object.keys(model_ids).length > 0) ||
    (typeof model_ids === 'string' && model_ids.trim())
  );
  
  // Look for ML scores in multiple places
  const scoreNum = hasNum(ranker_raw?.confidence) ? Number(ranker_raw.confidence)
                   : hasNum(ranker_raw?.ranker_score) ? Number(ranker_raw.ranker_score)
                   : hasNum(ranker_score) ? Number(ranker_score)
                   : hasNum(fm.ranker_score) ? Number(fm.ranker_score)
                   : hasNum(row.ranker_score) ? Number(row.ranker_score)
                   : hasNum(row?.ranker_meta?.ranker_score) ? Number(row.ranker_meta.ranker_score)
                   : hasNum(row?.ranker_meta?.ranker_raw?.confidence) ? Number(row.ranker_meta.ranker_raw.confidence)
                   : null;
                   
  // Show ML data if we have ANY of: ML score, enhanced ML flags, model IDs, or ranker_meta
  // Be more lenient - if we have any ML-related data, show it
  const hasRealMLData = hasNum(scoreNum) || hasMLIndicators || hasModelIds || 
                        (oneRowRaw && (oneRowRaw.ranker_meta || oneRowRaw.ranker || oneRowRaw.ml_meta)) ||
                        (mRaw && (mRaw.ranker_meta || mRaw.ranker || mRaw.ml_meta));
  


  if (hasRealMLData) {
    // Normalize probs to sqli/xss/redirect and clamp to [0,1]
    const pickedProbs = {};
    for (const [k, v] of Object.entries(family_probs || {})) {
      const key = String(k).toLowerCase();
      if (["sqli", "xss", "redirect"].includes(key) && hasNum(v)) {
        pickedProbs[key] = Math.max(0, Math.min(1, Number(v)));
      }
    }
    if (!isNonEmptyObj(pickedProbs) && family_chosen) {
      pickedProbs[String(family_chosen).toLowerCase()] = 1.0;
    }

    // Determine the actual ML type based on the data
    let mlType = 'ML';
    if (String(used_path || '').toLowerCase() === 'enhanced_ml') {
      mlType = 'Enhanced ML';
    } else if (String(used_path || '').toLowerCase().includes('ml')) {
      mlType = 'ML';
    } else if (String(used_path || '').toLowerCase().includes('ranker')) {
      mlType = 'ML Ranker';
    } else if (enhancedFlag) {
      mlType = 'Enhanced ML';
    } else if (mlPredFlag) {
      mlType = 'ML Prediction';
    } else if (model_ids && typeof model_ids === 'object' && model_ids.enhanced_ml) {
      mlType = 'Enhanced ML';
    } else if (model_ids && typeof model_ids === 'object' && model_ids.ranker_path) {
      mlType = 'ML Ranker';
    }
    
    return {
      used_path: used_path || 'enhanced_ml',
      ranker_score: scoreNum,
      ranker_raw: ranker_raw || { confidence: scoreNum },
      family_probs: pickedProbs,
      family_chosen: family_chosen || (Object.keys(pickedProbs)[0] || null),
      model_ids: model_ids || { enhanced_ml: true },
      feature_dim_total: feature_dim_total || null,
      enhanced_ml: isEnhancedML,
      is_ml_prediction: true,
      _ml_type: mlType,
    };
  }

  // Synthesize heuristic fallback if we have signals
  const syn = synthesizeRankerMetaFromSignals(
    synthHints?.signals || {},
    synthHints?.family || null,
    Number(synthHints?.confidence || 0)
  );
  if (syn) {
    return {
      ...syn,
      used_path: used_path || 'heuristic',
      feature_dim_total: feature_dim_total || null,
      _ml_type: 'Heuristic',
    };
  }

  return {
    used_path: used_path || 'heuristic',
    ranker_score: 'Heuristic',
    model_ids: 'Heuristic',
    family_probs: {},
    feature_dim_total: feature_dim_total || null,
    _synthetic: true,
    _note: 'Heuristic fallback - no ML data',
    _ml_type: 'Heuristic',
  };
}

// Provide a simple Badge component used across the page
const Badge = ({ tone = 'slate', title, children }) => {
  const map = {
    indigo: 'bg-indigo-100 text-indigo-800',
    slate: 'bg-slate-100 text-slate-800',
    teal: 'bg-teal-100 text-teal-800',
    purple: 'bg-purple-100 text-purple-800',
    blue: 'bg-blue-100 text-blue-800',
    pink: 'bg-pink-100 text-pink-800',
    red: 'bg-red-100 text-red-800',
    amber: 'bg-amber-100 text-amber-800',
    green: 'bg-green-100 text-green-800',
  };
  return (
    <span className={cn('px-2 py-0.5 rounded text-xs whitespace-nowrap', map[tone] || map.slate)} title={title}>
      {children}
    </span>
  );
};

// Lightweight toggle pill button for filters/view switches
const TogglePill = ({
  active = false,
  onClick = () => {},
  children,
  toneActive = 'blue',
  toneInactive = 'gray',
  title,
}) => {
  const activeMap = {
    slate: 'bg-slate-700 text-white border-slate-700',
    blue: 'bg-blue-600 text-white border-blue-600',
    teal: 'bg-teal-600 text-white border-teal-600',
    purple: 'bg-purple-600 text-white border-purple-600',
    indigo: 'bg-indigo-600 text-white border-indigo-600',
    gray: 'bg-gray-700 text-white border-gray-700',
  };
  const inactiveMap = {
    slate: 'bg-slate-100 text-slate-800 border-slate-200',
    blue: 'bg-blue-100 text-blue-800 border-blue-200',
    teal: 'bg-teal-100 text-teal-800 border-teal-200',
    purple: 'bg-purple-100 text-purple-800 border-purple-200',
    indigo: 'bg-indigo-100 text-indigo-800 border-indigo-200',
    gray: 'bg-gray-100 text-gray-800 border-gray-200',
  };
  const cls = active
    ? activeMap[toneActive] || activeMap.blue
    : inactiveMap[toneInactive] || inactiveMap.gray;
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={cn('px-2 py-1 rounded-full text-xs border transition-colors', cls)}
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

/** === Collapsible section header component === */
const CollapsibleHeader = ({ title, expanded, onToggle, children, count }) => (
  <div className="flex items-center justify-between">
    <button
      onClick={onToggle}
      className="flex items-center gap-2 text-lg font-semibold hover:text-blue-600 transition-colors cursor-pointer"
    >
      <span className="text-lg">{expanded ? '▼' : '▶'}</span>
      <span>{title}</span>
      {count !== undefined && <span className="text-sm text-gray-500">({count})</span>}
    </button>
    {children}
  </div>
);

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

  // Extra filters / pagination
  const [methodFilter, setMethodFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  // Collapsible sections state
  const [endpointsExpanded, setEndpointsExpanded] = useState(true);
  const [capturedRequestsExpanded, setCapturedRequestsExpanded] = useState(false);

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

  // Group results by endpoint + parameter to show payloads together
  const groupedResults = useMemo(() => {
    const groups = {};
    
    filteredResults.forEach(result => {
      // Create a unique key for endpoint + parameter combination
      const groupKey = `${result.method}:${result.url.split('?')[0]}:${result.param}`;
      
      if (!groups[groupKey]) {
        groups[groupKey] = {
          method: result.method,
          baseUrl: result.url.split('?')[0],
          param: result.param,
          family: result.family,
          severity: result.severity,
          confidence: result.confidence,
          origin: result.origin,
          signals: result.signals,
          // Store all payloads for this endpoint+param combination
          payloads: []
        };
      }
      
      // Add this payload to the group
      groups[groupKey].payloads.push({
        payload: result.payload,
        ranker_score: (() => {
          // Try multiple sources for ML score in order of preference
          const sources = [
            result.ranker_meta?.confidence,
            result.ranker_meta?.ranker_score,
            result.ranker_meta?.ranker_raw?.confidence,
            result.ranker_meta?.ranker_raw?.ranker_score,
            result.ranker_score,
            result.confidence
          ];
          
          // Find first valid score
          for (const score of sources) {
            if (typeof score === 'number' && score >= 0 && score <= 1) {
              return score;
            }
          }
          return null;
        })(),
        family_probs: result.ranker_meta?.family_probs,
        used_path: result.ranker_meta?.used_path,
        ranker_meta: result.ranker_meta,
        // Include other result data for details
        originalResult: result
      });
    });
    
    // Convert to array and sort payloads by ML score (descending)
    return Object.values(groups).map(group => ({
      ...group,
      payloads: group.payloads.sort((a, b) => (b.ranker_score || 0) - (a.ranker_score || 0))
    }));
  }, [filteredResults]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(groupedResults.length / pageSize));
  const pageClamped = Math.min(page, totalPages);
  const start = (pageClamped - 1) * pageSize;
  const end = Math.min(groupedResults.length, start + pageSize);
  const pageRows = groupedResults.slice(start, end);

  // Summary tiles (based on visible/filtered results)
  const summary = useMemo(() => {
    const src = groupedResults;
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
        // Check for enhanced ML scores from payloads
        const mlPayloads = r.payloads.filter(p => p.ranker_score);
        if (mlPayloads.length > 0) {
          const avgScore = mlPayloads.reduce((sum, p) => sum + (p.ranker_score || 0), 0) / mlPayloads.length;
          avgRankerScore += avgScore;
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
  }, [groupedResults]);

  // Export helpers
  const copyJson = async () => {
    try {
      // Create a simplified version for copying
      const simplifiedResults = groupedResults.map(r => ({
        method: r.method,
        endpoint: r.baseUrl + "?" + r.param,
        parameter: r.param,
        vuln_family: r.family,
        payloads: r.payloads.map(p => ({
          payload: p.payload,
          ml_score: p.ranker_score,
          ml_type: p.used_path
        })),
        payload_score: r.confidence,
        payload_origin: r.origin,
        severity: r.severity,
        signals: r.signals
      }));
      await navigator.clipboard.writeText(JSON.stringify(simplifiedResults, null, 2));
      toast.success("Copied grouped results JSON");
    } catch {
      toast.error("Copy failed");
    }
  };
  const downloadCsv = () => {
    const rows = [
      [
        "method","endpoint","parameter","vuln_family","payload_count","top_ml_score","ml_type",
        "payload_score","payload_origin","severity","sql_error","boolean_sqli","time_sqli","xss_reflected","external_redirect",
      ],
      ...groupedResults.map((r) => [
        r.method, r.baseUrl + "?" + r.param, r.param || "", r.family || "", 
        r.payloads.length,
        r.payloads[0]?.ranker_score ? (r.payloads[0].ranker_score * 100).toFixed(1) + "%" : "",
        r.payloads[0]?.used_path || "",
        r.confidence, r.origin || "",
        r.severity || "",
        r.signals.sql_error ? "1" : "0",
        r.signals.boolean_sqli ? "1" : "0",
        r.signals.time_sqli ? "1" : "0",
        r.signals.xss_reflected ? "1" : "0",
        r.signals.external_redirect ? "1" : "0",
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
          a.download = `grouped_fuzzing_results_${new Date().toISOString().split('T')[0]}.csv`;
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
    <div className="max-w-full overflow-hidden p-4 space-y-4">
      <header className="flex items-center justify-between gap-2 flex-wrap">
        <h1 className="text-2xl font-semibold">Crawl &amp; Fuzz</h1>
        <div className="flex items-center gap-2 flex-wrap">
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
            className="border p-1 rounded min-w-[200px] max-w-full"
            placeholder="Optional bearer token for fuzz (Authorization: Bearer ...)"
            value={fuzzBearer}
            onChange={(e) => setFuzzBearer(e.target.value)}
          />
        </div>
      )}

      {/* Quick stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard label="Target" value={<span className="text-sm font-mono break-all">{targetUrl || "—"}</span>} />
        <StatCard label="Endpoints" value={counts.endpoints} />
        <StatCard label="Visible" value={counts.visible} />
        <StatCard label="Selected" value={counts.selected} />
        <StatCard label="Captured" value={counts.captured} />
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-2 items-center sticky top-0 z-20 bg-white/90 backdrop-blur border-b py-2 px-1 max-w-full">
        <button className="bg-purple-600 text-white px-4 py-2 rounded disabled:opacity-60 text-sm" onClick={onFuzzAll} disabled={!jobId || loadingFuzz} type="button">
          {loadingFuzz ? "Fuzzing…" : `Fuzz ALL (${engineMode === "core" ? "ML" : engineMode})`}
        </button>
        <button
          className="bg-blue-600 text-white px-4 py-2 rounded disabled:opacity-60 text-sm"
          onClick={onFuzzSelected}
          disabled={!jobId || loadingFuzz || selectedKeys.size === 0}
          type="button"
        >
          {`Fuzz Selected (${engineMode === "core" ? "ML" : engineMode})`}
        </button>
        <button className="bg-gray-800 text-white px-4 py-2 rounded disabled:opacity-60 text-sm" onClick={downloadReport} disabled={!jobId} type="button">
          Download Report
        </button>

        <div className="ml-auto flex items-center gap-2 flex-wrap">
          {/* Family */}
          <div className="flex items-center gap-1 flex-wrap">
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
            <input type="range" min="0" max="1" step="0.05" value={minConf} onChange={(e) => setMinConf(Number(e.target.value))} className="w-20" />
            <span className="text-xs font-mono">{minConf.toFixed(2)}</span>
          </div>

          {/* Signal toggles */}
          <div className="flex items-center gap-1 flex-wrap">
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
          <input className="border p-2 rounded min-w-[200px] max-w-full" placeholder="Search (URL, param, payload, origin…)" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <button className="border px-3 py-2 rounded text-sm" onClick={copyJson} title="Copy filtered JSON" type="button">Copy JSON</button>
          <button className="border px-3 py-2 rounded text-sm" onClick={downloadCsv} title="Download filtered CSV" type="button">CSV</button>



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
        <CollapsibleHeader
          title="Endpoints"
          expanded={endpointsExpanded}
          onToggle={() => setEndpointsExpanded(!endpointsExpanded)}
          count={filtered.length}
        >
          <div className="flex items-center gap-2 flex-wrap">
            <button className="border px-3 py-1.5 rounded text-sm" onClick={selectAllVisible} type="button">Select all (visible)</button>
            <button className="border px-3 py-1.5 rounded text-sm" onClick={() => selectTopNVisible(20)} title="Select top 20 visible by priority" type="button">Select top 20</button>
            <button className="border px-3 py-1.5 rounded text-sm" onClick={() => selectFamilyVisible("redirect")} type="button">Select redirects</button>
            <button className="border px-3 py-1.5 rounded text-sm" onClick={() => selectFamilyVisible("xss")} type="button">Select XSS</button>
            <button className="border px-3 py-1.5 rounded text-sm" onClick={() => selectFamilyVisible("sqli")} type="button">Select SQLi</button>
            <button className="border px-3 py-1.5 rounded text-sm" onClick={clearSelection} type="button">Clear</button>
          </div>
        </CollapsibleHeader>

        {endpointsExpanded && (
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
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm">{(ep.method || "").toUpperCase()}</span>
                        <a href={ep.url} target="_blank" rel="noreferrer" className="font-mono text-sm break-words underline decoration-dotted max-w-full">
                          {ep.url}
                        </a>
                      </div>
                      <div className="flex items-center justify-between mt-1">
                        <div className="flex items-center gap-2">
                        </div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <div className="flex items-center gap-1">
                            <span className="text-xs font-semibold text-blue-600">PRIO:</span>
                            <span className="text-sm font-mono font-bold bg-blue-100 text-blue-800 px-2 py-1 rounded">
                              {(ep._priority || 0).toFixed(2)}
                            </span>
                          </div>
                          <FamilyBadge fam={ep._family} />
                        </div>
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
        )}
      </section>

      {/* Captured requests */}
      <section className="space-y-2">
        <CollapsibleHeader
          title="Captured Requests"
          expanded={capturedRequestsExpanded}
          onToggle={() => setCapturedRequestsExpanded(!capturedRequestsExpanded)}
          count={captured.length}
        />
        {capturedRequestsExpanded && (
          <div className="border rounded max-h-80 overflow-auto">
            {captured.length === 0 ? (
              <div className="p-3 text-gray-500">No captured requests</div>
            ) : (
              captured.map((r, i) => (
                <div key={i} className="p-3 border-b">
                  <div className="font-mono text-sm break-words">
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
        )}
      </section>

      {/* Results summary strip + ML insights */}
      {results.length > 0 && (
        <section className="space-y-2">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
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
            <div className="flex items-end gap-1 sm:gap-2 h-16 overflow-x-auto">
              {summary.confBuckets.map((c, i) => {
                const lo = (i * 0.2).toFixed(1);
                const hi = ((i + 1) * 0.2).toFixed(1);
                return (
                  <div key={i} className="flex flex-col items-center min-w-[24px] sm:min-w-[32px]">
                    <div className="w-6 sm:w-8 bg-gray-300 rounded-t" style={{ height: `${Math.min(100, 8 + c * 6)}%` }} title={`${lo}–${hi}: ${c}`} />
                    <div className="text-[10px] font-mono mt-1">{lo}-{hi}</div>
                  </div>
                );
              })}
            </div>
          </div>
        </section>
      )}

      {/* Actual Results Table/Cards */}
      {results.length > 0 && (
        <section className="space-y-4">
                      <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold text-gray-800">🔍 Fuzzing Results (Grouped by Endpoint)</h2>
              <div className="text-sm text-gray-600 bg-gray-100 px-3 py-1 rounded-full">
                {groupedResults.length} endpoints, {groupedResults.reduce((sum, r) => sum + r.payloads.length, 0)} total payloads
              </div>
            </div>
          
          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-600">
                Page {pageClamped} of {totalPages} · Showing {start + 1}-{end} of {filteredResults.length}
              </div>
              <div className="flex items-center gap-2">
                <button
                  className="px-3 py-1 border rounded disabled:opacity-50"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={pageClamped <= 1}
                  type="button"
                >
                  Previous
                </button>
                <span className="px-3 py-1">{pageClamped}</span>
                <button
                  className="px-3 py-1 border rounded disabled:opacity-50"
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={pageClamped >= totalPages}
                  type="button"
                >
                  Next
                </button>
              </div>
            </div>
          )}

          {/* ML Debug Section - Show raw ML data */}
          <div className="border rounded-lg bg-yellow-50 p-4 mb-4">
            <h3 className="text-lg font-bold text-yellow-800 mb-3">🔍 ML Debug Section</h3>
            
            {/* Debug Info */}
            <div className="bg-white p-3 rounded border mb-4">
              <div className="text-sm font-semibold text-gray-700 mb-2">Debug Info:</div>
              <div className="text-xs text-gray-600 space-y-1">
                <div>Total Endpoints: {groupedResults.length}</div>
                <div>Total Payloads: {groupedResults.reduce((sum, r) => sum + r.payloads.length, 0)}</div>
                <div>ML Origin Results: {groupedResults.filter(r => r.origin === 'ml').length}</div>
                <div>Payloads with ML scores: {groupedResults.reduce((sum, r) => sum + r.payloads.filter(p => p.ranker_score).length, 0)}</div>
                <div>Payloads with family_probs: {groupedResults.reduce((sum, r) => sum + r.payloads.filter(p => p.family_probs).length, 0)}</div>
                <div>Total ranker_meta objects: {groupedResults.reduce((sum, r) => sum + r.payloads.filter(p => p.ranker_meta).length, 0)}</div>
                <div>ML scores found in: {(() => {
                  const sources = new Set();
                  groupedResults.forEach(r => {
                    r.payloads.forEach(p => {
                      if (p.ranker_meta) {
                        if (p.ranker_meta.confidence !== undefined) sources.add('confidence');
                        if (p.ranker_meta.ranker_score !== undefined) sources.add('ranker_score');
                        if (p.ranker_meta.ranker_raw?.confidence !== undefined) sources.add('ranker_raw.confidence');
                      }
                    });
                  });
                  return Array.from(sources).join(', ') || 'none';
                })()}</div>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {groupedResults.slice(0, 6).map((r, i) => {
                // Debug logging
                if (i === 0) {
                  console.log('🔍 First grouped result ML data:', {
                    origin: r.origin,
                    payloads_count: r.payloads.length,
                    first_payload: r.payloads[0],
                    has_ranker_meta: r.payloads.some(p => !!p.ranker_meta),
                    ranker_scores: r.payloads.map(p => p.ranker_score),
                    ranker_meta_keys: r.payloads[0]?.ranker_meta ? Object.keys(r.payloads[0].ranker_meta) : [],
                    raw_ranker_meta: r.payloads[0]?.ranker_meta
                  });
                }
                return (
                <div key={i} className="bg-white p-3 rounded border">
                  <div className="text-xs font-mono text-gray-600 mb-2">
                    {r.method} {r.baseUrl}?{r.param}
                  </div>
                  
                  {/* Group Summary */}
                  <div className="bg-blue-50 p-2 rounded border mb-2">
                    <div className="text-xs font-semibold text-blue-800">Group Summary:</div>
                    <div className="text-xs text-blue-700">
                      {r.payloads.length} payloads, {r.payloads.filter(p => p.ranker_score).length} with ML scores
                    </div>
                  </div>
                  
                  {/* Payloads ML Data */}
                  <div className="space-y-2 text-xs">
                    {r.payloads.slice(0, 3).map((payload, idx) => (
                      <div key={idx} className="bg-gray-100 p-2 rounded">
                        <div className="font-semibold text-gray-700">Payload {idx + 1}:</div>
                        <div className="text-gray-600 mb-1">
                          {payload.payload ? payload.payload.slice(0, 30) + "..." : "—"}
                        </div>
                        <div className="text-gray-600">
                          ML Score: {payload.ranker_score ? (payload.ranker_score * 100).toFixed(1) + "%" : "None"}
                        </div>
                      </div>
                    ))}
                    {r.payloads.length > 3 && (
                      <div className="text-xs text-gray-500 text-center">
                        +{r.payloads.length - 3} more payloads
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
            </div>
          </div>

          {/* Redesigned Results Table - One endpoint + parameter per row */}
          <div className="border rounded-lg overflow-hidden bg-white">
            {/* Summary Row */}
            <div className="bg-blue-50 border-b border-blue-200 p-3">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-4">
                  <span className="text-blue-800 font-medium">📊 Summary:</span>
                  <span className="text-blue-700">Endpoints: {groupedResults.length}</span>
                  <span className="text-blue-700">Total Payloads: {groupedResults.reduce((sum, r) => sum + r.payloads.length, 0)}</span>
                  <span className="text-blue-700">ML Results: {groupedResults.filter(r => r.origin === 'ml').length}</span>
                  <span className="text-blue-700">High Confidence: {groupedResults.filter(r => r.confidence >= 0.8).length}</span>
                </div>
                <div className="text-blue-700 font-medium">
                  {groupedResults.length} unique endpoints
                </div>
              </div>
            </div>
            
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gradient-to-r from-gray-50 to-blue-50 border-b border-gray-200">
                  <tr>
                    <th className="text-left p-3 font-semibold text-gray-700">
                      <SortHeader fieldKey="method" label="🔒 Method" current={sortBy} set={setSortBy} />
                    </th>
                    <th className="text-left p-3 font-semibold text-gray-700">
                      <SortHeader fieldKey="url" label="🌐 Endpoint + Parameter" current={sortBy} set={setSortBy} />
                    </th>
                    <th className="text-left p-3 font-semibold text-gray-700">
                      <SortHeader fieldKey="family" label="⚠️ Vulnerability Family" current={sortBy} set={setSortBy} />
                    </th>
                    <th className="text-left p-3 font-semibold text-gray-700">
                      <SortHeader fieldKey="conf" label="🎯 All Payloads + ML Scores" current={sortBy} set={setSortBy} />
                    </th>
                    <th className="text-left p-3 font-semibold text-gray-700">
                      <SortHeader fieldKey="origin" label="📊 Origin & Confidence" current={sortBy} set={setSortBy} />
                    </th>
                    <th className="text-left p-3 font-semibold text-gray-700">🔍 Details</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((r, i) => {
                    const isExpanded = expanded.has(rowKey(r));
                    return (
                      <tr key={rowKey(r)} className={cn(
                        "border-b hover:bg-gray-50 transition-colors",
                        compact ? "text-xs" : "",
                        i % 2 === 0 ? "bg-white" : "bg-gray-50"
                      )}>
                        {/* Method */}
                        <td className="p-3">
                          <span className={cn(
                            "font-mono px-2 py-1 rounded text-xs font-semibold border shadow-sm",
                            r.method === "GET" ? "bg-green-100 text-green-800 border-green-200" :
                            r.method === "POST" ? "bg-blue-100 text-blue-800 border-blue-200" :
                            r.method === "PUT" ? "bg-yellow-100 text-yellow-800 border-yellow-200" :
                            r.method === "DELETE" ? "bg-red-100 text-red-800 border-red-200" :
                            "bg-gray-100 text-gray-800 border-gray-200"
                          )} title={`HTTP ${r.method} method`}>
                            {r.method}
                          </span>
                        </td>
                        
                        {/* Endpoint + Parameter */}
                        <td className="p-3">
                          <div className="space-y-1">
                            <div className="font-mono text-blue-600 break-all max-w-xs">
                              {r.baseUrl}?{r.param}
                            </div>
                            <div className="text-xs text-gray-600">
                              <span className="font-medium">Param:</span>{" "}
                              <span className="font-mono bg-gray-100 px-1.5 py-0.5 rounded">
                                {r.param || "—"}
                              </span>
                            </div>
                          </div>
                        </td>
                        
                        {/* Vulnerability Family */}
                        <td className="p-3">
                          <div className="space-y-2">
                            {/* Primary Family Badge */}
                            <div className="flex items-center gap-2">
                              <FamilyBadge fam={r.family} />
                              <SeverityBadge sev={r.severity} />
                            </div>
                            
                            {/* ML Family Probabilities - Simplified */}
                            {r.payloads[0]?.family_probs && Object.keys(r.payloads[0].family_probs).length > 0 ? (
                              <div className="bg-blue-50 p-2 rounded border">
                                <div className="text-xs font-semibold text-blue-800 mb-1">ML Confidence:</div>
                                {Object.entries(r.payloads[0].family_probs)
                                  .sort(([,a], [,b]) => b - a)
                                  .slice(0, 1) // Show only top prediction
                                  .map(([family, prob]) => (
                                    <div key={family} className="text-xs">
                                      <span className="font-medium text-blue-700">
                                        {family.toUpperCase()}: {(prob * 100).toFixed(1)}%
                                      </span>
                                    </div>
                                  ))}
                              </div>
                            ) : null}
                          </div>
                        </td>
                        
                        {/* Payload + ML Score */}
                        <td className="p-3">
                          <div className="space-y-2">
                            <div className="text-xs font-semibold text-gray-700 mb-2">
                              {r.payloads.length} Payload{r.payloads.length !== 1 ? 's' : ''} Tested
                            </div>
                            
                            {/* Payloads List */}
                            <div className="space-y-2 max-h-32 overflow-y-auto">
                              {r.payloads.map((payload, idx) => (
                                <div key={idx} className="bg-gray-50 p-2 rounded border">
                                  {/* Payload Text */}
                                  <div className="text-xs font-semibold text-gray-700 mb-1">Payload {idx + 1}:</div>
                                  <div className="font-mono text-xs text-gray-800 break-all max-w-xs mb-2">
                                    {payload.payload && payload.payload.length > 25 
                                      ? payload.payload.slice(0, 25) + "..." 
                                      : payload.payload || "—"}
                                  </div>
                                  
                                  {/* ML Score */}
                                  {payload.ranker_score ? (
                                    <div className="bg-green-50 p-1.5 rounded border">
                                      <div className="text-xs font-semibold text-green-800">ML Score:</div>
                                      <div className="text-sm font-bold text-green-700">
                                        {(payload.ranker_score * 100).toFixed(1)}%
                                      </div>
                                      <div className="text-xs text-green-600">
                                        {payload.used_path === 'enhanced_ml' ? 'Enhanced ML' : 'ML'}
                                      </div>
                                    </div>
                                  ) : (
                                    <div className="bg-gray-50 p-1.5 rounded border">
                                      <div className="text-xs text-gray-500">No ML Score</div>
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        </td>
                        
                        {/* Payload Recommendation Score */}
                        <td className="p-3">
                          <div className="space-y-3">
                            {/* Confidence Meter */}
                            <div className="space-y-1">
                              <div className="text-xs text-gray-500 font-medium">Confidence</div>
                              <ConfMeter v={r.confidence} />
                            </div>
                            
                            {/* Origin Badge */}
                            <div className="text-center">
                              <OriginBadge origin={r.origin} />
                            </div>
                            

                          </div>
                        </td>
                        
                        {/* Details Button */}
                        <td className="p-3">
                          <button
                            onClick={() => toggleExpand(rowKey(r))}
                            className={cn(
                              "px-3 py-1.5 rounded text-xs font-medium transition-all duration-200 border",
                              isExpanded 
                                ? "bg-blue-100 text-blue-800 border-blue-300 shadow-sm" 
                                : "bg-white text-gray-700 border-gray-300 hover:bg-blue-50 hover:border-blue-200 hover:text-blue-700"
                            )}
                            type="button"
                            title={isExpanded ? "Hide detailed information" : "Show detailed information"}
                          >
                            {isExpanded ? "▼ Hide" : "▶ Details"}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Expanded Details Rows */}
          {pageRows.map((r, i) => {
            const isExpanded = expanded.has(rowKey(r));
            if (!isExpanded) return null;
            
                         return (
               <div key={`details-${rowKey(r)}`} className="border rounded-lg bg-gradient-to-br from-gray-50 to-blue-50 p-4 space-y-4 shadow-sm">
                 <div className="flex items-center justify-between border-b border-gray-200 pb-3">
                   <h4 className="font-semibold text-gray-800 flex items-center gap-2">
                     <span className="text-blue-600">📊</span>
                     Detailed Results for {r.method} {r.baseUrl}?{r.param}
                   </h4>
                   <button
                     onClick={() => toggleExpand(rowKey(r))}
                     className="text-gray-500 hover:text-gray-700 hover:bg-white rounded-full p-1 transition-colors"
                     type="button"
                     title="Close details"
                   >
                     ✕
                   </button>
                 </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {/* ML Details */}
                  <div className="space-y-2">
                    <h5 className="font-medium text-gray-700">ML Analysis</h5>
                    <div className="bg-white p-3 rounded border space-y-2">
                      {r.payloads.some(p => p.family_probs || p.ranker_score) ? (
                        <>
                          {r.payloads[0]?.family_probs && Object.keys(r.payloads[0].family_probs).length > 0 && (
                            <div>
                              <div className="text-xs text-gray-500">Top Family Probabilities</div>
                              <FamilyProbsBar probs={r.payloads[0].family_probs} />
                            </div>
                          )}
                          <div className="text-xs space-y-1">
                            <div><span className="text-gray-500">Top ML Score:</span> {(() => {
                              const topPayload = r.payloads.find(p => p.ranker_score) || r.payloads[0];
                              const sc = topPayload?.ranker_score;
                              return typeof sc === 'number' ? (sc * 100).toFixed(1) + '%' : '—';
                            })()}</div>
                            <div><span className="text-gray-500">ML Type:</span> {r.payloads[0]?.used_path || '—'}</div>
                            <div><span className="text-gray-500">Payloads with ML:</span> {r.payloads.filter(p => p.ranker_score).length}/{r.payloads.length}</div>
                          </div>
                        </>
                      ) : (
                        <span className="text-gray-400 text-xs">No ML data available</span>
                      )}
                    </div>
                  </div>
                  
                  {/* Signals */}
                  <div className="space-y-2">
                    <h5 className="font-medium text-gray-700">Detection Signals</h5>
                    <div className="bg-white p-3 rounded border">
                      <div className="flex flex-wrap gap-1">
                        {r.signals.sql_error && <Badge tone="red">SQL Error</Badge>}
                        {r.signals.boolean_sqli && <Badge tone="blue">Boolean SQLi</Badge>}
                        {r.signals.time_sqli && <Badge tone="blue">Time SQLi</Badge>}
                        {r.signals.xss_reflected && <Badge tone="pink">XSS Reflected</Badge>}
                        {r.signals.external_redirect && <Badge tone="purple">External Redirect</Badge>}
                        {!r.signals.sql_error && !r.signals.boolean_sqli && !r.signals.time_sqli && 
                         !r.signals.xss_reflected && !r.signals.external_redirect && (
                          <span className="text-gray-400 text-xs">No strong signals detected</span>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  {/* Delta Information */}
                  <div className="space-y-2">
                    <h5 className="font-medium text-gray-700">Response Changes</h5>
                    <div className="bg-white p-3 rounded border">
                      <DeltaCell d={r.delta} />
                    </div>
                  </div>
                </div>
                
                {/* All Payloads */}
                <div className="space-y-2">
                  <h5 className="font-medium text-gray-700">All Tested Payloads ({r.payloads.length})</h5>
                  <div className="bg-white p-3 rounded border space-y-3">
                    {r.payloads.map((payload, idx) => (
                      <div key={idx} className="border-b border-gray-100 pb-2 last:border-b-0">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-medium text-gray-700">Payload {idx + 1}</span>
                          {payload.ranker_score && (
                            <span className="text-xs font-bold text-green-600">
                              ML Score: {(payload.ranker_score * 100).toFixed(1)}%
                            </span>
                          )}
                        </div>
                        <pre className="font-mono text-xs bg-gray-50 p-2 rounded overflow-auto max-h-20">
                          {payload.payload || "—"}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
                
                {/* Additional Context */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <h5 className="font-medium text-gray-700">Request Details</h5>
                    <div className="bg-white p-3 rounded border space-y-1 text-xs">
                      <div><span className="text-gray-500">Method:</span> {r.method}</div>
                      <div><span className="text-gray-500">Parameter:</span> {r.param || '—'}</div>
                      <div><span className="text-gray-500">Origin:</span> <OriginBadge origin={r.origin} /></div>
                      <div><span className="text-gray-500">Severity:</span> <SeverityBadge sev={r.severity} /></div>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <h5 className="font-medium text-gray-700">Response Analysis</h5>
                    <div className="bg-white p-3 rounded border space-y-1 text-xs">
                      <div><span className="text-gray-500">Confidence:</span> {r.confidence.toFixed(3)}</div>
                      {r.delta?.status_changed && <div><span className="text-gray-500">Status Changed:</span> Yes</div>}
                      {r.delta?.len_delta && <div><span className="text-gray-500">Length Δ:</span> {r.delta.len_delta}</div>}
                      {r.delta?.ms_delta && <div><span className="text-gray-500">Time Δ:</span> {r.delta.ms_delta}ms</div>}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}

          {/* Bottom Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center">
              <div className="flex items-center gap-2">
                <button
                  className="px-3 py-1 border rounded disabled:opacity-50"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={pageClamped <= 1}
                  type="button"
                >
                  Previous
                </button>
                <span className="px-3 py-1">{pageClamped} of {totalPages}</span>
                <button
                  className="px-3 py-1 border rounded disabled:opacity-50"
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={pageClamped >= totalPages}
                  type="button"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}


