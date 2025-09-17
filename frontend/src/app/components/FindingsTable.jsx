"use client";
import { useMemo, useState } from "react";
import { TriangleAlert, ShieldCheck, Database, Link as LinkIcon, ChevronDown, ChevronRight } from "lucide-react";
import { humanizeWhyCodes } from "../../lib/microcopy";

const famIcon = (f) => f==="xss" ? <TriangleAlert className="icon" /> : f==="sqli" ? <Database className="icon" /> : <LinkIcon className="icon" />;

const badge = (t) => <span className={`px-2 py-0.5 rounded text-xs ${t==="positive"?"bg-green-100 text-green-700":t==="suspected"?"bg-amber-100 text-amber-700":t==="error"?"bg-red-100 text-red-700":"bg-zinc-100 text-zinc-700"}`}>{t}</span>;

// Use centralized microcopy mapping from lib/microcopy.js

// Provenance chips
const ProvenanceChips = ({ why }) => {
  const chips = [];
  if (why?.includes("probe_proof")) {
    chips.push(
      <span key="probe" className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-700" title="Found by low-cost probe (oracle).">
        Probe
      </span>
    );
  }
  if (why?.includes("ml_ranked")) {
    chips.push(
      <span key="ml" className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700" title="Ranked by ML and confirmed by injection.">
        ML+Inject
      </span>
    );
  }
  return <div className="flex gap-1">{chips}</div>;
};

// P_cal badge
const PCalBadge = ({ p_cal }) => {
  if (p_cal == null) return null;
  return (
    <span className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700 font-mono">
      p={p_cal.toFixed(2)}
    </span>
  );
};

// Proof Type badge
const ProofTypeBadge = ({ vuln_proof }) => {
  if (!vuln_proof?.type) return null;
  const typeMap = {
    "xss_reflection": "XSS",
    "redirect_header": "Redirect", 
    "sqli_error": "SQLi",
    "other": "Other"
  };
  return (
    <span className="px-2 py-0.5 rounded text-xs bg-red-100 text-red-700" title={`Proof: ${vuln_proof.type}`}>
      Proof: {typeMap[vuln_proof.type] || vuln_proof.type}
    </span>
  );
};

// Decision Source badge (shows probe ML)
const DecisionSourceBadge = ({ family, xss_context_source, sqli_dialect_source }) => {
  
  // Map probe ML sources to more specific descriptions with model names
  const getProbeMLSource = (family, xssContextSource, sqliDialectSource) => {
    if (family === "xss") {
      if (xssContextSource === "ml") {
        return "XSS Context Classifier";
      } else if (xssContextSource === "rule") {
        return "XSS Rules";
      } else {
        return "XSS Probe";
      }
    } else if (family === "sqli") {
      if (sqliDialectSource === "ml" || (typeof sqliDialectSource === 'string' && sqliDialectSource.startsWith("ml"))) {
        return "SQLi Dialect Classifier";
      } else if (sqliDialectSource === "rule") {
        return "SQLi Rules";
      } else {
        return "SQLi Probe";
      }
    } else if (family === "redirect") {
      return "Redirect Probe";
    }
    return "Probe";
  };
  
  // For Decision Source, we want to show probe ML, not payload ranking ML
  const specificSource = getProbeMLSource(family, xss_context_source, sqli_dialect_source);
  
  const colors = {
    "XSS Context Classifier": "bg-purple-100 text-purple-700",
    "XSS Rules": "bg-blue-100 text-blue-700",
    "XSS Probe": "bg-green-100 text-green-700",
    "SQLi Dialect Classifier": "bg-purple-100 text-purple-700", 
    "SQLi Rules": "bg-blue-100 text-blue-700",
    "SQLi Probe": "bg-green-100 text-green-700",
    "Redirect Probe": "bg-yellow-100 text-yellow-700",
    "Probe": "bg-gray-100 text-gray-700"
  };
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs ${colors[specificSource] || "bg-gray-100 text-gray-700"}`}
      title={`Probe ML source: ${specificSource}`}
    >
      {specificSource}
    </span>
  );
};

// Rank Source badge (shows payload ranking ML - for Evidence Modal)
const RankSourceBadge = ({ rank_source, family, model_tag }) => {
  if (!rank_source) return null;
  
  // Map rank_source to more specific descriptions
  const getSpecificSource = (source, family, modelTag) => {
    if (source === "ml") {
      if (family === "xss") {
        return modelTag === "family_xss" ? "XSS Ranker" : "XSS ML";
      } else if (family === "sqli") {
        return modelTag === "family_sqli" ? "SQLi Ranker" : "SQLi ML";
      } else if (family === "redirect") {
        return modelTag === "family_redirect" ? "Redirect Ranker" : "Redirect ML";
      }
      return "ML Ranker";
    } else if (source === "probe_only") {
      return "Probe Only";
    } else if (source === "defaults") {
      return "Default Payloads";
    }
    return source;
  };
  
  const specificSource = getSpecificSource(rank_source, family, model_tag);
  
  const colors = {
    "ml": "bg-purple-100 text-purple-700",
    "probe_only": "bg-blue-100 text-blue-700", 
    "defaults": "bg-gray-100 text-gray-700"
  };
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs ${colors[rank_source] || "bg-gray-100 text-gray-700"}`}
      title={`Ranking source: ${rank_source}${model_tag ? ` (${model_tag})` : ''}`}
    >
      {specificSource}
    </span>
  );
};

// ML chip with honest state
const MLChip = ({ rank_source, ml_proba, ml }) => {
  // Use ML state if available, otherwise fallback to rank_source
  const rankerActive = ml?.ranker_active ?? (rank_source === "ml");
  const classifierUsed = ml?.classifier_used ?? (rank_source === "ml" && ml_proba != null);
  
  // Only show p_cal when classifier actually ran
  if (rankerActive && classifierUsed && ml_proba != null) {
    return (
      <span 
        className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700 font-mono"
        title="ML prioritized payload; decision from probe proof."
      >
        ML p={ml_proba.toFixed(2)}
      </span>
    );
  } else if (!rankerActive) {
    return (
      <span 
        className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700"
        title="ML ranker inactive; using default payloads."
      >
        Rank: defaults • ML inactive
      </span>
    );
  } else if (rankerActive && !classifierUsed) {
    // Ranker active but classifier didn't run - don't show p_cal
    return (
      <span 
        className="px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700"
        title="ML ranker active but classifier not used."
      >
        Rank: model
      </span>
    );
  }
  
  if (rank_source === "ctx_pool") {
    return (
      <span 
        className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-700 font-mono"
        title="Context-aware payload pool used for XSS"
      >
        CTX
      </span>
    );
  }
  
  return null;
};

// SQLi dialect badge
const SQLiDialectBadge = ({ family, result }) => {
  if (family !== "sqli") return null;
  
  if (!result?.sqli_dialect) {
    return (
      <span className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700" title="No SQLi dialect detected">
        —
      </span>
    );
  }
  
  const dialect = result.sqli_dialect;
  const confident = result.sqli_dialect_source === "ml" && result.sqli_dialect_ml_proba > 0.7;
  
  const dialectColors = {
    "mysql": "bg-blue-100 text-blue-700",
    "postgresql": "bg-green-100 text-green-700", 
    "mssql": "bg-red-100 text-red-700",
    "sqlite": "bg-yellow-100 text-yellow-700",
    "oracle": "bg-purple-100 text-purple-700",
    "unknown": "bg-gray-100 text-gray-700"
  };
  
  const colorClass = dialectColors[dialect] || "bg-gray-100 text-gray-700";
  const confidenceIcon = confident ? "✓" : "?";
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs ${colorClass}`}
      title={`SQLi dialect: ${dialect} (${confident ? 'confident' : 'uncertain'})`}
    >
      {dialect} {confidenceIcon}
    </span>
  );
};

// XSS Context/Escaping chips
const XSSContextChips = ({ family, xss_context, xss_escaping, xss_context_source, xss_context_ml_proba }) => {
  if (family !== "xss" || !xss_context || !xss_escaping) return null;
  
  const contextMap = {
    "html_body": "html",
    "attr": "attr", 
    "js_string": "js",
    "url": "url",
    "css": "css",
    "unknown": "?"
  };
  
  const escapingMap = {
    "raw": "raw",
    "html": "html",
    "url": "url", 
    "js": "js",
    "unknown": "?"
  };
  
  return (
    <div className="flex gap-1 items-center">
      <span 
        className="px-2 py-0.5 rounded text-xs bg-orange-100 text-orange-700 font-mono"
        title={`XSS Context: ${xss_context}, Escaping: ${xss_escaping}`}
      >
        {contextMap[xss_context] || "?"}/{escapingMap[xss_escaping] || "?"}
      </span>
    </div>
  );
};

// SQLi Dialect chip
const SQLiDialectChip = ({ family, telemetry }) => {
  if (family !== "sqli") return null;
  
  if (!telemetry?.sqli_dialect_hint) {
    return (
      <span className="px-2 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-700" title="No SQLi dialect detected">
        —
      </span>
    );
  }
  
  const dialect = telemetry.sqli_dialect_hint;
  const confident = telemetry.sqli_dialect_confident;
  
  const dialectMap = {
    "mysql": "MySQL",
    "postgresql": "PostgreSQL", 
    "mssql": "SQL Server",
    "sqlite": "SQLite"
  };
  
  return (
    <span 
      className={`px-2 py-0.5 rounded text-xs font-mono ${
        confident 
          ? "bg-green-100 text-green-700" 
          : "bg-yellow-100 text-yellow-700"
      }`}
      title={`Detected Dialect: ${dialect}${confident ? " (confident)" : " (weak signal)"}`}
    >
      {dialectMap[dialect] || dialect}
    </span>
  );
};

// Microcopy display
const Microcopy = ({ why }) => {
  const messages = humanizeWhyCodes(why || []);
  if (!messages.length) return null;
  return (
    <div className="text-xs text-gray-500 mt-1">
      {messages.join(" ")}
    </div>
  );
};

export default function FindingsTable({ results=[], onView }) {
  if (!results.length) return <div className="text-sm text-zinc-500 p-4">No results yet.</div>;

  // Quick filters and sorting state
  const [familyFilter, setFamilyFilter] = useState('all'); // all|xss|sqli|redirect
  const [sourceFilter, setSourceFilter] = useState('all'); // all|probe|ml
  const [onlyConfident, setOnlyConfident] = useState(false); // ML p>0.7
  const [dialectFilter, setDialectFilter] = useState('all'); // all|mysql|postgresql|mssql|sqlite|oracle|unknown
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState('cvss'); // cvss|family|proba|target
  const [sortDir, setSortDir] = useState('desc'); // asc|desc

  const normalized = useMemo(() => {
    // Normalize a few fields up-front to simplify filtering/sorting
    return (results || []).map(r => {
      const sqliSrc = (r.sqli_dialect_source || '').toLowerCase();
      const sqliMl = sqliSrc.startsWith('ml');
      const sqliProba = typeof r.sqli_dialect_ml_proba === 'number' ? r.sqli_dialect_ml_proba : null;
      const cvssScore = r?.cvss?.base ?? r?.cvss?.score ?? r?.cvss ?? 0;
      const family = (r.family || '').toLowerCase();
      const url = r?.target?.url || r?.url || '';
      const param = r?.target?.param || r?.param || '';
      const paramIn = r?.target?.param_in || r?.param_in || '';
      const text = `${family} ${url} ${paramIn}:${param} ${(r.why||[]).join(' ')} ${(r.sqli_dialect||'')}`.toLowerCase();
      return {
        ...r,
        _cvss: Number(cvssScore) || 0,
        _sqliMl: sqliMl,
        _sqliConfident: sqliMl && (Number(sqliProba) > 0.7),
        _sqliProba: sqliProba,
        _text: text,
      };
    });
  }, [results]);

  const filtered = useMemo(() => {
    return normalized.filter(r => {
      // family filter
      if (familyFilter !== 'all' && r.family !== familyFilter) return false;
      // source filter (probe vs ml) uses dialect for SQLi and xss_context_source for XSS
      if (sourceFilter !== 'all') {
        const xssSrc = (r.xss_context_source || '').toLowerCase();
        const sqliSrc = (r.sqli_dialect_source || '').toLowerCase();
        const isProbe = (r.rank_source === 'probe_only') || (!xssSrc && !sqliSrc) || (r.family === 'sqli' && !sqliSrc);
        const isMl = (xssSrc === 'ml') || sqliSrc.startsWith('ml') || r.rank_source === 'ml';
        if (sourceFilter === 'probe' && !isProbe) return false;
        if (sourceFilter === 'ml' && !isMl) return false;
      }
      // confident ML filter (applies to both XSS and SQLi)
      if (onlyConfident) {
        const xssConf = (r.xss_context_source === 'ml') && (Number(r.xss_context_ml_proba) > 0.7);
        const sqliConf = r._sqliConfident;
        if (!(xssConf || sqliConf)) return false;
      }
      // dialect filter (only when family is sqli)
      if (dialectFilter !== 'all' && r.family === 'sqli') {
        const d = (r.sqli_dialect || 'unknown').toLowerCase();
        if (d !== dialectFilter) return false;
      }
      // text search
      if (search && !r._text.includes(search.toLowerCase())) return false;
      return true;
    });
  }, [normalized, familyFilter, sourceFilter, onlyConfident, dialectFilter, search]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a,b) => {
      const dir = sortDir === 'asc' ? 1 : -1;
      if (sortKey === 'cvss') return dir * ((a._cvss||0) - (b._cvss||0));
      if (sortKey === 'family') return dir * String(a.family||'').localeCompare(String(b.family||''));
      if (sortKey === 'proba') return dir * ((Number(a._sqliProba||a.xss_context_ml_proba||0)) - (Number(b._sqliProba||b.xss_context_ml_proba||0)));
      if (sortKey === 'target') return dir * String(a?.target?.url||a.url||'').localeCompare(String(b?.target?.url||b.url||''));
      return 0;
    });
    return arr.reverse(); // because above diff is a-b; then reverse to apply desc default
  }, [filtered, sortKey, sortDir]);

  // Group results by decision
  const grouped = results.reduce((acc, result) => {
    const decision = result.decision;
    if (!acc[decision]) acc[decision] = [];
    acc[decision].push(result);
    return acc;
  }, {});

  const [expandedSections, setExpandedSections] = useState({
    positive: true,
    clean: true,
    na: false
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const renderResultRow = (result, index) => (
    <tr key={index} className="border-t">
      <td className="p-2 flex items-center gap-2">
        {famIcon(result.family)}
        <span className="uppercase text-xs">{result.family}</span>
      </td>
      <td className="p-2 break-all">
        <div>{result.target?.method || result.method} {result.target?.url || result.url}</div>
        <Microcopy why={result.why} />
        {result.error_message && (
          <div className="mt-1 text-xs text-red-600 bg-red-50 px-2 py-1 rounded">
            Error: {result.error_message}
          </div>
        )}
      </td>
      <td className="p-2">
        {(() => {
          // Fallback order: param_in:param -> header:location for redirect -> none:none
          const paramIn = result.target?.param_in || result.param_in;
          const param = result.target?.param || result.param;
          const hasValidParams = paramIn && param && 
                                 paramIn !== 'none' && param !== 'none' &&
                                 paramIn !== '' && param !== '';
          
          if (hasValidParams) {
            return `${paramIn}:${param}`;
          } else if (result.family === 'redirect') {
            return 'header:location';
          } else {
            return <span className="text-gray-500">none:none</span>;
          }
        })()}
      </td>
      <td className="p-2">
        <div className="space-y-1">
          {badge(result.decision)}
          <ProvenanceChips why={result.why} />
          <ProofTypeBadge vuln_proof={result.vuln_proof} />
          <XSSContextChips 
            family={result.family} 
            xss_context={result.xss_context} 
            xss_escaping={result.xss_escaping}
            xss_context_source={result.xss_context_source}
            xss_context_ml_proba={result.xss_context_ml_proba}
          />
          <SQLiDialectChip 
            family={result.family} 
            telemetry={result.telemetry}
          />
          {/* Rank source chip to show payload prioritization origin */}
          {result.rank_source && (
            <span className={`px-2 py-0.5 rounded text-xs ${result.rank_source==='ml' ? 'bg-purple-100 text-purple-700' : result.rank_source==='ctx_pool' ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'}`} title={`Ranking source: ${result.rank_source}`}>
              {result.rank_source === 'ml' ? 'Rank: model' : result.rank_source === 'ctx_pool' ? 'Rank: ctx_pool' : 'Rank: defaults'}
            </span>
          )}
        </div>
      </td>
      <td className="p-2">
        <DecisionSourceBadge 
          family={result.family}
          xss_context_source={result.xss_context_source}
          sqli_dialect_source={result.sqli_dialect_source}
        />
      </td>
      <td className="p-2 text-right tabular-nums">
        {result.family === "xss" && result.xss_context_source === "ml" && result.xss_context_ml_proba ? 
          `${Math.round(result.xss_context_ml_proba * 100)}%` :
          result.family === "sqli" && (result.sqli_dialect_source === "ml" || (typeof result.sqli_dialect_source === 'string' && result.sqli_dialect_source.startsWith("ml"))) && result.sqli_dialect_ml_proba != null ?
          `${Math.round(result.sqli_dialect_ml_proba * 100)}%` :
          result.ml?.classifier_used && result.ml_proba != null ? result.ml_proba.toFixed(2) : "—"}
      </td>
      <td className="p-2">
        <SQLiDialectBadge family={result.family} result={result} />
      </td>
      <td className="p-2 font-semibold">
        {result.cvss?.base ?? "—"}
      </td>
      <td className="p-2 text-right">
        <button 
          onClick={()=>onView?.(result.evidence_id)} 
          className="px-3 py-1 rounded bg-zinc-900 text-white hover:bg-zinc-800"
        >
          Evidence
        </button>
      </td>
    </tr>
  );

  const renderSection = (title, results, sectionKey, defaultExpanded = true) => {
    const isExpanded = expandedSections[sectionKey] ?? defaultExpanded;
    const count = results.length;
    
    return (
      <div key={sectionKey} className="mb-4">
        <button
          onClick={() => toggleSection(sectionKey)}
          className="flex items-center gap-2 text-sm font-semibold text-gray-700 mb-2 hover:text-gray-900"
        >
          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          {title} ({count})
        </button>
        
        {isExpanded && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-zinc-500 sticky top-0 bg-white">
                  <th className="p-2 cursor-pointer" onClick={()=>{setSortKey('family'); setSortDir(d=>d==='asc'?'desc':'asc')}}>Family</th>
                  <th className="p-2 cursor-pointer" onClick={()=>{setSortKey('target'); setSortDir(d=>d==='asc'?'desc':'asc')}}>Target</th>
                  <th className="p-2">Param</th>
                  <th className="p-2">Decision</th>
                  <th className="p-2">Decision Source</th>
                  <th className="p-2 cursor-pointer" onClick={()=>{setSortKey('proba'); setSortDir(d=>d==='asc'?'desc':'asc')}}>ML Proba</th>
                  <th className="p-2">SQLi Dialect</th>
                  <th className="p-2 cursor-pointer" onClick={()=>{setSortKey('cvss'); setSortDir(d=>d==='asc'?'desc':'asc')}}>CVSS</th>
                  <th className="p-2"></th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((result, index) => renderResultRow(result, index))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  };

  // Quick filter bar
  const FilterBar = () => (
    <div className="flex flex-wrap gap-2 items-center p-2 bg-gray-50 rounded mb-3">
      <span className="text-xs text-gray-600">Filter:</span>
      {['all','xss','sqli','redirect'].map(f => (
        <button key={f} onClick={()=>setFamilyFilter(f)} className={`px-2 py-0.5 rounded text-xs ${familyFilter===f?'bg-zinc-900 text-white':'bg-white text-gray-700 border'}`}>{f}</button>
      ))}
      <span className="ml-2 text-xs text-gray-600">Source:</span>
      {['all','probe','ml'].map(f => (
        <button key={f} onClick={()=>setSourceFilter(f)} className={`px-2 py-0.5 rounded text-xs ${sourceFilter===f?'bg-purple-700 text-white':'bg-white text-gray-700 border'}`}>{f}</button>
      ))}
      <label className="ml-2 text-xs flex items-center gap-1"><input type="checkbox" checked={onlyConfident} onChange={e=>setOnlyConfident(e.target.checked)} /> Confident ML</label>
      <span className="ml-2 text-xs text-gray-600">Dialect:</span>
      {['all','sqlite','mysql','postgresql','mssql','oracle','unknown'].map(d => (
        <button key={d} onClick={()=>setDialectFilter(d)} className={`px-2 py-0.5 rounded text-xs ${dialectFilter===d?'bg-green-700 text-white':'bg-white text-gray-700 border'}`}>{d}</button>
      ))}
      <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search…" className="ml-auto px-2 py-1 text-xs border rounded w-40" />
    </div>
  );

  return (
    <div>
      <FilterBar />
      {grouped.positive && renderSection("Positive", grouped.positive, "positive")}
      {grouped.suspected && renderSection("Suspected", grouped.suspected, "suspected")}
      {grouped.clean && renderSection("Clean", grouped.clean, "clean")}
      {grouped.not_applicable && renderSection("No parameters (NA)", grouped.not_applicable, "na", false)}
      {grouped.error && renderSection("Errors", grouped.error, "error", false)}
    </div>
  );
}
