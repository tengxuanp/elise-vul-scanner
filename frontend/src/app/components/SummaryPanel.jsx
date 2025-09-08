"use client";
import React from 'react';

const SummaryPanel = ({ 
  assessmentResult, 
  mlMode, 
  jobId 
}) => {
  if (!assessmentResult) return null;

  const { summary, meta } = assessmentResult;
  
  // Calculate confirmed breakdown
  const confirmedProbe = assessmentResult.results?.filter(r => 
    r.decision === "confirmed" && r.why?.includes("probe_proof")
  ).length || 0;
  
  const confirmedMLInject = assessmentResult.results?.filter(r => 
    r.decision === "confirmed" && r.why?.includes("ml_ranked")
  ).length || 0;
  
  const clean = assessmentResult.results?.filter(r => 
    r.decision === "tested_negative"
  ).length || 0;

  // ML mode badge color
  const getMLBadgeColor = (mode) => {
    switch (mode) {
      case "Calibrated models": return "bg-green-100 text-green-700";
      case "Defaults only": return "bg-amber-100 text-amber-700";
      case "Off": return "bg-gray-100 text-gray-700";
      default: return "bg-gray-100 text-gray-700";
    }
  };

  // Format processing time
  const formatTime = (ms) => {
    if (!ms) return "N/A";
    const seconds = (ms / 1000).toFixed(1);
    return `${seconds}s`;
  };

  return (
    <div className="card p-6">
      <h3 className="font-semibold mb-4">Summary</h3>
      
      {/* ML Mode Badge */}
      <div className="mb-4">
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getMLBadgeColor(mlMode)}`}>
          ML: {mlMode}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="text-gray-600">Endpoints crawled</div>
          <div className="font-semibold">{meta?.endpoints_crawled || 0}</div>
        </div>
        
        <div>
          <div className="text-gray-600">Targets enumerated</div>
          <div className="font-semibold">{meta?.targets_enumerated || 0}</div>
        </div>
        
        <div>
          <div className="text-gray-600">Confirmed (Probe)</div>
          <div className="font-semibold text-green-600">{confirmedProbe}</div>
        </div>
        
        <div>
          <div className="text-gray-600">Confirmed (ML+Inject)</div>
          <div className="font-semibold text-blue-600">{confirmedMLInject}</div>
        </div>
        
        <div>
          <div className="text-gray-600">Clean</div>
          <div className="font-semibold text-gray-600">{clean}</div>
        </div>
        
        <div>
          <div className="text-gray-600">NA (no params)</div>
          <div className="font-semibold text-gray-500">{summary?.na || 0}</div>
        </div>
        
        <div>
          <div className="text-gray-600">Processing time</div>
          <div className="font-semibold">{formatTime(meta?.processing_time_ms)}</div>
        </div>
        
        <div>
          <div className="text-gray-600">Job ID</div>
          <div className="font-mono text-xs">{jobId || "-"}</div>
        </div>
      </div>
    </div>
  );
};

export default SummaryPanel;
