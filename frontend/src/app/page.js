"use client";
import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { getHealth } from "../lib/api";
import HealthBadge from "../components/HealthBadge";
import CrawlForm from "../components/CrawlForm";
import EndpointTable from "../components/EndpointTable";
import TriagePanel from "../components/TriagePanel";
import FuzzPanel from "../components/FuzzPanel";
import FindingsTable from "../components/FindingsTable";

export default function Page() {
  const { data: health } = useQuery({ queryKey: ["health"], queryFn: getHealth });
  const mlReady = !!(health && health.ml_ready);
  const [endpoints, setEndpoints] = useState([]);
  const [crawlMeta, setCrawlMeta] = useState(null);
  const [predictions, setPredictions] = useState([]);
  const [fuzzResults, setFuzzResults] = useState([]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Elise — Probe-first Scanner</h1>
        <HealthBadge />
      </div>

      {/* ML Readiness Banner */}
      {!mlReady && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-amber-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-amber-800">
                ML Models Not Ready
              </h3>
              <div className="mt-2 text-sm text-amber-700">
                <p>Train models first to enable fuzzing. Run <code className="bg-amber-100 px-1 rounded">make models</code> or use the training endpoint.</p>
              </div>
            </div>
          </div>
        </div>
      )}


      <div className="grid grid-cols-12 gap-5">
        <div className="col-span-12 lg:col-span-3 space-y-4">
          <CrawlForm onCrawled={(eps) => { setEndpoints(eps || []); setPredictions([]); setFuzzResults([]); }} onMeta={setCrawlMeta} />
          <TriagePanel endpoints={endpoints} mlReady={mlReady} onTriage={(res) => setPredictions(res)} />
          <FuzzPanel predictions={predictions} mlReady={mlReady} onFuzz={(res) => setFuzzResults(res)} />
        </div>

        <div className="col-span-12 lg:col-span-5 space-y-4">
          <EndpointTable endpoints={endpoints} meta={crawlMeta} />
        </div>

        <div className="col-span-12 lg:col-span-4 space-y-4">
          {predictions.length > 0 && (
            <div className="bg-white rounded-xl shadow p-4">
              <h2 className="font-semibold mb-3">ML Predictions ({predictions.length})</h2>
              <div className="space-y-2">
                {predictions.map((pred, i) => (
                  <div key={i} className="p-2 bg-gray-50 rounded text-sm">
                    <div className="font-medium">{pred.endpoint?.url}</div>
                    <div className="text-gray-600">Family: {pred.family} | Confidence: {Math.round((pred.confidence || 0) * 100)}%</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {fuzzResults.length > 0 && (
            <div className="bg-white rounded-xl shadow p-4">
              <h2 className="font-semibold mb-3">Fuzz Results ({fuzzResults.length})</h2>
              <div className="space-y-2">
                {fuzzResults.map((result, i) => (
                  <div key={i} className={`p-2 rounded text-sm ${result.family && result.family !== 'none' ? 'bg-red-50 border border-red-200' : 'bg-gray-50'}`}>
                    <div className="font-medium">{result.endpoint?.url}</div>
                    <div className="text-gray-600">Family: {result.family} | CVSS: {result.cvss?.base || 'N/A'}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}