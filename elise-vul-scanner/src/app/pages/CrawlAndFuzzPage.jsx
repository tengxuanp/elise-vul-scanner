"use client";
import { useState } from 'react';
import CrawlForm from '../components/CrawlForm';
import { startFuzz, getFuzzResult, zapScanAndFetchAlerts } from '../api/api';
import { toast } from 'react-toastify';

export default function CrawlAndFuzzPage() {
  const [endpoints, setEndpoints] = useState([]);
  const [selectedEndpoints, setSelectedEndpoints] = useState([]);
  const [fuzzResults, setFuzzResults] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loadingFuzz, setLoadingFuzz] = useState(false);
  const [loadingScan, setLoadingScan] = useState(false);

  const toggleSelect = (ep) => {
    setSelectedEndpoints((prev) =>
      prev.includes(ep) ? prev.filter((e) => e !== ep) : [...prev, ep]
    );
  };

const handleFuzzSelected = async () => {
  if (selectedEndpoints.length === 0) {
    toast.error('Select endpoints before fuzzing.');
    return;
  }

  try {
    setLoadingFuzz(true);
    await startFuzz(selectedEndpoints);
    toast.info('Fuzzing started. Waiting for results...');

    const pollInterval = setInterval(async () => {
      try {
        const res = await getFuzzResult();
        if (res.status !== 'pending') {
          clearInterval(pollInterval);
          setFuzzResults(res.results || []);
          toast.success(`Fuzzing completed with ${res.results?.length || 0} results.`);
          setLoadingFuzz(false);
        }
      } catch (err) {
        clearInterval(pollInterval);
        console.error(err);
        toast.error('Failed to get fuzz results.');
        setLoadingFuzz(false);
      }
    }, 5000);

  } catch (err) {
    toast.error('Failed to start fuzzing.');
    console.error(err);
    setLoadingFuzz(false);
  }
};


  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Crawl, Fuzz & Active Scan</h1>

      <CrawlForm
        onResults={({ endpoints: crawledEndpoints, captured_requests }) => {
          const merged = [
            ...(crawledEndpoints || []),
            ...(captured_requests || []).map(req => ({
              url: req.url,
              method: req.method,
              params: [] // No params from captured requests
            }))
          ];
          setEndpoints(merged);
          setSelectedEndpoints([]);
          toast.success(`Loaded ${merged.length} endpoints.`);
        }}
      />

      {endpoints.length > 0 && (
        <div className="border p-4 rounded space-y-2">
          <h2 className="text-xl font-semibold">Discovered Endpoints & Captured APIs</h2>
          {endpoints.map((ep, idx) => (
            <label key={idx} className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={selectedEndpoints.includes(ep)}
                onChange={() => toggleSelect(ep)}
              />
              <span>{ep.method} {ep.url} – [{Array.isArray(ep.params) && ep.params.length > 0 ? ep.params.join(', ') : 'No Params'}]</span>
            </label>
          ))}
        </div>
      )}

      {selectedEndpoints.length > 0 && (
        <div className="border p-4 rounded space-y-2">
          <h2 className="text-xl font-semibold">Fuzz & Active Scan Controls</h2>

          <div className="flex space-x-2">
            <button
              onClick={handleFuzzSelected}
              className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600"
              disabled={loadingFuzz}
            >
              {loadingFuzz ? 'Fuzzing...' : 'Start Fuzzing'}
            </button>

          </div>
        </div>
      )}

      {fuzzResults.length > 0 && (
        <div className="border p-4 rounded">
          <h2 className="text-xl font-semibold mb-2">Fuzzing Results</h2>
          <table className="table-auto w-full border text-sm">
            <thead>
              <tr className="bg-gray-200">
                <th className="border px-2 py-1">Endpoint</th>
                <th className="border px-2 py-1">Param</th>
                <th className="border px-2 py-1">Payload</th>
                <th className="border px-2 py-1">Status</th>
                <th className="border px-2 py-1">Resp. Length</th>
                <th className="border px-2 py-1">Reflected</th>
              </tr>
            </thead>
            <tbody>
              {fuzzResults.map((r, idx) => (
                <tr key={idx} className="hover:bg-gray-50">
                  <td className="border px-2 py-1">{r.url}</td>
                  <td className="border px-2 py-1">{r.param}</td>
                  <td className="border px-2 py-1">{r.payload}</td>
                  <td className="border px-2 py-1">{r.status_code}</td>
                  <td className="border px-2 py-1">{r.response_length}</td>
                  <td className="border px-2 py-1">{r.reflects_payload ? '✅' : '❌'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {alerts.length > 0 && (
        <div className="border p-4 rounded">
          <h2 className="text-xl font-semibold mb-2">Active Scan Alerts</h2>
          <table className="table-auto w-full border text-sm">
            <thead>
              <tr className="bg-gray-200">
                <th className="border px-2 py-1">Risk</th>
                <th className="border px-2 py-1">URL</th>
                <th className="border px-2 py-1">Alert</th>
                <th className="border px-2 py-1">Param</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a, idx) => (
                <tr key={idx} className="hover:bg-gray-50">
                  <td className="border px-2 py-1">{a.risk}</td>
                  <td className="border px-2 py-1">{a.url}</td>
                  <td className="border px-2 py-1">{a.alert}</td>
                  <td className="border px-2 py-1">{a.param || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
