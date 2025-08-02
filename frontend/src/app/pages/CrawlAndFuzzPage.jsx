"use client";
import { useState, useEffect } from 'react';
import CrawlForm from '../components/CrawlForm';
import { startFuzz, getCategorizedEndpoints, startProbe, getRecommendations } from '../api/api';
import { toast } from 'react-toastify';

export default function CrawlAndFuzzPage() {
  const [endpoints, setEndpoints] = useState([]);
  const [selectedEndpoints, setSelectedEndpoints] = useState([]);
  const [fuzzResults, setFuzzResults] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loadingFuzz, setLoadingFuzz] = useState(false);
  const [loadingScan, setLoadingScan] = useState(false);
  const [loadingProbe, setLoadingProbe] = useState(false);
  const [loadingReco, setLoadingReco] = useState(false);

  const [categorized, setCategorized] = useState(null);
  const [hasScanned, setHasScanned] = useState(false);
  const [targetUrl, setTargetUrl] = useState("");
  const [probeCount, setProbeCount] = useState(null);
  const [recommendations, setRecommendations] = useState([]);

  useEffect(() => {
    setEndpoints([]);
    setSelectedEndpoints([]);
    setFuzzResults([]);
    setAlerts([]);
    setCategorized(null);
    setHasScanned(false);
    setTargetUrl("");
  }, []);

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

    const allResults = [];

    try {
      setLoadingFuzz(true);
      toast.info('Fuzzing started. Running ffuf on selected endpoints...');

      for (const ep of selectedEndpoints) {
        if (!ep.params || ep.params.length === 0) {
          console.warn(`Skipping ${ep.url} with no params.`);
          continue;
        }

        for (const param of ep.params) {
          try {
            const res = await startFuzz({ url: ep.url, param });
            if (res && res.output_file) {
              allResults.push({
                url: ep.url,
                param,
                payload: 'FUZZ',
                status_code: '✔️',
                response_length: 'See JSON',
                reflects_payload: '❓'
              });
            }
          } catch (err) {
            allResults.push({
              url: ep.url,
              param,
              payload: 'FUZZ',
              status_code: 'Error',
              response_length: '-',
              reflects_payload: '❌'
            });
            console.error(`Fuzzing failed for ${ep.url}?${param}=FUZZ`, err);
          }
        }
      }

      setFuzzResults(allResults);
      toast.success(`Fuzzing completed for ${allResults.length} param(s).`);
    } catch (err) {
      toast.error('Fuzzing failed.');
      console.error(err);
    } finally {
      setLoadingFuzz(false);
    }
  };

  const handleProbe = async () => {
    try {
      setLoadingProbe(true);
      const res = await startProbe();
      setProbeCount(res.probed_count || 0);
      toast.success(`Probed ${res.probed_count || 0} param(s).`);
    } catch (err) {
      console.error('Probe failed:', err);
      toast.error('Probe failed.');
    } finally {
      setLoadingProbe(false);
    }
  };

  const handleRecommend = async () => {
    try {
      setLoadingReco(true);
      const res = await getRecommendations();
      setRecommendations(res.recommendations || []);
      toast.success(`Got recommendations for ${res.recommendations?.length || 0} param(s).`);
    } catch (err) {
      console.error('Recommendation failed:', err);
      toast.error('Recommendation failed.');
    } finally {
      setLoadingReco(false);
    }
  };

  const handleCrawlResults = async ({ endpoints: crawledEndpoints, captured_requests, target_url }) => {
    const merged = [
      ...(crawledEndpoints || []),
      ...(captured_requests || []).map(req => ({
        url: req.url,
        method: req.method,
        params: []
      }))
    ];
    setEndpoints(merged);
    setSelectedEndpoints([]);
    setTargetUrl(target_url);
    toast.success(`Loaded ${merged.length} endpoints.`);

    try {
      const categorizedRes = await getCategorizedEndpoints(target_url);
      setCategorized(categorizedRes);
      setHasScanned(true);
    } catch (err) {
      console.error('Failed to load categorized endpoints:', err);
      toast.error('Failed to categorize results.');
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Crawl, Fuzz & Active Scan</h1>

      <CrawlForm onResults={handleCrawlResults} />

      {hasScanned && categorized && (
        <div className="border p-4 rounded space-y-3">
          <h2 className="text-xl font-semibold">🧠 Categorized Vulnerability Candidates</h2>
          {Object.entries(categorized.grouped).map(([group, entries]) => (
            <div key={group}>
              <h3 className="text-md font-bold mt-3">{group} ({entries.length})</h3>
              <ul className="pl-4 list-disc text-sm">
                {entries.map((ep, i) => (
                  <li key={i}>
                    <code>{ep.method}</code> {ep.url} — <span className="text-gray-600">[{ep.params.join(', ') || 'No Params'}]</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}

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

      {hasScanned && (
        <div className="border p-4 rounded space-y-2">
          <h2 className="text-xl font-semibold">Probe & Recommend</h2>
          <div className="flex space-x-2">
            <button
              onClick={handleProbe}
              className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600"
              disabled={loadingProbe}
            >
              {loadingProbe ? 'Probing...' : 'Start Probe'}
            </button>
            <button
              onClick={handleRecommend}
              className="bg-purple-500 text-white px-4 py-2 rounded hover:bg-purple-600"
              disabled={loadingReco}
            >
              {loadingReco ? 'Recommending...' : 'Recommend Payloads'}
            </button>
          </div>
          {probeCount !== null && (
            <p className="text-sm text-gray-600">Probed {probeCount} param(s).</p>
          )}
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
                  <td className="border px-2 py-1">{r.reflects_payload}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {recommendations.length > 0 && (
        <div className="border p-4 rounded">
          <h2 className="text-xl font-semibold mb-2">Payload Recommendations</h2>
          <table className="table-auto w-full border text-sm">
            <thead>
              <tr className="bg-gray-200">
                <th className="border px-2 py-1">Endpoint</th>
                <th className="border px-2 py-1">Param</th>
                <th className="border px-2 py-1">Recommended Payloads</th>
              </tr>
            </thead>
            <tbody>
              {recommendations.map((r, idx) => (
                <tr key={idx} className="hover:bg-gray-50">
                  <td className="border px-2 py-1">{r.method} {r.url}</td>
                  <td className="border px-2 py-1">{r.param}</td>
                  <td className="border px-2 py-1">
                    {r.recommendations
                      .map(([p, prob]) => `${p} (${(prob * 100).toFixed(1)}%)`)
                      .join(', ')}
                  </td>
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
