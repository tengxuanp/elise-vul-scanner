"use client"
import { useState } from 'react';
import { fuzzEndpoint } from '../api/api';
import { toast } from 'react-toastify';

export default function FuzzForm({ endpointUrl, method }) {
  const [payloads, setPayloads] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const handleFuzz = async () => {
    if (!payloads.trim()) {
      toast.error('Please enter at least one payload.');
      return;
    }

    try {
      setLoading(true);
      const payloadList = payloads.split('\n').map((p) => p.trim()).filter(Boolean);
      const res = await fuzzEndpoint(endpointUrl, method, payloadList);
      setResults(res.data.results);
      toast.success(`Fuzzing completed with ${res.data.results.length} results.`);
    } catch (err) {
      toast.error('Fuzzing failed. Check console for details.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mt-4 p-4 border rounded">
      <h3 className="text-lg font-semibold mb-2">Fuzz Endpoint</h3>
      <p className="mb-2 text-gray-600">
        Target: <strong>{endpointUrl}</strong> ({method})
      </p>
      <textarea
        className="w-full border p-2 rounded mb-2"
        rows="4"
        placeholder="Enter payloads, one per line"
        value={payloads}
        onChange={(e) => setPayloads(e.target.value)}
      />
      <button
        onClick={handleFuzz}
        className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600"
        disabled={loading}
      >
        {loading ? 'Fuzzing...' : 'Start Fuzzing'}
      </button>

      {results.length > 0 && (
        <div className="mt-4">
          <h4 className="font-semibold mb-2">Fuzz Results:</h4>
          <table className="table-auto w-full border">
            <thead>
              <tr className="bg-gray-200">
                <th className="border px-2 py-1">Param</th>
                <th className="border px-2 py-1">Payload</th>
                <th className="border px-2 py-1">Status</th>
                <th className="border px-2 py-1">Resp. Length</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, idx) => (
                <tr key={idx} className="hover:bg-gray-50">
                  <td className="border px-2 py-1">{r.param}</td>
                  <td className="border px-2 py-1">{r.payload}</td>
                  <td className="border px-2 py-1">{r.status_code}</td>
                  <td className="border px-2 py-1">{r.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
