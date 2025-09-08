"use client";

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { API_BASE } from '../../lib/api';
import Stepbar from '../components/Stepbar';

export default function CrawlPage() {
  const router = useRouter();
  const [formData, setFormData] = useState({
    target_url: '',
    max_depth: 2,
    max_endpoints: 30,
    submit_get_forms: true,
    submit_post_forms: true,
    click_buttons: true
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [selectedEndpoints, setSelectedEndpoints] = useState(new Set());
  const [error, setError] = useState(null);

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleCrawl = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    // Auto-generate job ID
    const jobId = `crawl-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    try {
      const requestPayload = {
        job_id: jobId,
        target_url: formData.target_url,
        crawl_opts: {
          max_depth: parseInt(formData.max_depth),
          max_endpoints: parseInt(formData.max_endpoints),
          submit_get_forms: formData.submit_get_forms,
          submit_post_forms: formData.submit_post_forms,
          click_buttons: formData.click_buttons
        }
      };

      const response = await fetch(`${API_BASE}/crawl`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestPayload)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Crawl failed');
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleProceedToAssess = async () => {
    if (!result || selectedEndpoints.size === 0) return;

    setLoading(true);
    try {
      const selectedEndpointsList = Array.from(selectedEndpoints).map(idx => 
        result.endpoints[parseInt(idx)]
      );

      const response = await fetch(`${API_BASE}/assess`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          job_id: result.job_id,
          endpoints: selectedEndpointsList,
          top_k: 3
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        // Handle validation errors from FastAPI
        if (Array.isArray(errorData.detail)) {
          const errorMessages = errorData.detail.map(err => `${err.loc.join('.')}: ${err.msg}`).join(', ');
          throw new Error(errorMessages);
        }
        throw new Error(errorData.detail || 'Assessment failed');
      }

      // Navigate to assess page with job_id
      router.push(`/assess?jobId=${result.job_id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const toggleEndpoint = (idx) => {
    const newSelected = new Set(selectedEndpoints);
    if (newSelected.has(idx.toString())) {
      newSelected.delete(idx.toString());
    } else {
      newSelected.add(idx.toString());
    }
    setSelectedEndpoints(newSelected);
  };

  const selectAllEndpoints = () => {
    if (result && result.endpoints) {
      setSelectedEndpoints(new Set(result.endpoints.map((_, idx) => idx.toString())));
    }
  };

  const clearSelection = () => {
    setSelectedEndpoints(new Set());
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <Stepbar currentStep="crawl" />
        
        <div className="mt-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-8">Crawl Target</h1>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Crawl Form */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">Crawl Configuration</h2>
              
              <form onSubmit={handleCrawl} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Target URL
                  </label>
                  <input
                    type="url"
                    name="target_url"
                    value={formData.target_url}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="https://example.com"
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Max Depth
                    </label>
                    <input
                      type="number"
                      name="max_depth"
                      value={formData.max_depth}
                      onChange={handleInputChange}
                      min="1"
                      max="5"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Max Endpoints
                    </label>
                    <input
                      type="number"
                      name="max_endpoints"
                      value={formData.max_endpoints}
                      onChange={handleInputChange}
                      min="1"
                      max="100"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      name="submit_get_forms"
                      checked={formData.submit_get_forms}
                      onChange={handleInputChange}
                      className="mr-2"
                    />
                    <span className="text-sm text-gray-700">Submit GET forms</span>
                  </label>

                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      name="submit_post_forms"
                      checked={formData.submit_post_forms}
                      onChange={handleInputChange}
                      className="mr-2"
                    />
                    <span className="text-sm text-gray-700">Submit POST forms</span>
                  </label>

                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      name="click_buttons"
                      checked={formData.click_buttons}
                      onChange={handleInputChange}
                      className="mr-2"
                    />
                    <span className="text-sm text-gray-700">Click buttons</span>
                  </label>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? 'Crawling...' : 'Start Crawl'}
                </button>
              </form>

              {error && (
                <div className="mt-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
                  {error}
                </div>
              )}
            </div>

            {/* Results */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">Crawl Results</h2>
              
              {result ? (
                <div className="space-y-4">
                  <div className="p-3 bg-green-100 border border-green-400 text-green-700 rounded">
                    <p><strong>Mode:</strong> {result.mode}</p>
                    <p><strong>Endpoints Found:</strong> {result.endpoints_count}</p>
                    <p><strong>Persisted:</strong> {result.persisted ? 'Yes' : 'No'}</p>
                    <p><strong>Path:</strong> {result.path}</p>
                  </div>

                  {result.endpoints && result.endpoints.length > 0 && (
                    <div>
                      <div className="flex justify-between items-center mb-3">
                        <h3 className="font-medium">Select Endpoints to Assess</h3>
                        <div className="space-x-2">
                          <button
                            onClick={selectAllEndpoints}
                            className="text-sm text-blue-600 hover:text-blue-800"
                          >
                            Select All
                          </button>
                          <button
                            onClick={clearSelection}
                            className="text-sm text-gray-600 hover:text-gray-800"
                          >
                            Clear
                          </button>
                        </div>
                      </div>

                      <div className="max-h-96 overflow-y-auto border rounded">
                        {result.endpoints.map((endpoint, idx) => (
                          <div key={idx} className="p-3 border-b last:border-b-0">
                            <label className="flex items-start space-x-3">
                              <input
                                type="checkbox"
                                checked={selectedEndpoints.has(idx.toString())}
                                onChange={() => toggleEndpoint(idx)}
                                className="mt-1"
                              />
                              <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium text-gray-900 truncate">
                                  {endpoint.method} {endpoint.url}
                                </p>
                                {endpoint.params && endpoint.params.length > 0 && (
                                  <p className="text-xs text-gray-500">
                                    {endpoint.params.length} parameter(s)
                                  </p>
                                )}
                              </div>
                            </label>
                          </div>
                        ))}
                      </div>

                      <div className="mt-4 flex justify-between items-center">
                        <span className="text-sm text-gray-600">
                          {selectedEndpoints.size} of {result.endpoints.length} selected
                        </span>
                        <button
                          onClick={handleProceedToAssess}
                          disabled={loading || selectedEndpoints.size === 0}
                          className="bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {loading ? 'Processing...' : 'Proceed to Assess'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-gray-500">No crawl results yet. Start a crawl to see discovered endpoints.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
