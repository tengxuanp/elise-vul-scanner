"use client";
import { useState, useCallback } from "react";

const useEnhancedMLFuzzer = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);

  const fuzzEndpoints = useCallback(async (endpoints, topK = 5) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const targets = endpoints.map(endpoint => ({
        url: endpoint.url,
        param: endpoint.param,
        method: endpoint.method || 'GET'
      }));

      const response = await fetch('http://localhost:8000/api/enhanced-fuzz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(targets)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data.results || []);
      return data;
    } catch (err) {
      setError(err.message);
      console.error(`Enhanced ML Fuzzing failed: ${err.message}`);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const clearResults = useCallback(() => {
    setResults([]);
    setError(null);
  }, []);

  return {
    fuzzEndpoints,
    clearResults,
    isLoading,
    results,
    error
  };
};

const useEnhancedCrawler = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState([]);
  const [error, setError] = useState(null);

  const crawlTarget = useCallback(async (targetUrl, maxEndpoints = 20) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:8000/api/enhanced-crawl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl,
          max_endpoints: maxEndpoints
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setDiscoveredEndpoints(data.endpoints || []);
      console.log(`Discovered ${data.discovered_endpoints} endpoints from ${targetUrl}`);
      return data;
    } catch (err) {
      setError(err.message);
      console.error(`Crawling failed: ${err.message}`);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const clearEndpoints = useCallback(() => {
    setDiscoveredEndpoints([]);
    setError(null);
  }, []);

  return {
    crawlTarget,
    clearEndpoints,
    isLoading,
    discoveredEndpoints,
    error
  };
};

export default function CrawlAndFuzzPage() {
  const {
    fuzzEndpoints,
    clearResults,
    isLoading: fuzzingLoading,
    results: fuzzingResults,
    error: fuzzingError
  } = useEnhancedMLFuzzer();

  const {
    crawlTarget,
    clearEndpoints,
    isLoading: crawlingLoading,
    discoveredEndpoints,
    error: crawlingError
  } = useEnhancedCrawler();

  const [targetUrl, setTargetUrl] = useState("http://localhost:8082/");
  const [maxEndpoints, setMaxEndpoints] = useState(20);
  const [selectedEndpoints, setSelectedEndpoints] = useState(new Set());
  const [topK, setTopK] = useState(5);

  const toggleEndpointSelection = useCallback((endpointKey) => {
    setSelectedEndpoints(prev => {
      const newSet = new Set(prev);
      if (newSet.has(endpointKey)) {
        newSet.delete(endpointKey);
      } else {
        newSet.add(endpointKey);
      }
      return newSet;
    });
  }, []);

  const selectAllEndpoints = useCallback(() => {
    const allKeys = discoveredEndpoints.map(ep => `${ep.url}|${ep.param}|${ep.method}`);
    setSelectedEndpoints(new Set(allKeys));
  }, [discoveredEndpoints]);

  const clearSelection = useCallback(() => {
    setSelectedEndpoints(new Set());
  }, []);

  const handleCrawl = useCallback(async () => {
    if (!targetUrl.trim()) {
      alert("Please enter a target URL");
      return;
    }
    
    try {
      await crawlTarget(targetUrl, maxEndpoints);
    } catch (err) {
      console.error("Crawling failed:", err);
    }
  }, [targetUrl, maxEndpoints, crawlTarget]);

  const handleFuzzSelected = useCallback(async () => {
    if (selectedEndpoints.size === 0) {
      alert("Please select endpoints to fuzz");
      return;
    }

    const selectedEndpointsList = discoveredEndpoints.filter(ep => 
      selectedEndpoints.has(`${ep.url}|${ep.param}|${ep.method}`)
    );

    try {
      await fuzzEndpoints(selectedEndpointsList, topK);
      alert(`Enhanced ML fuzzing completed for ${selectedEndpointsList.length} endpoints`);
    } catch (err) {
      console.error("Fuzzing failed:", err);
    }
  }, [selectedEndpoints, discoveredEndpoints, topK, fuzzEndpoints]);

  const handleFuzzAll = useCallback(async () => {
    if (discoveredEndpoints.length === 0) {
      alert("Please crawl a target first");
      return;
    }

    try {
      await fuzzEndpoints(discoveredEndpoints, topK);
      alert(`Enhanced ML fuzzing completed for all ${discoveredEndpoints.length} endpoints`);
    } catch (err) {
      console.error("Fuzzing failed:", err);
    }
  }, [discoveredEndpoints, topK, fuzzEndpoints]);

  const handleClearAll = useCallback(() => {
    clearEndpoints();
    clearResults();
    setSelectedEndpoints(new Set());
  }, [clearEndpoints, clearResults]);

  const getCVSSColor = (score) => {
    if (score >= 9.0) return "bg-red-100 text-red-800";
    if (score >= 7.0) return "bg-orange-100 text-orange-800";
    if (score >= 4.0) return "bg-yellow-100 text-yellow-800";
    if (score >= 0.1) return "bg-blue-100 text-blue-800";
    return "bg-gray-100 text-gray-800";
  };

  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.8) return "bg-green-100 text-green-800";
    if (confidence >= 0.6) return "bg-yellow-100 text-yellow-800";
    if (confidence >= 0.4) return "bg-orange-100 text-orange-800";
    return "bg-red-100 text-red-800";
  };

  const getVulnerabilityColor = (type) => {
    const colors = {
      'xss': 'bg-red-100 text-red-800',
      'sqli': 'bg-orange-100 text-orange-800',
      'rce': 'bg-purple-100 text-purple-800',
      'lfi': 'bg-blue-100 text-blue-800',
      'redirect': 'bg-yellow-100 text-yellow-800',
      'ssrf': 'bg-indigo-100 text-indigo-800',
      'xxe': 'bg-pink-100 text-pink-800'
    };
    return colors[type] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            🚀 Enhanced ML Fuzzer with CVSS Scoring
          </h1>
          <p className="text-xl text-gray-600">
            Automation Detection & Exploitation of Web Application Vulnerabilities using Machine Learning
          </p>
          
          <div className="mt-6 inline-flex items-center px-4 py-2 rounded-full text-sm font-medium bg-green-100 text-green-800">
            <span className="w-2 h-2 bg-green-400 rounded-full mr-2"></span>
            Enhanced ML System Active - CVSS-Based Risk Assessment
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          <div className="lg:col-span-1 space-y-6">
            
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">
                🎯 Target Discovery
              </h2>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Target URL
                  </label>
                  <input
                    type="url"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Max Endpoints
                  </label>
                  <input
                    type="number"
                    value={maxEndpoints}
                    onChange={(e) => setMaxEndpoints(parseInt(e.target.value))}
                    min="1"
                    max="100"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <button
                  onClick={handleCrawl}
                  disabled={crawlingLoading}
                  className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {crawlingLoading ? "🔍 Discovering..." : "🔍 Discover Endpoints"}
                </button>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">
                🧪 Enhanced ML Fuzzing
              </h2>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Top K Payloads per Endpoint
                  </label>
                  <input
                    type="number"
                    value={topK}
                    onChange={(e) => setTopK(parseInt(e.target.value))}
                    min="1"
                    max="10"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <button
                  onClick={handleFuzzSelected}
                  disabled={fuzzingLoading || selectedEndpoints.size === 0}
                  className="w-full bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {fuzzingLoading ? "🧪 Fuzzing..." : `🧪 Fuzz Selected (${selectedEndpoints.size})`}
                </button>
                
                <button
                  onClick={handleFuzzAll}
                  disabled={fuzzingLoading || discoveredEndpoints.length === 0}
                  className="w-full bg-purple-600 text-white py-2 px-4 rounded-md hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {fuzzingLoading ? "🧪 Fuzzing..." : `🧪 Fuzz All (${discoveredEndpoints.length})`}
                </button>
                
                <button
                  onClick={handleClearAll}
                  className="w-full bg-gray-500 text-white py-2 px-4 rounded-md hover:bg-gray-600"
                >
                  🗑️ Clear All
                </button>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">
                📊 ML & CVSS Statistics
              </h2>
              
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Discovered Endpoints:</span>
                  <span className="font-medium">{discoveredEndpoints.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Selected Endpoints:</span>
                  <span className="font-medium">{selectedEndpoints.size}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Fuzzing Results:</span>
                  <span className="font-medium">{fuzzingResults.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Vulnerabilities Found:</span>
                  <span className="font-medium">{fuzzingResults.filter(r => r.vulnerability_type).length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">High Risk (CVSS ≥7.0):</span>
                  <span className="font-medium">{fuzzingResults.filter(r => r.cvss_base_score && r.cvss_base_score >= 7.0).length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Avg ML Confidence:</span>
                  <span className="font-medium">
                    {fuzzingResults.length > 0 
                      ? (fuzzingResults.reduce((sum, r) => sum + (r.ml_confidence || 0), 0) / fuzzingResults.length * 100).toFixed(1) + '%'
                      : '0%'
                    }
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Avg CVSS Score:</span>
                  <span className="font-medium">
                    {fuzzingResults.length > 0 
                      ? (fuzzingResults.reduce((sum, r) => sum + (r.cvss_base_score || 0), 0) / fuzzingResults.length).toFixed(1)
                      : '0.0'
                    }
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="lg:col-span-2 space-y-6">
            
            {discoveredEndpoints.length > 0 && (
              <div className="bg-white rounded-lg shadow">
                <div className="px-6 py-4 border-b border-gray-200">
                  <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-gray-900">
                      🔍 Discovered Endpoints ({discoveredEndpoints.length})
                    </h2>
                    <div className="flex space-x-2">
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
                </div>
                
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Select
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          URL
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Parameter
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Method
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Type
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {discoveredEndpoints.map((endpoint, index) => {
                        const endpointKey = `${endpoint.url}|${endpoint.param}|${endpoint.method}`;
                        const isSelected = selectedEndpoints.has(endpointKey);
                        
                        return (
                          <tr key={index} className={isSelected ? "bg-blue-50" : ""}>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() => toggleEndpointSelection(endpointKey)}
                                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                              />
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                              {endpoint.url}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {endpoint.param}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                                endpoint.method === 'GET' ? 'bg-green-100 text-green-800' : 'bg-orange-100 text-orange-800'
                              }`}>
                                {endpoint.method}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                                endpoint.type === 'discovered' ? 'bg-blue-100 text-blue-800' : 'bg-purple-100 text-purple-800'
                              }`}>
                                {endpoint.type}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {fuzzingResults.length > 0 && (
              <div className="bg-white rounded-lg shadow">
                <div className="px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">
                    🧪 Enhanced ML Fuzzing Results with CVSS Scoring ({fuzzingResults.length})
                  </h2>
                </div>
                
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Target
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Payload
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Vulnerability
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          ML Confidence
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          CVSS Score
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Risk Level
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Exploitation
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {fuzzingResults.map((result, index) => (
                        <tr key={index}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-900">
                              {result.url}
                            </div>
                            <div className="text-sm text-gray-500">
                              {result.param} ({result.method})
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-900 max-w-xs truncate" title={result.payload}>
                              {result.payload}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {result.vulnerability_type && typeof result.vulnerability_type === 'string' ? (
                              <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getVulnerabilityColor(result.vulnerability_type)}`}>
                                {result.vulnerability_type.toUpperCase()}
                              </span>
                            ) : (
                              <span className="text-gray-400 text-xs">None</span>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {result.ml_confidence ? (
                              <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getConfidenceColor(result.ml_confidence)}`}>
                                {(result.ml_confidence * 100).toFixed(0)}%
                              </span>
                            ) : (
                              <span className="text-gray-400 text-xs">N/A</span>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {result.cvss_base_score ? (
                              <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getCVSSColor(result.cvss_base_score)}`}>
                                {result.cvss_base_score.toFixed(1)}
                              </span>
                            ) : (
                              <span className="text-gray-400 text-xs">N/A</span>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {result.cvss_severity && typeof result.cvss_severity === 'string' ? (
                              <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                                result.cvss_severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                                result.cvss_severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                                result.cvss_severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                                result.cvss_severity === 'LOW' ? 'bg-blue-100 text-blue-800' :
                                'bg-gray-100 text-gray-800'
                              }`}>
                                {result.cvss_severity.toUpperCase()}
                              </span>
                            ) : (
                              <span className="text-gray-400 text-xs">N/A</span>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-900">
                              <div className="text-xs text-gray-500">Potential:</div>
                              <span className="font-medium">{(result.exploitation_potential * 100).toFixed(0)}%</span>
                            </div>
                            {result.exploitation_complexity && (
                              <div className="text-xs text-gray-500 mt-1">
                                {result.exploitation_complexity}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {discoveredEndpoints.length === 0 && fuzzingResults.length === 0 && (
              <div className="bg-white rounded-lg shadow p-12 text-center">
                <div className="text-gray-400 text-6xl mb-4">🚀</div>
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  Ready to Discover and Fuzz with Enhanced ML
                </h3>
                <p className="text-gray-500">
                  Enter a target URL above and click "Discover Endpoints" to get started with CVSS-based ML fuzzing.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
