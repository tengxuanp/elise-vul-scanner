"use client";
import { useState, useCallback } from "react";

// Hook for dynamic crawling
const useEnhancedCrawler = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState([]);
  const [error, setError] = useState(null);

  const crawlTarget = useCallback(async (targetUrl, maxEndpoints = 20) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:8000/api/crawl', {
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

// Hook for ML prediction and payload recommendation
const useMLPrediction = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [predictions, setPredictions] = useState([]);
  const [error, setError] = useState(null);

  const predictVulnerabilities = useCallback(async (endpoints) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:8000/api/ml-predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpoints })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setPredictions(data.recommendations || []);
      console.log(`ML predictions completed for ${data.total_endpoints} endpoints`);
      return data;
    } catch (err) {
      setError(err.message);
      console.error(`ML prediction failed: ${err.message}`);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const clearPredictions = useCallback(() => {
    setPredictions([]);
    setError(null);
  }, []);

  return {
    predictVulnerabilities,
    clearPredictions,
    isLoading,
    predictions,
    error
  };
};

// Hook for real ML fuzzing
const useMLFuzzer = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);

  const fuzzWithML = useCallback(async (fuzzRequests) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:8000/api/ml-fuzz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fuzz_requests: fuzzRequests })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data.results || []);
      console.log(`Real ML fuzzing completed: ${data.vulnerabilities_found} vulnerabilities found`);
      return data;
    } catch (err) {
      setError(err.message);
      console.error(`ML fuzzing failed: ${err.message}`);
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
    fuzzWithML,
    clearResults,
    isLoading,
    results,
    error
  };
};

export default function CrawlAndFuzzPage() {
  // Hooks for different stages
  const {
    crawlTarget,
    clearEndpoints,
    isLoading: crawlingLoading,
    discoveredEndpoints,
    error: crawlingError
  } = useEnhancedCrawler();

  const {
    predictVulnerabilities,
    clearPredictions,
    isLoading: predictionLoading,
    predictions,
    error: predictionError
  } = useMLPrediction();

  const {
    fuzzWithML,
    clearResults,
    isLoading: fuzzingLoading,
    results,
    error: fuzzingError
  } = useMLFuzzer();

  // State management
  const [targetUrl, setTargetUrl] = useState("http://localhost:8082/");
  const [maxEndpoints, setMaxEndpoints] = useState(20);
  const [selectedFuzzRequests, setSelectedFuzzRequests] = useState(new Set());
  const [currentStep, setCurrentStep] = useState(1); // 1: Crawl, 2: Predict, 3: Fuzz
  const [isTrainingModels, setIsTrainingModels] = useState(false);
  const [exploitationResults, setExploitationResults] = useState({});
  const [isExploiting, setIsExploiting] = useState(false);

  // Step 1: Crawling
  const handleCrawl = useCallback(async () => {
    if (!targetUrl.trim()) {
      alert("Please enter a target URL");
      return;
    }
    
    try {
      await crawlTarget(targetUrl, maxEndpoints);
      setCurrentStep(2);
    } catch (err) {
      console.error("Crawling failed:", err);
    }
  }, [targetUrl, maxEndpoints, crawlTarget]);

  // Step 2: ML Prediction
  const handleMLPredict = useCallback(async () => {
    if (discoveredEndpoints.length === 0) {
      alert("Please crawl endpoints first");
      return;
    }
    
    try {
      // First, ensure ML models are trained
      setIsTrainingModels(true);
      console.log("🧠 Ensuring ML models are trained...");
      const trainResponse = await fetch('http://localhost:8000/api/train-models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      
      if (!trainResponse.ok) {
        throw new Error(`Model training failed: ${trainResponse.status}`);
      }
      
      const trainData = await trainResponse.json();
      console.log("✅ ML models trained:", trainData.message);
      setIsTrainingModels(false);
      
      // Now run ML prediction
      await predictVulnerabilities(discoveredEndpoints);
      setCurrentStep(3);
    } catch (err) {
      setIsTrainingModels(false);
      console.error("ML prediction failed:", err);
    }
  }, [discoveredEndpoints, predictVulnerabilities]);

  // Step 3: Fuzzing
  const handleFuzzSelected = useCallback(async () => {
    if (selectedFuzzRequests.size === 0) {
      alert("Please select endpoint-payload combinations to fuzz");
      return;
    }

    const fuzzRequests = Array.from(selectedFuzzRequests).map(key => {
      const [endpointIndex, payloadIndex] = key.split('|').map(Number);
      const prediction = predictions[endpointIndex];
      const payload = prediction.recommended_payloads[payloadIndex];
      
      return {
        endpoint: prediction.endpoint,
        payload: payload.payload
      };
    });

    try {
      await fuzzWithML(fuzzRequests);
    } catch (err) {
      console.error("Fuzzing failed:", err);
    }
  }, [selectedFuzzRequests, predictions, fuzzWithML]);

  // Exploitation handler
  const handleExploit = useCallback(async (result) => {
    setIsExploiting(true);
    
    try {
      const response = await fetch('http://localhost:8000/api/exploit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          endpoint: result.endpoint,
          original_payload: result.payload,
          error_response: result.response_body || result.evidence?.join(' ') || '',
          max_attempts: 5
        })
      });

      if (!response.ok) {
        throw new Error(`Exploitation failed: ${response.statusText}`);
      }

      const exploitationResult = await response.json();
      
      // Store exploitation result
      setExploitationResults(prev => ({
        ...prev,
        [`${result.endpoint.url}-${result.payload}`]: exploitationResult
      }));

      console.log("Exploitation result:", exploitationResult);
      
    } catch (error) {
      console.error("Exploitation failed:", error);
      alert(`Exploitation failed: ${error.message}`);
    } finally {
      setIsExploiting(false);
    }
  }, []);

  const handleFuzzAll = useCallback(async () => {
    if (predictions.length === 0) {
      alert("Please run ML prediction first");
      return;
    }

    const fuzzRequests = [];
    predictions.forEach(prediction => {
      prediction.recommended_payloads.forEach(payload => {
        fuzzRequests.push({
          endpoint: prediction.endpoint,
          payload: payload.payload
        });
      });
    });

    try {
      await fuzzWithML(fuzzRequests);
    } catch (err) {
      console.error("Fuzzing failed:", err);
    }
  }, [predictions, fuzzWithML]);

  const toggleFuzzRequest = useCallback((endpointIndex, payloadIndex) => {
    const key = `${endpointIndex}|${payloadIndex}`;
    setSelectedFuzzRequests(prev => {
      const newSet = new Set(prev);
      if (newSet.has(key)) {
        newSet.delete(key);
      } else {
        newSet.add(key);
      }
      return newSet;
    });
  }, []);

  const selectAllFuzzRequests = useCallback(() => {
    const allKeys = new Set();
    predictions.forEach((prediction, endpointIndex) => {
      prediction.recommended_payloads.forEach((_, payloadIndex) => {
        allKeys.add(`${endpointIndex}|${payloadIndex}`);
      });
    });
    setSelectedFuzzRequests(allKeys);
  }, [predictions]);

  const clearSelection = useCallback(() => {
    setSelectedFuzzRequests(new Set());
  }, []);

  const handleClearAll = useCallback(() => {
    clearEndpoints();
    clearPredictions();
    clearResults();
    setSelectedFuzzRequests(new Set());
    setCurrentStep(1);
  }, [clearEndpoints, clearPredictions, clearResults]);

  const getVulnerabilityColor = (type) => {
    const colors = {
      'xss': 'bg-red-100 text-red-800',
      'sqli': 'bg-orange-100 text-orange-800',
      'rce': 'bg-purple-100 text-purple-800',
      'lfi': 'bg-blue-100 text-blue-800',
      'redirect': 'bg-yellow-100 text-yellow-800'
    };
    return colors[type] || 'bg-gray-100 text-gray-800';
  };

  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    return 'text-red-600';
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Real ML-Based Vulnerability Scanner
          </h1>
          <p className="text-gray-600">
            Dynamic crawling → ML prediction → Payload recommendation → Real fuzzing
          </p>
        </div>

        {/* Progress Steps */}
        <div className="mb-8">
          <div className="flex items-center justify-center space-x-4">
            <div className={`flex items-center ${currentStep >= 1 ? 'text-blue-600' : 'text-gray-400'}`}>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center ${currentStep >= 1 ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>
                1
              </div>
              <span className="ml-2 font-medium">Crawl</span>
            </div>
            <div className={`w-16 h-1 ${currentStep >= 2 ? 'bg-blue-600' : 'bg-gray-200'}`}></div>
            <div className={`flex items-center ${currentStep >= 2 ? 'text-blue-600' : 'text-gray-400'}`}>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center ${currentStep >= 2 ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>
                2
              </div>
              <span className="ml-2 font-medium">ML Predict</span>
            </div>
            <div className={`w-16 h-1 ${currentStep >= 3 ? 'bg-blue-600' : 'bg-gray-200'}`}></div>
            <div className={`flex items-center ${currentStep >= 3 ? 'text-blue-600' : 'text-gray-400'}`}>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center ${currentStep >= 3 ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>
                3
              </div>
              <span className="ml-2 font-medium">Fuzz</span>
            </div>
          </div>
        </div>

        {/* Step 1: Crawling */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Step 1: Dynamic Crawling</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Target URL</label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="http://localhost:8082/"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Max Endpoints</label>
              <input
                type="number"
                value={maxEndpoints}
                onChange={(e) => setMaxEndpoints(parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                min="1"
                max="100"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={handleCrawl}
                disabled={crawlingLoading}
                className="w-full bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {crawlingLoading ? 'Crawling...' : 'Start Crawling'}
              </button>
            </div>
          </div>

          {crawlingError && (
            <div className="bg-red-50 border border-red-200 rounded-md p-3 mb-4">
              <p className="text-red-800">Crawling Error: {crawlingError}</p>
            </div>
          )}

          {discoveredEndpoints.length > 0 && (
            <div className="space-y-4">
              <div className="bg-green-50 border border-green-200 rounded-md p-3">
                <p className="text-green-800">
                  ✅ Discovered {discoveredEndpoints.length} endpoints
                </p>
                <div className="mt-2 text-sm text-green-700">
                  {(() => {
                    const getCount = discoveredEndpoints.filter(ep => ep.method === 'GET').length;
                    const postCount = discoveredEndpoints.filter(ep => ep.method === 'POST').length;
                    const status200 = discoveredEndpoints.filter(ep => ep.status === 200).length;
                    const status401 = discoveredEndpoints.filter(ep => ep.status === 401).length;
                    const apiEndpoints = discoveredEndpoints.filter(ep => ep.type === 'api_pattern').length;
                    
                    return (
                      <div className="flex flex-wrap gap-4">
                        <span>GET: {getCount} | POST: {postCount}</span>
                        <span>200: {status200} | 401: {status401}</span>
                        <span>API: {apiEndpoints}</span>
                      </div>
                    );
                  })()}
                </div>
              </div>
              
              {/* Display discovered endpoints */}
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <h3 className="text-lg font-medium text-gray-900 mb-3">Discovered Endpoints</h3>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {discoveredEndpoints.map((endpoint, index) => (
                    <div key={index} className="flex items-center justify-between bg-white p-3 rounded border">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-sm text-blue-600">{endpoint.url}</span>
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            endpoint.method === 'GET' ? 'bg-green-100 text-green-800' : 
                            endpoint.method === 'POST' ? 'bg-orange-100 text-orange-800' : 
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {endpoint.method}
                          </span>
                        </div>
                        <div className="text-sm text-gray-600 mt-1">
                          Parameter: <code className="bg-gray-100 px-1 rounded">{endpoint.param}</code>
                          {endpoint.type && (
                            <span className="ml-2 text-xs text-gray-500">
                              Type: {endpoint.type} | Source: {endpoint.source}
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="text-right">
                        {endpoint.status && (
                          <span className={`text-xs px-2 py-1 rounded ${
                            endpoint.status === 200 ? 'bg-green-100 text-green-800' :
                            endpoint.status === 401 ? 'bg-yellow-100 text-yellow-800' :
                            endpoint.status === 403 ? 'bg-red-100 text-red-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {endpoint.status}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              
              {/* Continue button */}
              <div className="text-center">
                <button
                  onClick={() => setCurrentStep(2)}
                  className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700"
                >
                  Continue to ML Prediction →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Step 2: ML Prediction */}
        {discoveredEndpoints.length > 0 && (
          <div className="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Step 2: ML Vulnerability Prediction</h2>
            
            <div className="mb-4">
              <button
                onClick={handleMLPredict}
                disabled={predictionLoading || isTrainingModels}
                className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 disabled:opacity-50"
              >
                {isTrainingModels ? 'Training ML Models...' : predictionLoading ? 'ML Predicting...' : 'Run ML Prediction'}
              </button>
            </div>

            {predictionError && (
              <div className="bg-red-50 border border-red-200 rounded-md p-3 mb-4">
                <p className="text-red-800">ML Prediction Error: {predictionError}</p>
              </div>
            )}

            {predictions.length > 0 && (
              <div className="space-y-4">
                <div className="bg-green-50 border border-green-200 rounded-md p-3">
                  <p className="text-green-800">
                    🧠 ML found {predictions.length} potentially vulnerable endpoints
                  </p>
                </div>

                {predictions.map((prediction, index) => (
                  <div key={index} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-medium text-gray-900">
                        {prediction.endpoint.url}
                      </h3>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getVulnerabilityColor(prediction.predicted_vulnerability)}`}>
                          {prediction.predicted_vulnerability.toUpperCase()}
                        </span>
                        <span className={`text-sm font-medium ${getConfidenceColor(prediction.confidence)}`}>
                          {Math.round(prediction.confidence * 100)}% confidence
                        </span>
                      </div>
                    </div>
                    
                    <p className="text-sm text-gray-600 mb-3">
                      Parameter: {prediction.endpoint.param} | Method: {prediction.endpoint.method}
                    </p>

                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-gray-700">ML-Recommended Payloads:</h4>
                      {prediction.recommended_payloads.map((payload, payloadIndex) => (
                        <div key={payloadIndex} className="flex items-center justify-between bg-gray-50 p-2 rounded">
                          <div className="flex-1">
                            <code className="text-sm text-gray-800">{payload.payload}</code>
                            <span className="ml-2 text-xs text-gray-500">
                              Score: {payload.score.toFixed(2)} | Context: {payload.context}
                            </span>
                          </div>
                          <input
                            type="checkbox"
                            checked={selectedFuzzRequests.has(`${index}|${payloadIndex}`)}
                            onChange={() => toggleFuzzRequest(index, payloadIndex)}
                            className="ml-2"
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                ))}

                <div className="flex space-x-2">
                  <button
                    onClick={selectAllFuzzRequests}
                    className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
                  >
                    Select All
                  </button>
                  <button
                    onClick={clearSelection}
                    className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700"
                  >
                    Clear Selection
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Step 3: Real Fuzzing */}
        {predictions.length > 0 && (
          <div className="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Step 3: Real ML Fuzzing</h2>
            
            <div className="mb-4">
              <p className="text-sm text-gray-600 mb-2">
                Selected {selectedFuzzRequests.size} endpoint-payload combinations
              </p>
              <div className="flex space-x-2">
                <button
                  onClick={handleFuzzSelected}
                  disabled={fuzzingLoading || selectedFuzzRequests.size === 0}
                  className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 disabled:opacity-50"
                >
                  {fuzzingLoading ? 'Fuzzing...' : 'Fuzz Selected'}
                </button>
                <button
                  onClick={handleFuzzAll}
                  disabled={fuzzingLoading}
                  className="bg-orange-600 text-white px-4 py-2 rounded-md hover:bg-orange-700 disabled:opacity-50"
                >
                  {fuzzingLoading ? 'Fuzzing...' : 'Fuzz All'}
                </button>
              </div>
            </div>

            {fuzzingError && (
              <div className="bg-red-50 border border-red-200 rounded-md p-3 mb-4">
                <p className="text-red-800">Fuzzing Error: {fuzzingError}</p>
              </div>
            )}

            {results.length > 0 && (
              <div className="space-y-4">
                <div className="bg-green-50 border border-green-200 rounded-md p-3">
                  <p className="text-green-800">
                    🔥 Real fuzzing completed: {results.filter(r => r.vulnerability_detected).length} vulnerabilities found
                  </p>
                  <p className="text-sm text-green-700 mt-1">
                    💡 Click the links below to manually verify vulnerabilities in your browser
                  </p>
                </div>

                {results.map((result, index) => (
                  <div key={index} className={`border rounded-lg p-4 ${result.vulnerability_detected ? 'border-red-200 bg-red-50' : 'border-gray-200 bg-gray-50'}`}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex-1">
                        <h3 className="font-medium text-gray-900 mb-1">
                          {result.endpoint.url}
                        </h3>
                        <div className="flex items-center space-x-2">
                          <a 
                            href={(() => {
                              // Handle SPA routes for the base URL
                              let baseUrl = result.endpoint.url;
                              if (baseUrl.includes('/login') && !baseUrl.includes('#/')) {
                                baseUrl = baseUrl.replace('/login', '/#/login');
                              }
                              if (baseUrl.includes('/register') && !baseUrl.includes('#/')) {
                                baseUrl = baseUrl.replace('/register', '/#/register');
                              }
                              if (baseUrl.includes('/admin') && !baseUrl.includes('#/')) {
                                baseUrl = baseUrl.replace('/admin', '/#/admin');
                              }
                              return baseUrl;
                            })()}
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:text-blue-800 text-sm underline"
                          >
                            🔗 Open in new tab
                          </a>
                          <span className="text-gray-400">|</span>
                          <span className="text-sm text-gray-600">
                            {result.endpoint.method} | {result.endpoint.param}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${result.vulnerability_detected ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                          {result.vulnerability_detected ? 'VULNERABLE' : 'SAFE'}
                        </span>
                        <span className="text-sm text-gray-600">
                          {result.response_status} | {result.response_time.toFixed(2)}s
                        </span>
                        {result.evolution_info && (
                          <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">
                            🧬 ML Evolved
                          </span>
                        )}
                        {result.vulnerability_detected && (
                          <button
                            onClick={() => handleExploit(result)}
                            disabled={isExploiting}
                            className="text-xs bg-red-100 text-red-800 px-2 py-1 rounded hover:bg-red-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {isExploiting ? '⏳ Exploiting...' : '🎯 Exploit'}
                          </button>
                        )}
                      </div>
                    </div>
                    
                    {result.evolution_info && (
                      <div className="mb-2 p-2 bg-blue-50 rounded text-xs">
                        <div className="text-blue-700">
                          <strong>🧬 ML Evolution:</strong> {result.evolution_info.evolution_reason}
                        </div>
                        {result.evolution_info.original_payload && (
                          <div className="text-blue-600 mt-1">
                            <strong>Original:</strong> <code className="bg-blue-100 px-1 rounded">{result.evolution_info.original_payload}</code>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Exploitation Results */}
                    {exploitationResults[`${result.endpoint.url}-${result.payload}`] && (
                      <div className="mb-2 p-3 bg-green-50 border border-green-200 rounded">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-sm font-medium text-green-800">🎯 Exploitation Results</h4>
                          <span className={`text-xs px-2 py-1 rounded ${
                            exploitationResults[`${result.endpoint.url}-${result.payload}`].success 
                              ? 'bg-green-100 text-green-800' 
                              : 'bg-red-100 text-red-800'
                          }`}>
                            {exploitationResults[`${result.endpoint.url}-${result.payload}`].success ? 'SUCCESS' : 'FAILED'}
                          </span>
                        </div>
                        
                        {exploitationResults[`${result.endpoint.url}-${result.payload}`].success && (
                          <div className="space-y-2">
                            <div className="text-sm text-green-700">
                              <strong>Working Payload:</strong>
                              <code className="block bg-green-100 p-2 rounded mt-1 text-xs">
                                {exploitationResults[`${result.endpoint.url}-${result.payload}`].working_payload}
                              </code>
                            </div>
                            
                            {exploitationResults[`${result.endpoint.url}-${result.payload}`].extracted_data && (
                              <div className="text-sm text-green-700">
                                <strong>Extracted Data:</strong>
                                <div className="bg-green-100 p-2 rounded mt-1 text-xs max-h-32 overflow-y-auto">
                                  <pre>{exploitationResults[`${result.endpoint.url}-${result.payload}`].extracted_data}</pre>
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                        
                        {/* Attempt Details */}
                        {exploitationResults[`${result.endpoint.url}-${result.payload}`].attempts && (
                          <div className="mt-3">
                            <strong className="text-xs text-gray-700">🔬 Exploitation Attempts:</strong>
                            <div className="mt-1 space-y-2">
                              {exploitationResults[`${result.endpoint.url}-${result.payload}`].attempts.map((attempt, idx) => (
                                <div key={idx} className="bg-gray-50 p-2 rounded text-xs">
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="font-medium">Attempt {attempt.attempt}</span>
                                    <span className={`px-2 py-1 rounded text-xs ${
                                      attempt.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                                    }`}>
                                      {attempt.success ? 'SUCCESS' : 'FAILED'}
                                    </span>
                                  </div>
                                  <div className="text-gray-600">
                                    <strong>Payload:</strong> <code className="bg-gray-200 px-1 rounded">{attempt.payload}</code>
                                  </div>
                                  <div className="text-gray-600">
                                    <strong>Description:</strong> {attempt.description}
                                  </div>
                                  <div className="text-gray-600">
                                    <strong>Status:</strong> {attempt.response_status} | <strong>Time:</strong> {attempt.response_time.toFixed(3)}s
                                  </div>
                                  {attempt.response_preview && (
                                    <div className="text-gray-600 mt-1">
                                      <strong>Response:</strong> {attempt.response_preview.substring(0, 100)}...
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        <div className="text-xs text-green-600 mt-2">
                          <strong>Database Type:</strong> {exploitationResults[`${result.endpoint.url}-${result.payload}`].error_analysis?.database_type || 'Unknown'}
                          <br />
                          <strong>Confidence:</strong> {(exploitationResults[`${result.endpoint.url}-${result.payload}`].confidence * 100).toFixed(1)}%
                          <br />
                          <strong>Exploitation Type:</strong> {exploitationResults[`${result.endpoint.url}-${result.payload}`].exploitation_type}
                        </div>
                        
                        {/* Detailed Evidence */}
                        {exploitationResults[`${result.endpoint.url}-${result.payload}`].error_analysis?.evidence && (
                          <div className="mt-2">
                            <strong className="text-xs text-green-700">🔍 Evidence:</strong>
                            <ul className="text-xs text-green-600 mt-1 space-y-1">
                              {exploitationResults[`${result.endpoint.url}-${result.payload}`].error_analysis.evidence.map((evidence, idx) => (
                                <li key={idx} className="flex items-start">
                                  <span className="mr-1">•</span>
                                  <span>{evidence}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                        
                        {/* Failure Reasons */}
                        {exploitationResults[`${result.endpoint.url}-${result.payload}`].error_analysis?.failure_reasons && (
                          <div className="mt-2">
                            <strong className="text-xs text-red-700">❌ Why it failed:</strong>
                            <ul className="text-xs text-red-600 mt-1 space-y-1">
                              {exploitationResults[`${result.endpoint.url}-${result.payload}`].error_analysis.failure_reasons.map((reason, idx) => (
                                <li key={idx} className="flex items-start">
                                  <span className="mr-1">•</span>
                                  <span>{reason}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                        
                        {/* Suggestions */}
                        {exploitationResults[`${result.endpoint.url}-${result.payload}`].suggestions && (
                          <div className="mt-2">
                            <strong className="text-xs text-blue-700">💡 Suggestions:</strong>
                            <ul className="text-xs text-blue-600 mt-1 space-y-1">
                              {exploitationResults[`${result.endpoint.url}-${result.payload}`].suggestions.map((suggestion, idx) => (
                                <li key={idx} className="flex items-start">
                                  <span className="mr-1">•</span>
                                  <span>{suggestion}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                    
                    <div className="mb-2">
                      <div className="flex items-center justify-between">
                        <code className="text-sm text-gray-800 bg-white p-1 rounded flex-1 mr-2">
                          {result.payload}
                        </code>
                        <a 
                          href={(() => {
                            // Handle SPA routes and special cases
                            let testUrl = result.endpoint.url;
                            
                            // Fix SPA routes
                            if (testUrl.includes('/login') && !testUrl.includes('#/')) {
                              testUrl = testUrl.replace('/login', '/#/login');
                            }
                            if (testUrl.includes('/register') && !testUrl.includes('#/')) {
                              testUrl = testUrl.replace('/register', '/#/register');
                            }
                            if (testUrl.includes('/admin') && !testUrl.includes('#/')) {
                              testUrl = testUrl.replace('/admin', '/#/admin');
                            }
                            
                            // Add payload parameter
                            const separator = testUrl.includes('?') ? '&' : '?';
                            return `${testUrl}${separator}${result.endpoint.param}=${encodeURIComponent(result.payload)}`;
                          })()}
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-800 text-sm underline whitespace-nowrap"
                        >
                          🧪 Test with payload
                        </a>
                      </div>
                    </div>

                    {result.vulnerability_detected && (
                      <div className="mb-2">
                        <p className="text-sm font-medium text-red-800">Evidence:</p>
                        <ul className="text-sm text-red-700 list-disc list-inside">
                          {result.evidence.map((evidence, i) => (
                            <li key={i}>{evidence}</li>
                          ))}
                        </ul>
                        <p className="text-sm text-gray-600 mt-1">
                          Confidence: {Math.round(result.confidence_score * 100)}%
                        </p>
                      </div>
                    )}

                    <details className="text-sm text-gray-600">
                      <summary className="cursor-pointer">Response Preview</summary>
                      <pre className="mt-2 p-2 bg-white rounded text-xs overflow-auto max-h-32">
                        {result.response_preview}
                      </pre>
                    </details>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Clear All Button */}
        <div className="text-center">
          <button
            onClick={handleClearAll}
            className="bg-gray-600 text-white px-6 py-2 rounded-md hover:bg-gray-700"
          >
            Clear All
          </button>
        </div>
      </div>
    </div>
  );
}