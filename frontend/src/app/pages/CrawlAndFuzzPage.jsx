"use client";
import { useState, useCallback } from "react";
import { 
  crawlTarget, 
  predictVulnerabilities, 
  enhancedFuzz, 
  trainModels, 
  getMLStatus,
  getEvidence 
} from "../api/api";

// Hook for enhanced crawling
const useEnhancedCrawler = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState([]);
  const [error, setError] = useState(null);

  const crawlTargetUrl = useCallback(async (targetUrl, maxEndpoints = 20) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await crawlTarget({ 
        target_url: targetUrl, 
        max_endpoints: maxEndpoints,
        max_depth: 3,
        max_pages: 12
      });
      setDiscoveredEndpoints(data.endpoints || []);
      console.log(`Discovered ${data.endpoints?.length || 0} endpoints from ${targetUrl}`);
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
    crawlTargetUrl,
    clearEndpoints,
    isLoading,
    discoveredEndpoints,
    error
  };
};

// Hook for ML prediction with probe-enhanced workflow
const useMLPrediction = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [predictions, setPredictions] = useState([]);
  const [error, setError] = useState(null);

  const predictVulns = useCallback(async (endpoints) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await predictVulnerabilities(endpoints, 5);
      setPredictions(data.findings || []);
      console.log(`ML predictions completed: ${data.findings?.length || 0} findings`);
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
    predictVulns,
    clearPredictions,
    isLoading,
    predictions,
    error
  };
};

// Hook for enhanced fuzzing
const useEnhancedFuzzer = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);

  const fuzzTargets = useCallback(async (targets) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await enhancedFuzz(targets, 5);
      setResults(data.results || []);
      console.log(`Enhanced fuzzing completed: ${data.results?.length || 0} results`);
      return data;
    } catch (err) {
      setError(err.message);
      console.error(`Enhanced fuzzing failed: ${err.message}`);
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
    fuzzTargets,
    clearResults,
    isLoading,
    results,
    error
  };
};

// Hook for ML model management
const useMLModels = () => {
  const [isTraining, setIsTraining] = useState(false);
  const [mlStatus, setMLStatus] = useState(null);
  const [error, setError] = useState(null);

  const trainMLModels = useCallback(async () => {
    setIsTraining(true);
    setError(null);
    
    try {
      const data = await trainModels();
      console.log("ML models trained:", data.message);
      return data;
    } catch (err) {
      setError(err.message);
      console.error(`ML training failed: ${err.message}`);
      throw err;
    } finally {
      setIsTraining(false);
    }
  }, []);

  const checkMLStatus = useCallback(async () => {
    try {
      const data = await getMLStatus();
      setMLStatus(data);
      return data;
    } catch (err) {
      setError(err.message);
      console.error(`ML status check failed: ${err.message}`);
      throw err;
    }
  }, []);

  return {
    trainMLModels,
    checkMLStatus,
    isTraining,
    mlStatus,
    error
  };
};

export default function CrawlAndFuzzPage() {
  // Hooks for different stages
  const {
    crawlTargetUrl,
    clearEndpoints,
    isLoading: crawlingLoading,
    discoveredEndpoints,
    error: crawlingError
  } = useEnhancedCrawler();

  const {
    predictVulns,
    clearPredictions,
    isLoading: predictionLoading,
    predictions,
    error: predictionError
  } = useMLPrediction();

  const {
    fuzzTargets,
    clearResults,
    isLoading: fuzzingLoading,
    results,
    error: fuzzingError
  } = useEnhancedFuzzer();

  const {
    trainMLModels,
    checkMLStatus,
    isTraining,
    mlStatus,
    error: mlError
  } = useMLModels();

  // State management
  const [targetUrl, setTargetUrl] = useState("http://localhost:5001/");
  const [maxEndpoints, setMaxEndpoints] = useState(20);
  const [currentStep, setCurrentStep] = useState(1); // 1: Crawl, 2: Predict, 3: Fuzz
  const [selectedTargets, setSelectedTargets] = useState(new Set());
  const [jobId, setJobId] = useState(null);

  // Step 1: Crawling
  const handleCrawl = useCallback(async () => {
    if (!targetUrl.trim()) {
      alert("Please enter a target URL");
      return;
    }
    
    try {
      const data = await crawlTargetUrl(targetUrl, maxEndpoints);
      setJobId(data.job_id || `crawl-${Date.now()}`);
      setCurrentStep(2);
    } catch (err) {
      console.error("Crawling failed:", err);
    }
  }, [targetUrl, maxEndpoints, crawlTargetUrl]);

  // Step 2: ML Prediction
  const handleMLPredict = useCallback(async () => {
    if (discoveredEndpoints.length === 0) {
      alert("Please crawl endpoints first");
      return;
    }
    
    try {
      // First, ensure ML models are trained
      console.log("🧠 Ensuring ML models are trained...");
      await trainMLModels();
      
      // Now run ML prediction
      await predictVulns(discoveredEndpoints);
      setCurrentStep(3);
    } catch (err) {
      console.error("ML prediction failed:", err);
    }
  }, [discoveredEndpoints, predictVulns, trainMLModels]);

  // Step 3: Enhanced Fuzzing
  const handleFuzzSelected = useCallback(async () => {
    if (selectedTargets.size === 0) {
      alert("Please select targets to fuzz");
      return;
    }

    const targets = Array.from(selectedTargets).map(index => {
      const prediction = predictions[index];
      return {
        url: prediction.target?.url || prediction.url,
        param: prediction.target?.param || prediction.param,
        method: prediction.target?.method || prediction.method || 'GET'
      };
    });

    try {
      await fuzzTargets(targets);
    } catch (err) {
      console.error("Fuzzing failed:", err);
    }
  }, [selectedTargets, predictions, fuzzTargets]);

  const handleFuzzAll = useCallback(async () => {
    if (predictions.length === 0) {
      alert("Please run ML prediction first");
      return;
    }

    const targets = predictions.map(prediction => ({
      url: prediction.target?.url || prediction.url,
      param: prediction.target?.param || prediction.param,
      method: prediction.target?.method || prediction.method || 'GET'
    }));

    try {
      await fuzzTargets(targets);
    } catch (err) {
      console.error("Fuzzing failed:", err);
    }
  }, [predictions, fuzzTargets]);

  const toggleTarget = useCallback((index) => {
    setSelectedTargets(prev => {
      const newSet = new Set(prev);
      if (newSet.has(index)) {
        newSet.delete(index);
      } else {
        newSet.add(index);
      }
      return newSet;
    });
  }, []);

  const selectAllTargets = useCallback(() => {
    setSelectedTargets(new Set(predictions.map((_, index) => index)));
  }, [predictions]);

  const clearSelection = useCallback(() => {
    setSelectedTargets(new Set());
  }, []);

  const handleClearAll = useCallback(() => {
    clearEndpoints();
    clearPredictions();
    clearResults();
    setSelectedTargets(new Set());
    setCurrentStep(1);
    setJobId(null);
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

  const getCVSSColor = (score) => {
    if (score >= 7.0) return 'text-red-600';
    if (score >= 4.0) return 'text-yellow-600';
    return 'text-green-600';
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Probe-Enhanced ML Vulnerability Scanner
          </h1>
          <p className="text-gray-600">
            Dynamic crawling → Probe evidence → ML triage → Structured findings
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
                placeholder="http://localhost:5001/"
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
                    const withParams = discoveredEndpoints.filter(ep => ep.param_locs && 
                      (ep.param_locs.query?.length > 0 || ep.param_locs.form?.length > 0 || ep.param_locs.json?.length > 0)).length;
                    
                    return (
                      <div className="flex flex-wrap gap-4">
                        <span>GET: {getCount} | POST: {postCount}</span>
                        <span>200: {status200} | 401: {status401}</span>
                        <span>With Params: {withParams}</span>
                      </div>
                    );
                  })()}
                </div>
              </div>
              
              {/* Display discovered endpoints */}
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <h3 className="text-lg font-medium text-gray-900 mb-3">Discovered Endpoints</h3>
                {discoveredEndpoints.length > 300 && (
                  <div className="text-xs text-gray-500 mb-2">
                    Showing 300 of {discoveredEndpoints.length} endpoints
                  </div>
                )}
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {discoveredEndpoints.slice(0, 300).map((endpoint, index) => (
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
                          {endpoint.param_locs && (
                            <>
                              Query: {endpoint.param_locs.query?.join(', ') || 'none'} | 
                              Form: {endpoint.param_locs.form?.join(', ') || 'none'} | 
                              JSON: {endpoint.param_locs.json?.join(', ') || 'none'}
                            </>
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
                disabled={predictionLoading || isTraining}
                className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 disabled:opacity-50"
              >
                {isTraining ? 'Training ML Models...' : predictionLoading ? 'ML Predicting...' : 'Run ML Prediction'}
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
                    🧠 ML found {predictions.length} potentially vulnerable targets
                  </p>
                </div>

                {predictions.map((prediction, index) => (
                  <div key={index} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-medium text-gray-900">
                        {prediction.target?.url || prediction.url || 'Unknown URL'}
                      </h3>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getVulnerabilityColor(prediction.vulnerability_type)}`}>
                          {prediction.vulnerability_type?.toUpperCase() || 'UNKNOWN'}
                        </span>
                        {prediction.ml_confidence && (
                          <span className={`text-sm font-medium ${getConfidenceColor(prediction.ml_confidence)}`}>
                            {Math.round(prediction.ml_confidence * 100)}% confidence
                          </span>
                        )}
                        {prediction.cvss_base_score && (
                          <span className={`text-sm font-medium ${getCVSSColor(prediction.cvss_base_score)}`}>
                            CVSS: {prediction.cvss_base_score}
                          </span>
                        )}
                      </div>
                    </div>
                    
                    <p className="text-sm text-gray-600 mb-3">
                      Parameter: {prediction.target?.param || prediction.param || 'Unknown'} | 
                      Method: {prediction.target?.method || prediction.method || 'Unknown'} |
                      Location: {prediction.target?.param_in || prediction.param_in || 'Unknown'}
                    </p>

                    {/* Probe Results */}
                    {prediction.probe_results && (
                      <div className="mb-3 p-3 bg-blue-50 rounded">
                        <h4 className="text-sm font-medium text-blue-800 mb-2">🔍 Probe Evidence:</h4>
                        <div className="text-xs text-blue-700 space-y-1">
                          {prediction.probe_results.xss_context && (
                            <div>XSS Context: <span className="font-mono">{prediction.probe_results.xss_context}</span></div>
                          )}
                          {prediction.probe_results.redirect_influence !== undefined && (
                            <div>Redirect Influence: <span className="font-mono">{prediction.probe_results.redirect_influence ? 'Yes' : 'No'}</span></div>
                          )}
                          {prediction.probe_results.sqli_error_based !== undefined && (
                            <div>SQLi Error: <span className="font-mono">{prediction.probe_results.sqli_error_based ? 'Yes' : 'No'}</span></div>
                          )}
                          {prediction.probe_results.sqli_boolean_delta && (
                            <div>SQLi Boolean Delta: <span className="font-mono">{prediction.probe_results.sqli_boolean_delta.toFixed(3)}</span></div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Evidence */}
                    {prediction.evidence && prediction.evidence.length > 0 && (
                      <div className="mb-3">
                        <h4 className="text-sm font-medium text-gray-700 mb-1">Evidence:</h4>
                        <ul className="text-sm text-gray-600 list-disc list-inside">
                          {prediction.evidence.map((evidence, i) => (
                            <li key={i}>{evidence}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Selection checkbox */}
                    <div className="flex items-center">
                      <input
                        type="checkbox"
                        checked={selectedTargets.has(index)}
                        onChange={() => toggleTarget(index)}
                        className="mr-2"
                      />
                      <span className="text-sm text-gray-600">Select for fuzzing</span>
                    </div>
                  </div>
                ))}

                <div className="flex space-x-2">
                  <button
                    onClick={selectAllTargets}
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

        {/* Step 3: Enhanced Fuzzing */}
        {predictions.length > 0 && (
          <div className="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Step 3: Enhanced Fuzzing</h2>
            
            <div className="mb-4">
              <p className="text-sm text-gray-600 mb-2">
                Selected {selectedTargets.size} targets for fuzzing
              </p>
              <div className="flex space-x-2">
                <button
                  onClick={handleFuzzSelected}
                  disabled={fuzzingLoading || selectedTargets.size === 0}
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
                    🔥 Enhanced fuzzing completed: {results.filter(r => r.vulnerability_type).length} vulnerabilities found
                  </p>
                </div>

                {results.map((result, index) => (
                  <div key={index} className={`border rounded-lg p-4 ${result.vulnerability_type ? 'border-red-200 bg-red-50' : 'border-gray-200 bg-gray-50'}`}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex-1">
                        <h3 className="font-medium text-gray-900 mb-1">
                          {result.url}
                        </h3>
                        <div className="flex items-center space-x-2">
                          <a 
                            href={result.url}
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:text-blue-800 text-sm underline"
                          >
                            🔗 Open in new tab
                          </a>
                          <span className="text-gray-400">|</span>
                          <span className="text-sm text-gray-600">
                            {result.method} | {result.param} ({result.param_in})
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        {result.vulnerability_type && (
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getVulnerabilityColor(result.vulnerability_type)}`}>
                            {result.vulnerability_type.toUpperCase()}
                          </span>
                        )}
                        {result.cvss_base_score && (
                          <span className={`text-sm font-medium ${getCVSSColor(result.cvss_base_score)}`}>
                            CVSS: {result.cvss_base_score}
                          </span>
                        )}
                        {result.ml_confidence && (
                          <span className={`text-sm font-medium ${getConfidenceColor(result.ml_confidence)}`}>
                            {Math.round(result.ml_confidence * 100)}%
                          </span>
                        )}
                      </div>
                    </div>
                    
                    {/* Evidence */}
                    {result.evidence && result.evidence.length > 0 && (
                      <div className="mb-2">
                        <p className="text-sm font-medium text-red-800">Evidence:</p>
                        <ul className="text-sm text-red-700 list-disc list-inside">
                          {result.evidence.map((evidence, i) => (
                            <li key={i}>{evidence}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Probe Results */}
                    {result.probe_results && (
                      <div className="mb-2 p-2 bg-blue-50 rounded text-xs">
                        <div className="text-blue-700">
                          <strong>🔍 Probe Evidence:</strong>
                          {result.probe_results.xss_context && (
                            <span className="ml-2">XSS: {result.probe_results.xss_context}</span>
                          )}
                          {result.probe_results.redirect_influence !== undefined && (
                            <span className="ml-2">Redirect: {result.probe_results.redirect_influence ? 'Yes' : 'No'}</span>
                          )}
                          {result.probe_results.sqli_error_based !== undefined && (
                            <span className="ml-2">SQLi: {result.probe_results.sqli_error_based ? 'Yes' : 'No'}</span>
                          )}
                        </div>
                      </div>
                    )}
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