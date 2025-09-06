"use client";
import { useState, useCallback } from "react";
import { 
  crawl, 
  mlPredict, 
  fuzz
} from "../../lib/api";
import EndpointTable from "../../components/EndpointTable";

// Hook for enhanced crawling
const useEnhancedCrawler = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState([]);
  const [crawlMeta, setCrawlMeta] = useState(null);
  const [error, setError] = useState(null);

  const crawlTargetUrl = useCallback(async (targetUrl, maxEndpoints = 20, maxDepth = 2, submitGetForms = true, submitPostForms = true, clickButtons = true, auth = null) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await crawl({ 
        target_url: targetUrl, 
        max_endpoints: maxEndpoints,
        max_depth: maxDepth,
        submit_get_forms: submitGetForms,
        submit_post_forms: submitPostForms,
        click_buttons: clickButtons,
        seeds: [],
        auth: auth
      });
      setDiscoveredEndpoints(data.endpoints || []);
      setCrawlMeta(data.meta || null);
      console.log(`Discovered ${data.endpoints?.length || 0} endpoints from ${targetUrl}`);
      console.log(`Crawl meta:`, data.meta);
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
    setCrawlMeta(null);
    setError(null);
  }, []);

  return {
    crawlTargetUrl,
    clearEndpoints,
    isLoading,
    discoveredEndpoints,
    crawlMeta,
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
      const data = await mlPredict(endpoints);
      setPredictions(data || []);
      console.log(`ML predictions completed: ${data?.length || 0} predictions`);
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

  const fuzzTargets = useCallback(async (predictions) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await fuzz(predictions);
      setResults(data || []);
      console.log(`Enhanced fuzzing completed: ${data?.length || 0} results`);
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

// ML model management removed - not part of canonical API

export default function CrawlAndFuzzPage() {
  // Hooks for different stages
  const {
    crawlTargetUrl,
    clearEndpoints,
    isLoading: crawlingLoading,
    discoveredEndpoints,
    crawlMeta,
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

  // ML model management removed - not part of canonical API

  // State management
  const [targetUrl, setTargetUrl] = useState("http://localhost:5001/");
  const [maxEndpoints, setMaxEndpoints] = useState(20);
  const [maxDepth, setMaxDepth] = useState(2);
  const [submitGetForms, setSubmitGetForms] = useState(true);
  const [submitPostForms, setSubmitPostForms] = useState(true);
  const [clickButtons, setClickButtons] = useState(true);
  const [authJson, setAuthJson] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [currentStep, setCurrentStep] = useState(1); // 1: Crawl, 2: Predict, 3: Fuzz
  const [selectedTargets, setSelectedTargets] = useState(new Set());
  const [jobId, setJobId] = useState(null);

  // Step 1: Crawling
  const handleCrawl = useCallback(async () => {
    if (!targetUrl.trim()) {
      alert("Please enter a target URL");
      return;
    }
    
    // Parse auth JSON if provided
    let auth = null;
    if (authJson.trim()) {
      try {
        auth = JSON.parse(authJson);
      } catch (err) {
        alert("Invalid auth JSON: " + err.message);
        return;
      }
    }
    
    try {
      const data = await crawlTargetUrl(targetUrl, maxEndpoints, maxDepth, submitGetForms, submitPostForms, clickButtons, auth);
      setJobId(data.job_id || `crawl-${Date.now()}`);
      setCurrentStep(2);
    } catch (err) {
      console.error("Crawling failed:", err);
    }
  }, [targetUrl, maxEndpoints, maxDepth, submitGetForms, submitPostForms, clickButtons, authJson, crawlTargetUrl]);

  // Step 2: ML Prediction
  const handleMLPredict = useCallback(async () => {
    if (discoveredEndpoints.length === 0) {
      alert("Please crawl endpoints first");
      return;
    }
    
    try {
      // Run ML prediction
      await predictVulns(discoveredEndpoints);
      setCurrentStep(3);
    } catch (err) {
      console.error("ML prediction failed:", err);
    }
  }, [discoveredEndpoints, predictVulns]);

  // Step 3: Enhanced Fuzzing
  const handleFuzzSelected = useCallback(async () => {
    if (selectedTargets.size === 0) {
      alert("Please select targets to fuzz");
      return;
    }

    const selectedPredictions = Array.from(selectedTargets).map(index => predictions[index]);

    try {
      await fuzzTargets(selectedPredictions);
    } catch (err) {
      console.error("Fuzzing failed:", err);
    }
  }, [selectedTargets, predictions, fuzzTargets]);

  const handleFuzzAll = useCallback(async () => {
    if (predictions.length === 0) {
      alert("Please run ML prediction first");
      return;
    }

    try {
      await fuzzTargets(predictions);
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
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Max Depth</label>
              <input
                type="number"
                value={maxDepth}
                onChange={(e) => setMaxDepth(parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                min="1"
                max="5"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div className="flex items-center">
              <input
                type="checkbox"
                id="submitGetForms"
                checked={submitGetForms}
                onChange={(e) => setSubmitGetForms(e.target.checked)}
                className="mr-2"
              />
              <label htmlFor="submitGetForms" className="text-sm font-medium text-gray-700">
                Submit GET forms
              </label>
            </div>
            <div className="flex items-center">
              <input
                type="checkbox"
                id="submitPostForms"
                checked={submitPostForms}
                onChange={(e) => setSubmitPostForms(e.target.checked)}
                className="mr-2"
              />
              <label htmlFor="submitPostForms" className="text-sm font-medium text-gray-700">
                Submit POST forms
              </label>
            </div>
            <div className="flex items-center">
              <input
                type="checkbox"
                id="clickButtons"
                checked={clickButtons}
                onChange={(e) => setClickButtons(e.target.checked)}
                className="mr-2"
              />
              <label htmlFor="clickButtons" className="text-sm font-medium text-gray-700">
                Click buttons (may trigger XHR)
              </label>
            </div>
          </div>

          {/* Auth Section */}
          <div className="mb-4">
            <button
              onClick={() => setShowAuth(!showAuth)}
              className="text-sm text-blue-600 hover:text-blue-800 underline"
            >
              {showAuth ? 'Hide' : 'Show'} Authentication (Optional)
            </button>
            {showAuth && (
              <div className="mt-2">
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Auth JSON (form-based login)
                </label>
                <textarea
                  value={authJson}
                  onChange={(e) => setAuthJson(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  rows="6"
                  placeholder={`{
  "type": "form",
  "login_url": "http://localhost:5001/login",
  "username_field": "username",
  "password_field": "password",
  "username": "admin",
  "password": "admin"
}`}
                />
                <p className="text-xs text-gray-500 mt-1">
                  Leave empty for public sites. JSON format for form-based authentication.
                </p>
              </div>
            )}
          </div>

          <div className="mb-4">
            <button
              onClick={handleCrawl}
              disabled={crawlingLoading}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              {crawlingLoading ? 'Crawling...' : 'Start Crawling'}
            </button>
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
              <EndpointTable endpoints={discoveredEndpoints} meta={crawlMeta} />
              
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
                disabled={predictionLoading}
                className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 disabled:opacity-50"
              >
                {predictionLoading ? 'ML Predicting...' : 'Run ML Prediction'}
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
                        {prediction.endpoint?.url || 'Unknown URL'}
                      </h3>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getVulnerabilityColor(prediction.family)}`}>
                          {prediction.family?.toUpperCase() || 'NONE'}
                        </span>
                        {prediction.confidence && (
                          <span className={`text-sm font-medium ${getConfidenceColor(prediction.confidence)}`}>
                            {Math.round(prediction.confidence * 100)}% confidence
                          </span>
                        )}
                        <span className="text-sm text-gray-500">
                          Features: {prediction.features_used || 48}
                        </span>
                      </div>
                    </div>
                    
                    <p className="text-sm text-gray-600 mb-3">
                      Method: {prediction.endpoint?.method || 'Unknown'} | 
                      Params: {prediction.endpoint?.params?.join(', ') || 'None'} |
                      Calibrated: {prediction.calibrated ? 'Yes' : 'No'}
                    </p>

                    {/* Canonical ML prediction doesn't include probe results or evidence */}

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
                    🔥 Enhanced fuzzing completed: {results.filter(r => r.family && r.family !== 'none').length} vulnerabilities found
                  </p>
                </div>

                {results.map((result, index) => (
                  <div key={index} className={`border rounded-lg p-4 ${result.family && result.family !== 'none' ? 'border-red-200 bg-red-50' : 'border-gray-200 bg-gray-50'}`}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex-1">
                        <h3 className="font-medium text-gray-900 mb-1">
                          {result.endpoint?.url || 'Unknown URL'}
                        </h3>
                        <div className="flex items-center space-x-2">
                          <a 
                            href={result.endpoint?.url}
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:text-blue-800 text-sm underline"
                          >
                            🔗 Open in new tab
                          </a>
                          <span className="text-gray-400">|</span>
                          <span className="text-sm text-gray-600">
                            {result.endpoint?.method} | {result.endpoint?.params?.join(', ') || 'No params'}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        {result.family && result.family !== 'none' && (
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getVulnerabilityColor(result.family)}`}>
                            {result.family.toUpperCase()}
                          </span>
                        )}
                        {result.cvss?.base && (
                          <span className={`text-sm font-medium ${getCVSSColor(result.cvss.base)}`}>
                            CVSS: {result.cvss.base} ({result.cvss.severity})
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
                            <li key={i}>{evidence.detail || evidence}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Signals */}
                    {result.signals && (
                      <div className="mb-2 p-2 bg-blue-50 rounded text-xs">
                        <div className="text-blue-700">
                          <strong>🔍 Signals:</strong>
                          {result.signals.sql_error && <span className="ml-2">SQL Error: Yes</span>}
                          {result.signals.xss_raw && <span className="ml-2">XSS Raw: Yes</span>}
                          {result.signals.xss_js && <span className="ml-2">XSS JS: Yes</span>}
                          {result.signals.open_redirect && <span className="ml-2">Open Redirect: Yes</span>}
                        </div>
                      </div>
                    )}

                    {/* Rationale */}
                    {result.rationale && (
                      <div className="mb-2 p-2 bg-gray-50 rounded text-xs">
                        <div className="text-gray-700">
                          <strong>💭 Rationale:</strong> {result.rationale}
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