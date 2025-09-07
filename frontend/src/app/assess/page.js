"use client";
import { useState, useCallback } from "react";
import { 
  crawl, 
  assess,
  getReport
} from "../../lib/api";

// Utility function to build cURL command
function buildCurl(ev) {
  const h = ev.request_headers || {};
  const head = Object.entries(h).map(([k,v])=>`-H ${JSON.stringify(`${k}: ${v}`)}`).join(" ");
  return `curl -i -X ${ev.method} ${head} ${JSON.stringify(ev.url)}`;
}

// Hook for the complete workflow: Crawl → Assess
const useWorkflow = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [endpoints, setEndpoints] = useState([]);
  const [assessment, setAssessment] = useState(null);
  const [crawlMeta, setCrawlMeta] = useState(null);
  const [error, setError] = useState(null);

  const runWorkflow = useCallback(async (targetUrl, options = {}) => {
    setIsLoading(true);
    setError(null);
    setEndpoints([]);
    setAssessment(null);
    setCrawlMeta(null);
    
    try {
      // Step 1: Crawl
      console.log("🔍 Starting crawl...");
      const crawlData = await crawl({
        target_url: targetUrl,
        max_depth: options.maxDepth || 2,
        max_endpoints: options.maxEndpoints || 30,
        submit_get_forms: options.submitGetForms !== false,
        submit_post_forms: options.submitPostForms !== false,
        seeds: options.seeds || []
      });
      
      setEndpoints(crawlData.endpoints || []);
      setCrawlMeta(crawlData.meta || null);
      console.log(`✅ Crawl completed: ${crawlData.endpoints?.length || 0} endpoints`);
      
      if (!crawlData.endpoints?.length) {
        throw new Error("No endpoints discovered");
      }
      
      // Step 2: Assess (automatically called on crawl success)
      console.log("🔍 Starting assessment...");
      const jobId = Date.now().toString(); // Generate job_id as requested
      const assessData = await assess({
        endpoints: crawlData.endpoints,
        job_id: jobId,
        top_k: options.topK || 3
      });
      
      setAssessment(assessData);
      console.log(`✅ Assessment completed: ${assessData.findings?.length || 0} findings`);
      
      return assessData;
    } catch (err) {
      setError(err.message);
      console.error(`Workflow failed: ${err.message}`);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const clearWorkflow = useCallback(() => {
    setEndpoints([]);
    setAssessment(null);
    setCrawlMeta(null);
    setError(null);
  }, []);

  return {
    runWorkflow,
    clearWorkflow,
    isLoading,
    endpoints,
    assessment,
    crawlMeta,
    error
  };
};

// Tab component for findings
function FindingsTab({ title, findings, emptyMessage }) {
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [reportModal, setReportModal] = useState(null);

  const toggleExpanded = (index) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedRows(newExpanded);
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      // You could add a toast notification here
    } catch (err) {
      console.error('Failed to copy: ', err);
    }
  };

  const runPoC = (finding) => {
    // This would trigger a PoC exploit
    console.log("Running PoC for:", finding);
    alert(`PoC exploit would be triggered for ${finding.family} vulnerability`);
  };

  const exportReport = async (jobId) => {
    try {
      const report = await getReport(jobId);
      setReportModal(report.markdown);
    } catch (err) {
      console.error("Failed to export report:", err);
      alert("Failed to export report");
    }
  };

  if (!findings?.length) {
    return (
      <div className="p-4 text-center text-gray-500">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {findings.map((finding, index) => (
        <div key={index} className="border rounded-lg p-4 bg-white">
          <div className="flex items-center justify-between mb-2">
            <div className="flex-1">
              <div className="font-medium text-sm">
                {finding.url} ({finding.param_in}:{finding.param})
              </div>
              <div className="text-xs text-gray-600">
                {finding.family.toUpperCase()} • CVSS: {finding.cvss?.base || 'N/A'}
              </div>
            </div>
            <div className="flex space-x-2">
              <button
                onClick={() => copyToClipboard(buildCurl(finding))}
                className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200"
              >
                Copy cURL
              </button>
              {(finding.family === 'sqli' || finding.family === 'xss') && (
                <button
                  onClick={() => runPoC(finding)}
                  className="px-2 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200"
                >
                  Run PoC
                </button>
              )}
              <button
                onClick={() => toggleExpanded(index)}
                className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
              >
                {expandedRows.has(index) ? 'Hide' : 'Show'} Details
              </button>
            </div>
          </div>
          
          {expandedRows.has(index) && (
            <div className="mt-3 pt-3 border-t">
              <div className="text-xs text-gray-600 mb-2">
                <strong>Why:</strong> {finding.why?.join(', ') || 'N/A'}
              </div>
              <div className="text-xs">
                <strong>Response Snippet:</strong>
                <pre className="mt-1 p-2 bg-gray-50 rounded text-xs overflow-auto max-h-32">
                  {finding.response_snippet || 'N/A'}
                </pre>
              </div>
            </div>
          )}
        </div>
      ))}
      
      {/* Report Modal */}
      {reportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-4xl max-h-[80vh] overflow-auto">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Export Report</h3>
              <button
                onClick={() => setReportModal(null)}
                className="text-gray-500 hover:text-gray-700"
              >
                ✕
              </button>
            </div>
            <pre className="bg-gray-50 p-4 rounded text-sm overflow-auto max-h-96">
              {reportModal}
            </pre>
            <div className="mt-4 flex justify-end space-x-2">
              <button
                onClick={() => copyToClipboard(reportModal)}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Copy Markdown
              </button>
              <button
                onClick={() => setReportModal(null)}
                className="px-4 py-2 bg-gray-300 text-gray-700 rounded hover:bg-gray-400"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function AssessPage() {
  const {
    runWorkflow,
    clearWorkflow,
    isLoading,
    endpoints,
    assessment,
    crawlMeta,
    error
  } = useWorkflow();

  const [targetUrl, setTargetUrl] = useState("");
  const [options, setOptions] = useState({
    maxDepth: 2,
    maxEndpoints: 30,
    submitGetForms: true,
    submitPostForms: true,
    topK: 3
  });
  const [activeTab, setActiveTab] = useState("confirmed");

  const handleRunWorkflow = async () => {
    if (!targetUrl.trim()) {
      alert("Please enter a target URL");
      return;
    }
    
    try {
      await runWorkflow(targetUrl, options);
      setActiveTab("confirmed");
    } catch (err) {
      // Error is handled by the hook
    }
  };

  // Categorize findings
  const confirmedFindings = assessment?.findings?.filter(f => f.family && f.family !== 'none') || [];
  const suspectedFindings = []; // No suspected findings in current workflow
  const cleanResults = assessment?.results?.filter(r => r.decision === 'tested_negative') || [];

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Vulnerability Assessment</h1>
        <a
          href="/"
          className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
        >
          ← Back to Home
        </a>
      </div>
      
      {/* Input Section */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
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
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Max Depth
              </label>
              <input
                type="number"
                value={options.maxDepth}
                onChange={(e) => setOptions({...options, maxDepth: parseInt(e.target.value) || 2})}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Max Endpoints
              </label>
              <input
                type="number"
                value={options.maxEndpoints}
                onChange={(e) => setOptions({...options, maxEndpoints: parseInt(e.target.value) || 30})}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Top K
              </label>
              <input
                type="number"
                value={options.topK}
                onChange={(e) => setOptions({...options, topK: parseInt(e.target.value) || 3})}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={handleRunWorkflow}
                disabled={isLoading}
                className="w-full px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Running...' : 'Run Assessment'}
              </button>
            </div>
          </div>
          
          <div className="flex space-x-4">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={options.submitGetForms}
                onChange={(e) => setOptions({...options, submitGetForms: e.target.checked})}
                className="mr-2"
              />
              <span className="text-sm">Submit GET forms</span>
            </label>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={options.submitPostForms}
                onChange={(e) => setOptions({...options, submitPostForms: e.target.checked})}
                className="mr-2"
              />
              <span className="text-sm">Submit POST forms</span>
            </label>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4 mb-6">
          <p className="text-red-800">Error: {error}</p>
        </div>
      )}

      {/* Results Section */}
      {assessment && (
        <div className="bg-white rounded-lg shadow">
          {/* Summary */}
          <div className="p-6 border-b">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-semibold">Assessment Results</h2>
              <button
                onClick={() => {
                  const jobId = assessment.job_id;
                  if (jobId) {
                    getReport(jobId).then(report => {
                      const modal = document.createElement('div');
                      modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
                      modal.innerHTML = `
                        <div class="bg-white rounded-lg p-6 max-w-4xl max-h-[80vh] overflow-auto">
                          <div class="flex justify-between items-center mb-4">
                            <h3 class="text-lg font-semibold">Export Report</h3>
                            <button onclick="this.closest('.fixed').remove()" class="text-gray-500 hover:text-gray-700">✕</button>
                          </div>
                          <pre class="bg-gray-50 p-4 rounded text-sm overflow-auto max-h-96">${report.markdown}</pre>
                          <div class="mt-4 flex justify-end space-x-2">
                            <button onclick="navigator.clipboard.writeText(\`${report.markdown}\`)" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">Copy Markdown</button>
                            <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 bg-gray-300 text-gray-700 rounded hover:bg-gray-400">Close</button>
                          </div>
                        </div>
                      `;
                      document.body.appendChild(modal);
                    }).catch(err => {
                      console.error("Failed to export report:", err);
                      alert("Failed to export report");
                    });
                  }
                }}
                className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
              >
                Export Report
              </button>
            </div>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
              <div className="bg-blue-50 p-3 rounded">
                <div className="text-2xl font-bold text-blue-600">{assessment.summary?.total || 0}</div>
                <div className="text-sm text-blue-800">Total Targets</div>
              </div>
              <div className="bg-red-50 p-3 rounded">
                <div className="text-2xl font-bold text-red-600">{assessment.summary?.positive || 0}</div>
                <div className="text-sm text-red-800">Confirmed</div>
              </div>
              <div className="bg-yellow-50 p-3 rounded">
                <div className="text-2xl font-bold text-yellow-600">{assessment.summary?.suspected || 0}</div>
                <div className="text-sm text-yellow-800">Suspected</div>
              </div>
              <div className="bg-green-50 p-3 rounded">
                <div className="text-2xl font-bold text-green-600">{assessment.summary?.na || 0}</div>
                <div className="text-sm text-green-800">Clean</div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="border-b">
            <nav className="flex space-x-8 px-6">
              <button
                onClick={() => setActiveTab("confirmed")}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === "confirmed"
                    ? "border-red-500 text-red-600"
                    : "border-transparent text-gray-500 hover:text-gray-700"
                }`}
              >
                Confirmed ({confirmedFindings.length})
              </button>
              <button
                onClick={() => setActiveTab("suspected")}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === "suspected"
                    ? "border-yellow-500 text-yellow-600"
                    : "border-transparent text-gray-500 hover:text-gray-700"
                }`}
              >
                Suspected ({suspectedFindings.length})
              </button>
              <button
                onClick={() => setActiveTab("clean")}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === "clean"
                    ? "border-green-500 text-green-600"
                    : "border-transparent text-gray-500 hover:text-gray-700"
                }`}
              >
                Clean ({cleanResults.length})
              </button>
            </nav>
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {activeTab === "confirmed" && (
              <FindingsTab
                title="Confirmed Vulnerabilities"
                findings={confirmedFindings}
                emptyMessage="No confirmed vulnerabilities found"
              />
            )}
            {activeTab === "suspected" && (
              <FindingsTab
                title="Suspected Vulnerabilities"
                findings={suspectedFindings}
                emptyMessage="No suspected vulnerabilities found"
              />
            )}
            {activeTab === "clean" && (
              <FindingsTab
                title="Clean Results"
                findings={cleanResults}
                emptyMessage="No clean results to display"
              />
            )}
          </div>
        </div>
      )}

      {/* Crawl Meta Display */}
      {crawlMeta && (
        <div className="mt-6 bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium mb-2">Crawl Information</h3>
          <div className="text-sm text-gray-600">
            <p>Engine: {crawlMeta.engine || 'Unknown'}</p>
            <p>Pages Visited: {crawlMeta.pagesVisited || 0}</p>
            <p>XHR Requests: {crawlMeta.xhrCount || 0}</p>
            <p>Endpoints Emitted: {crawlMeta.emitted || 0}</p>
            {crawlMeta.withParams && <p>With Parameters: {crawlMeta.withParams}</p>}
          </div>
        </div>
      )}
    </div>
  );
}
