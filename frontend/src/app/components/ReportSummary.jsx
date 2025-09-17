"use client";

import { ExclamationTriangleIcon, ShieldCheckIcon, InformationCircleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';

const ReportSummary = ({ summary, results = [] }) => {
  const positiveResults = results.filter(r => r.decision === 'positive');
  const suspectedResults = results.filter(r => r.decision === 'suspected');
  const cleanResults = results.filter(r => r.decision === 'clean');
  const notApplicableResults = results.filter(r => r.decision === 'not_applicable');

  // Count by family
  const familyCounts = positiveResults.reduce((acc, result) => {
    const family = result.family || 'unknown';
    acc[family] = (acc[family] || 0) + 1;
    return acc;
  }, {});

  // Count by severity
  const severityCounts = positiveResults.reduce((acc, result) => {
    const severity = result.severity || 'unknown';
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});

  const getFamilyIcon = (family) => {
    switch (family?.toLowerCase()) {
      case 'xss':
        return <ExclamationTriangleIcon className="h-5 w-5 text-orange-500" />;
      case 'sqli':
        return <ShieldCheckIcon className="h-5 w-5 text-red-500" />;
      case 'redirect':
        return <InformationCircleIcon className="h-5 w-5 text-blue-500" />;
      default:
        return <InformationCircleIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'high':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'medium':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-6">Assessment Summary</h2>
      
      {/* Overall Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="text-center">
          <div className="text-2xl font-bold text-red-600">{positiveResults.length}</div>
          <div className="text-sm text-gray-600">Vulnerabilities</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-yellow-600">{suspectedResults.length}</div>
          <div className="text-sm text-gray-600">Suspected</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-green-600">{cleanResults.length}</div>
          <div className="text-sm text-gray-600">Clean</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-gray-600">{notApplicableResults.length}</div>
          <div className="text-sm text-gray-600">N/A</div>
        </div>
      </div>

      {/* Vulnerabilities by Family */}
      {Object.keys(familyCounts).length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-medium text-gray-900 mb-3">Vulnerabilities by Type</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {Object.entries(familyCounts).map(([family, count]) => (
              <div key={family} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-2">
                  {getFamilyIcon(family)}
                  <span className="text-sm font-medium text-gray-900 capitalize">{family}</span>
                </div>
                <span className="text-lg font-bold text-gray-900">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Severity Breakdown */}
      {Object.keys(severityCounts).length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-medium text-gray-900 mb-3">Severity Breakdown</h3>
          <div className="space-y-2">
            {Object.entries(severityCounts).map(([severity, count]) => (
              <div key={severity} className="flex items-center justify-between p-3 rounded-lg border">
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(severity)}`}>
                    {severity.toUpperCase()}
                  </span>
                </div>
                <span className="text-lg font-bold text-gray-900">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Assessment Metadata */}
      {summary && (
        <div className="border-t pt-4">
          <h3 className="text-lg font-medium text-gray-900 mb-3">Assessment Details</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <dt className="text-gray-500">Endpoints Crawled</dt>
              <dd className="text-gray-900 font-medium">{summary.totals?.endpoints_crawled || 0}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Targets Enumerated</dt>
              <dd className="text-gray-900 font-medium">{summary.totals?.targets_enumerated || 0}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Probe Attempts</dt>
              <dd className="text-gray-900 font-medium">{summary.totals?.probe_attempts || 0}</dd>
            </div>
            <div>
              <dt className="text-gray-500">ML Inject Attempts</dt>
              <dd className="text-gray-900 font-medium">{summary.totals?.ml_inject_attempts || 0}</dd>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportSummary;
