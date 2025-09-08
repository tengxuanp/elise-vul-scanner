"use client";

import { useState } from 'react';

export default function DiagnosticsCard({ healthz }) {
  const [expanded, setExpanded] = useState(false);

  if (!healthz) {
    return (
      <div className="bg-white rounded-lg shadow p-4">
        <h3 className="text-lg font-semibold text-gray-900 mb-2">Diagnostics</h3>
        <p className="text-gray-500 text-sm">No diagnostic data available</p>
      </div>
    );
  }

  const truncateArray = (arr, maxItems = 3) => {
    if (!Array.isArray(arr)) return arr;
    if (arr.length <= maxItems) return arr;
    return [...arr.slice(0, maxItems), `... and ${arr.length - maxItems} more`];
  };

  const formatThresholds = (thresholds) => {
    if (!thresholds) return 'N/A';
    return Object.entries(thresholds)
      .map(([key, value]) => `${key}: ${value}`)
      .join(', ');
  };

  const formatModelsAvailable = (models) => {
    if (!models || typeof models !== 'object') return 'N/A';
    
    const modelList = Object.entries(models)
      .filter(([_, info]) => info.has_model)
      .map(([name, _]) => name);
    
    return truncateArray(modelList);
  };

  return (
    <div className="bg-white rounded-lg shadow p-4">
      <div className="flex justify-between items-center mb-3">
        <h3 className="text-lg font-semibold text-gray-900">Diagnostics</h3>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-sm text-blue-600 hover:text-blue-800"
        >
          {expanded ? 'Collapse' : 'Expand'}
        </button>
      </div>

      <div className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-gray-600">ML Mode:</span>
          <span className={`font-medium ${healthz.use_ml ? 'text-green-600' : 'text-gray-600'}`}>
            {healthz.use_ml ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        <div className="flex justify-between">
          <span className="text-gray-600">ML Active:</span>
          <span className={`font-medium ${healthz.ml_active ? 'text-green-600' : 'text-gray-600'}`}>
            {healthz.ml_active ? 'Yes' : 'No'}
          </span>
        </div>

        <div className="flex justify-between">
          <span className="text-gray-600">Require Ranker:</span>
          <span className={`font-medium ${healthz.require_ranker ? 'text-orange-600' : 'text-gray-600'}`}>
            {healthz.require_ranker ? 'Yes' : 'No'}
          </span>
        </div>

        {expanded && (
          <>
            <div className="border-t pt-2 mt-2">
              <div className="flex justify-between">
                <span className="text-gray-600">Models Available:</span>
                <div className="text-right">
                  {Array.isArray(formatModelsAvailable(healthz.models_available)) ? (
                    <div className="space-y-1">
                      {formatModelsAvailable(healthz.models_available).map((model, idx) => (
                        <div key={idx} className="text-xs bg-gray-100 px-2 py-1 rounded">
                          {model}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-gray-500">{formatModelsAvailable(healthz.models_available)}</span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex justify-between">
              <span className="text-gray-600">Thresholds:</span>
              <span className="text-gray-500 text-xs max-w-32 truncate" title={formatThresholds(healthz.thresholds)}>
                {formatThresholds(healthz.thresholds)}
              </span>
            </div>

            <div className="flex justify-between">
              <span className="text-gray-600">Using Defaults:</span>
              <span className={`font-medium ${healthz.using_defaults ? 'text-orange-600' : 'text-green-600'}`}>
                {healthz.using_defaults ? 'Yes' : 'No'}
              </span>
            </div>

            <div className="flex justify-between">
              <span className="text-gray-600">ML Status:</span>
              <span className={`font-medium ${
                healthz.ml_status === 'models_available' ? 'text-green-600' :
                healthz.ml_status === 'defaults_only' ? 'text-orange-600' :
                healthz.ml_status === 'disabled' ? 'text-gray-600' :
                'text-red-600'
              }`}>
                {healthz.ml_status}
              </span>
            </div>

            {healthz.failed_checks && healthz.failed_checks.length > 0 && (
              <div className="border-t pt-2 mt-2">
                <div className="text-gray-600 mb-1">Failed Checks:</div>
                <div className="space-y-1">
                  {healthz.failed_checks.map((check, idx) => (
                    <div key={idx} className="text-xs text-red-600 bg-red-50 px-2 py-1 rounded">
                      {check}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
