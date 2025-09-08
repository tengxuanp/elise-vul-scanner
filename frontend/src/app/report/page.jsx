"use client";

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { API_BASE } from '../../lib/api';
import Stepbar from '../components/Stepbar';

export default function ReportPage() {
  const searchParams = useSearchParams();
  const jobId = searchParams.get('jobId');
  
  const [report, setReport] = useState(null);
  const [evidenceFiles, setEvidenceFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (jobId) {
      fetchReport();
      fetchEvidenceFiles();
    }
  }, [jobId]);

  const fetchReport = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/report/${jobId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch report');
      }

      const reportData = await response.text();
      setReport(reportData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchEvidenceFiles = async () => {
    try {
      const response = await fetch(`${API_BASE}/evidence/list/${jobId}`);
      if (response.ok) {
        const files = await response.json();
        setEvidenceFiles(files);
      }
    } catch (err) {
      console.error('Failed to fetch evidence files:', err);
    }
  };

  const downloadReport = () => {
    if (!report) return;
    
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `elise-report-${jobId}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const openEvidenceFolder = () => {
    // This would typically open a file explorer or list files
    // For now, we'll show the evidence files in a modal or list
    console.log('Evidence files:', evidenceFiles);
  };

  if (!jobId) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-6xl mx-auto px-4 py-8">
          <Stepbar currentStep="report" />
          <div className="mt-8 text-center">
            <h1 className="text-3xl font-bold text-gray-900 mb-4">Report</h1>
            <p className="text-gray-600">No job ID provided. Please navigate from an assessment.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <Stepbar currentStep="report" />
        
        <div className="mt-8">
          <div className="flex justify-between items-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900">Report</h1>
            <div className="space-x-3">
              <button
                onClick={openEvidenceFolder}
                className="bg-gray-600 text-white py-2 px-4 rounded-md hover:bg-gray-700"
              >
                Open Evidence Folder
              </button>
              <button
                onClick={downloadReport}
                disabled={!report}
                className="bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Download Report
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Report Content */}
            <div className="lg:col-span-3">
              <div className="bg-white rounded-lg shadow p-6">
                <h2 className="text-xl font-semibold mb-4">Assessment Report</h2>
                
                {loading ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                    <span className="ml-2 text-gray-600">Loading report...</span>
                  </div>
                ) : error ? (
                  <div className="p-4 bg-red-100 border border-red-400 text-red-700 rounded">
                    {error}
                  </div>
                ) : report ? (
                  <div className="prose max-w-none">
                    <pre className="whitespace-pre-wrap text-sm bg-gray-50 p-4 rounded border overflow-x-auto">
                      {report}
                    </pre>
                  </div>
                ) : (
                  <p className="text-gray-500">No report available for job {jobId}</p>
                )}
              </div>
            </div>

            {/* Evidence Files Sidebar */}
            <div className="lg:col-span-1">
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Evidence Files</h3>
                
                {evidenceFiles.length > 0 ? (
                  <div className="space-y-2">
                    {evidenceFiles.map((file, idx) => (
                      <div key={idx} className="p-2 bg-gray-50 rounded border">
                        <p className="text-sm font-medium text-gray-900 truncate">
                          {file.filename}
                        </p>
                        <p className="text-xs text-gray-500">
                          {file.family} • {file.decision}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500 text-sm">No evidence files found</p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
