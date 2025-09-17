"use client";

import { useState } from 'react';
import { DocumentTextIcon, EyeIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';

const EvidenceViewer = ({ evidenceFiles, jobId }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchFileContent = async (filename) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/evidence/${jobId}/${filename}`);
      if (response.ok) {
        const content = await response.text();
        setFileContent(content);
        setSelectedFile(filename);
      } else {
        console.error('Failed to fetch file content');
      }
    } catch (error) {
      console.error('Error fetching file content:', error);
    } finally {
      setLoading(false);
    }
  };

  const downloadFile = async (filename) => {
    try {
      const response = await fetch(`/api/evidence/${jobId}/${filename}`);
      if (response.ok) {
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Error downloading file:', error);
    }
  };

  const getFamilyColor = (family) => {
    switch (family?.toLowerCase()) {
      case 'xss':
        return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'sqli':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'redirect':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getDecisionColor = (decision) => {
    switch (decision?.toLowerCase()) {
      case 'positive':
        return 'text-green-600 bg-green-50';
      case 'suspected':
        return 'text-yellow-600 bg-yellow-50';
      case 'clean':
        return 'text-blue-600 bg-blue-50';
      default:
        return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-4 border-b border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900">Evidence Files</h3>
        <p className="text-sm text-gray-600 mt-1">
          {evidenceFiles.length} evidence file{evidenceFiles.length !== 1 ? 's' : ''} found
        </p>
      </div>

      <div className="divide-y divide-gray-200">
        {evidenceFiles.length === 0 ? (
          <div className="p-4 text-center text-gray-500">
            <DocumentTextIcon className="h-8 w-8 mx-auto mb-2 text-gray-400" />
            <p>No evidence files found</p>
          </div>
        ) : (
          evidenceFiles.map((file, index) => (
            <div key={index} className="p-4 hover:bg-gray-50">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <DocumentTextIcon className="h-5 w-5 text-gray-400" />
                  <div>
                    <p className="text-sm font-medium text-gray-900 truncate max-w-xs">
                      {file.filename}
                    </p>
                    <div className="flex items-center space-x-2 mt-1">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getFamilyColor(file.family)}`}>
                        {file.family?.toUpperCase() || 'UNKNOWN'}
                      </span>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getDecisionColor(file.decision)}`}>
                        {file.decision?.toUpperCase() || 'UNKNOWN'}
                      </span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => fetchFileContent(file.filename)}
                    className="p-1 text-gray-400 hover:text-gray-600"
                    title="View content"
                  >
                    <EyeIcon className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => downloadFile(file.filename)}
                    className="p-1 text-gray-400 hover:text-gray-600"
                    title="Download file"
                  >
                    <ArrowDownTrayIcon className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* File Content Modal */}
      {selectedFile && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl max-w-4xl max-h-[80vh] w-full mx-4">
            <div className="p-4 border-b border-gray-200 flex items-center justify-between">
              <h4 className="text-lg font-semibold text-gray-900">{selectedFile}</h4>
              <button
                onClick={() => {
                  setSelectedFile(null);
                  setFileContent(null);
                }}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            <div className="p-4 overflow-auto max-h-96">
              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                  <span className="ml-2 text-gray-600">Loading...</span>
                </div>
              ) : fileContent ? (
                <pre className="text-sm text-gray-900 whitespace-pre-wrap break-words">
                  {fileContent}
                </pre>
              ) : (
                <p className="text-gray-500">No content available</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EvidenceViewer;
