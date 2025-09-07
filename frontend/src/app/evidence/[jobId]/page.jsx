"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getReport } from "../../../lib/api";

export default function EvidencePage({ params }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const { jobId } = params;

  useEffect(() => {
    async function loadReport() {
      try {
        const result = await getReport(jobId);
        setReport(result);
      } catch (error) {
        console.error("Failed to load report:", error);
        setReport({ markdown: "Report not found or failed to load." });
      } finally {
        setLoading(false);
      }
    }

    if (jobId) {
      loadReport();
    }
  }, [jobId]);

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <div className="text-center">
          <div className="text-lg">Loading evidence...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">Evidence Report</h1>
        <div className="flex gap-2">
          <button
            onClick={() => router.push("/scan")}
            className="px-4 py-2 rounded bg-gray-600 text-white"
          >
            New Scan
          </button>
          <button
            onClick={() => router.push(`/assess?jobId=${jobId}`)}
            className="px-4 py-2 rounded bg-blue-600 text-white"
          >
            Back to Assessment
          </button>
        </div>
      </div>

      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold">Step 3: Evidence</h2>
          <button
            onClick={() => {
              const blob = new Blob([report.markdown], { type: "text/markdown" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = `elise-report-${jobId}.md`;
              a.click();
              URL.revokeObjectURL(url);
            }}
            className="px-4 py-2 rounded bg-emerald-600 text-white"
          >
            Download Report
          </button>
        </div>

        <div className="bg-gray-50 border rounded p-4">
          <div className="text-sm text-gray-600 mb-2">Job ID: {jobId}</div>
          <pre className="whitespace-pre-wrap text-sm overflow-auto max-h-96">
            {report?.markdown || "No evidence available."}
          </pre>
        </div>
      </div>
    </div>
  );
}
