"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { crawl } from "../../lib/api";

export default function ScanPage() {
  const [loading, setLoading] = useState(false);
  const [targetUrl, setTargetUrl] = useState("");
  const router = useRouter();

  async function onCrawl() {
    if (!targetUrl) return;
    
    setLoading(true);
    try {
      const result = await crawl({ target_url: targetUrl });
      const jobId = Date.now().toString();
      
      // Store crawl result in sessionStorage for next step
      sessionStorage.setItem(`crawl_${jobId}`, JSON.stringify(result));
      
      // Navigate to assess page with jobId
      router.push(`/assess?jobId=${jobId}`);
    } catch (error) {
      console.error("Crawl error:", error);
      alert("Crawl failed: " + error.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-4xl p-6">
      <h1 className="text-3xl font-bold mb-6">Elise Vulnerability Scanner</h1>
      
      <div className="card p-6">
        <h2 className="text-xl font-semibold mb-4">Step 1: Crawl Target</h2>
        
        <div className="flex gap-3 mb-4">
          <input
            type="url"
            placeholder="https://target.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1 border rounded px-3 py-2"
            onKeyPress={(e) => e.key === 'Enter' && onCrawl()}
          />
          <button
            onClick={onCrawl}
            disabled={!targetUrl || loading}
            className="px-6 py-2 rounded bg-blue-600 text-white disabled:opacity-50"
          >
            {loading ? "Crawling..." : "Crawl"}
          </button>
        </div>
        
        <p className="text-sm text-zinc-600">
          Enter a target URL to discover endpoints and parameters for vulnerability assessment.
        </p>
      </div>
    </div>
  );
}
