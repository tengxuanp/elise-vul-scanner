"use client";
import { useState } from 'react';
import { crawlTarget, getCrawlResult } from '../api/api';
import { toast } from 'react-toastify';

export default function CrawlForm({ onResults }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!url.trim()) {
      toast.error('Please enter a valid target URL.');
      return;
    }

    try {
      setLoading(true);
      await crawlTarget({ target_url: url.trim() }); // ✅ Changed from target_domains to target_url
      toast.info('Crawl started. Waiting for results...');

      const pollInterval = setInterval(async () => {
        try {
          const res = await getCrawlResult();
          if (res.status !== 'pending') {
            clearInterval(pollInterval);
            onResults({
              endpoints: res.endpoints || [],
              captured_requests: res.captured_requests || []
            });
            toast.success(`Crawl completed. Found ${res.endpoints?.length || 0} endpoints, ${res.captured_requests?.length || 0} captured requests.`);
            setLoading(false);
          }
        } catch (err) {
          clearInterval(pollInterval);
          console.error(err);
          toast.error('Failed to get crawl results.');
          setLoading(false);
        }
      }, 5000);

    } catch (err) {
      console.error(err);
      toast.error('Crawl failed to start.');
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex items-center space-x-2">
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Enter Target URL (e.g., http://localhost:8082/)"
        className="border p-2 rounded w-1/2"
      />
      <button
        type="submit"
        className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
        disabled={loading}
      >
        {loading ? 'Crawling...' : 'Start Crawl'}
      </button>
    </form>
  );
}
