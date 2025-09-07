"use client";
import { useQuery } from "@tanstack/react-query";
import { health, API_BASE } from "../lib/api";

export default function HealthBadge() {
  const { data, isLoading, error } = useQuery({ queryKey: ["health"], queryFn: health });
  if (isLoading) return <div className="text-sm text-gray-500">Loading system status...</div>;
  if (error) return <div className="text-sm text-red-600">System error</div>;
  
  // Use canonical healthz response format
  const browserReady = data?.browser_pool_ready === true;
  const mlReady = data?.ml_ready === true;
  
  return (
    <div className="flex items-center gap-2 text-sm">
      <div className="flex items-center gap-1">
        <div className={`w-2 h-2 rounded-full ${browserReady ? "bg-green-500" : "bg-red-500"}`}></div>
        <span className="text-gray-600">Browser</span>
      </div>
      <div className="flex items-center gap-1">
        <div className={`w-2 h-2 rounded-full ${mlReady ? "bg-green-500" : "bg-gray-400"}`}></div>
        <span className="text-gray-600">ML</span>
      </div>
      <span className="text-gray-400 text-xs">•</span>
      <span className="text-gray-500 text-xs">API: {API_BASE}</span>
    </div>
  );
}
