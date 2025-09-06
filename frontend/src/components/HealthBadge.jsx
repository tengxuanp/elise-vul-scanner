"use client";
import { useQuery } from "@tanstack/react-query";
import { getHealth, API_BASE } from "../lib/api";

export default function HealthBadge() {
  const { data, isLoading, error } = useQuery({ queryKey: ["health"], queryFn: getHealth });
  if (isLoading) return <div className="text-sm">Health: loading…</div>;
  if (error) return <div className="text-sm text-red-600">Health error</div>;
  
  // Use canonical healthz response format
  const browserReady = data?.browser_pool_ready === true;
  const mlReady = data?.ml_ready === true;
  
  return (
    <div className="flex items-center gap-3 text-sm">
      <span className={`px-2 py-1 rounded ${browserReady ? "bg-emerald-100 text-emerald-800" : "bg-red-100 text-red-800"}`}>
        Browser: {browserReady ? "ready" : "not ready"}
      </span>
      <span className={`px-2 py-1 rounded ${mlReady ? "bg-emerald-100 text-emerald-800" : "bg-gray-200 text-gray-700"}`}>
        ML: {mlReady ? "ready" : "not ready"}
      </span>
      <span className="text-gray-500">API: {API_BASE}</span>
    </div>
  );
}
