"use client";
import { useQuery } from "@tanstack/react-query";
import { getHealth } from "../lib/api";

export default function HealthBadge() {
  const { data, isLoading, error } = useQuery({ queryKey: ["health"], queryFn: getHealth });
  if (isLoading) return <div className="text-sm">Health: loading…</div>;
  if (error) return <div className="text-sm text-red-600">Health error</div>;
  const b = data?.browser_ready, m = data?.ml_ready;
  return (
    <div className="flex items-center gap-3 text-sm">
      <span className={`px-2 py-1 rounded ${b ? "bg-emerald-100 text-emerald-800" : "bg-red-100 text-red-800"}`}>
        Browser: {b ? "ready" : "not ready"}
      </span>
      <span className={`px-2 py-1 rounded ${m ? "bg-emerald-100 text-emerald-800" : "bg-gray-200 text-gray-700"}`}>
        ML: {m ? "ready" : "not ready"}
      </span>
      <span className="text-gray-500">API: {process.env.NEXT_PUBLIC_API_BASE || "/api"}</span>
    </div>
  );
}
