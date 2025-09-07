"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  
  useEffect(() => {
    router.push("/scan");
  }, [router]);

  return (
    <div className="mx-auto max-w-4xl p-6">
      <div className="text-center">
        <h1 className="text-3xl font-bold mb-4">Elise Vulnerability Scanner</h1>
        <p className="text-lg text-gray-600 mb-6">Redirecting to scan page...</p>
        <a href="/scan" className="text-blue-600 underline">Click here if not redirected</a>
      </div>
    </div>
  );
}