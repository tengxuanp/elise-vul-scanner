"use client";
import './globals.css';
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

export default function RootLayout({ children }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: { queries: { retry: 0, staleTime: 10_000 } },
  }));

  return (
    <html lang="en">
      <body className="bg-zinc-50 text-zinc-900">
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      </body>
    </html>
  );
}