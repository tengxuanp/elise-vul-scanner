// frontend/src/app/components/CrawlForm.jsx
"use client";
import { useState } from "react";
import {
  startJob,
  crawlTarget,
  getCrawlStatus,
  getCrawlResult,
} from "../api/api";
import { toast } from "react-toastify";

/**
 * NOTE: Your backend accepts `max_depth` in /crawl.
 * Make sure your `crawlTarget` API helper forwards `max_depth` in the POST body:
 *   export const crawlTarget = async ({ job_id, target_url, auth, max_depth }) =>
 *     (await api.post('/crawl', { job_id, target_url, auth, max_depth })).data;
 */

function AuthFields({ mode, values, onChange, disabled }) {
  if (mode === "cookie") {
    return (
      <input
        className="border p-2 rounded w-full"
        placeholder="Cookie: sid=abc; jwt=eyJ..."
        value={values.cookie || ""}
        onChange={(e) => onChange({ ...values, cookie: e.target.value })}
        disabled={disabled}
      />
    );
  }
  if (mode === "bearer") {
    return (
      <input
        className="border p-2 rounded w-full"
        placeholder="Bearer token"
        value={values.bearer_token || ""}
        onChange={(e) => onChange({ ...values, bearer_token: e.target.value })}
        disabled={disabled}
      />
    );
  }
  if (mode === "form") {
    return (
      <div className="grid grid-cols-2 gap-2 w-full">
        <input
          className="border p-2 rounded"
          placeholder="Login URL"
          value={values.login_url || ""}
          onChange={(e) => onChange({ ...values, login_url: e.target.value })}
          disabled={disabled}
        />
        <input
          className="border p-2 rounded"
          placeholder="Username"
          value={values.username || ""}
          onChange={(e) => onChange({ ...values, username: e.target.value })}
          disabled={disabled}
        />
        <input
          className="border p-2 rounded"
          placeholder="Password"
          type="password"
          value={values.password || ""}
          onChange={(e) => onChange({ ...values, password: e.target.value })}
          disabled={disabled}
        />
        <input
          className="border p-2 rounded"
          placeholder="Username selector (e.g. input[name=email])"
          value={values.username_selector || ""}
          onChange={(e) =>
            onChange({ ...values, username_selector: e.target.value })
          }
          disabled={disabled}
        />
        <input
          className="border p-2 rounded"
          placeholder="Password selector"
          value={values.password_selector || ""}
          onChange={(e) =>
            onChange({ ...values, password_selector: e.target.value })
          }
          disabled={disabled}
        />
        <input
          className="border p-2 rounded"
          placeholder="Submit selector"
          value={values.submit_selector || ""}
          onChange={(e) =>
            onChange({ ...values, submit_selector: e.target.value })
          }
          disabled={disabled}
        />
      </div>
    );
  }
  if (mode === "manual") {
    return (
      <div className="grid grid-cols-2 gap-2 w-full">
        <input
          className="border p-2 rounded"
          placeholder="Login URL (optional)"
          value={values.login_url || ""}
          onChange={(e) => onChange({ ...values, login_url: e.target.value })}
          disabled={disabled}
        />
        <input
          className="border p-2 rounded"
          placeholder="Wait after login (ms, default 1500)"
          type="number"
          min={0}
          value={values.wait_after_ms ?? ""}
          onChange={(e) =>
            onChange({
              ...values,
              wait_after_ms:
                e.target.value === "" ? undefined : Number(e.target.value),
            })
          }
          disabled={disabled}
        />
        <div className="col-span-2 text-xs text-gray-600">
          Manual opens a headful browser window (if the server allows). Use it
          to log in; the crawler will capture the session.
        </div>
      </div>
    );
  }
  return null;
}

function normalizeUrl(u) {
  if (!u) return "";
  const s = String(u).trim();
  if (/^https?:\/\//i.test(s)) return s;
  return `http://${s}`;
}

export default function CrawlForm({ onResults, onJobReady }) {
  const [url, setUrl] = useState("");
  const [maxDepth, setMaxDepth] = useState(2);
  const [authMode, setAuthMode] = useState("none"); // none|cookie|bearer|form|manual
  const [authValues, setAuthValues] = useState({});
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    let target_url = url.trim();
    if (!target_url) {
      toast.error("Enter a valid URL");
      return;
    }
    target_url = normalizeUrl(target_url);

    const depth = Number(maxDepth);
    if (Number.isNaN(depth) || depth < 0 || depth > 10) {
      toast.error("Max depth must be between 0 and 10");
      return;
    }

    setLoading(true);
    try {
      // 1) Start job
      const { job_id } = await startJob({ target: target_url });
      onJobReady?.(job_id);

      // 2) Build auth payload
      let auth;
      if (authMode === "cookie") {
        auth = { mode: "cookie", cookie: authValues.cookie || "" };
      } else if (authMode === "bearer") {
        auth = { mode: "bearer", bearer_token: authValues.bearer_token || "" };
      } else if (authMode === "form") {
        auth = {
          mode: "form",
          login_url: authValues.login_url || "",
          username: authValues.username || "",
          password: authValues.password || "",
          username_selector: authValues.username_selector || "",
          password_selector: authValues.password_selector || "",
          submit_selector: authValues.submit_selector || "",
          wait_after_ms:
            authValues.wait_after_ms === undefined
              ? 1500
              : Number(authValues.wait_after_ms) || 1500,
        };
      } else if (authMode === "manual") {
        auth = {
          mode: "manual",
          login_url: authValues.login_url || "",
          wait_after_ms:
            authValues.wait_after_ms === undefined
              ? 1500
              : Number(authValues.wait_after_ms) || 1500,
        };
      } else {
        auth = { mode: "none" };
      }

      // 3) Trigger crawl (ensure max_depth is sent)
      await crawlTarget({
        target_url,
        max_depth: depth,
        max_endpoints: 20,
        max_pages: 12
      });
      toast.info("Crawl started");

      // 4) Poll status
      let status = "running";
      while (status === "running" || status === "starting") {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((r) => setTimeout(r, 1200));
        // eslint-disable-next-line no-await-in-loop
        status = (await getCrawlStatus(job_id)).status || "unknown";
      }
      if (status !== "completed") {
        toast.warn(`Crawl ended with status: ${status}`);
      }

      // 5) Fetch result
      const res = await getCrawlResult(job_id);
      onResults?.({
        job_id,
        target_url,
        endpoints: res.endpoints || [],
        captured_requests: res.captured_requests || [],
      });
      toast.success("Crawl completed");
    } catch (err) {
      console.error(err);
      toast.error("Crawl failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <div className="flex gap-2 items-center">
        <input
          className="border p-2 rounded flex-1"
          placeholder="http://localhost:8082"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={loading}
          aria-label="Target URL"
        />
        <input
          className="border p-2 rounded w-28"
          type="number"
          min={0}
          max={10}
          title="Max crawl depth"
          value={maxDepth}
          onChange={(e) => setMaxDepth(e.target.value)}
          disabled={loading}
          aria-label="Max crawl depth"
        />
        <select
          className="border p-2 rounded"
          value={authMode}
          onChange={(e) => {
            setAuthMode(e.target.value);
            setAuthValues({});
          }}
          title="Authentication mode"
          disabled={loading}
          aria-label="Authentication mode"
        >
          <option value="none">No auth</option>
          <option value="cookie">Cookie</option>
          <option value="bearer">Bearer</option>
          <option value="form">Form login</option>
          <option value="manual">Manual (headful)</option>
        </select>
        <button
          type="submit"
          className="bg-blue-600 text-white px-4 py-2 rounded disabled:opacity-60"
          disabled={loading}
        >
          {loading ? "Crawling…" : "Start Crawl"}
        </button>
      </div>

      <AuthFields
        mode={authMode}
        values={authValues}
        onChange={setAuthValues}
        disabled={loading}
      />
    </form>
  );
}
