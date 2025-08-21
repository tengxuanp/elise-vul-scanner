"use client";
import { useState } from 'react';
import { startJob, crawlTarget, getCrawlStatus, getCrawlResult } from '../api/api';
import { toast } from 'react-toastify';

function AuthFields({ mode, values, onChange }) {
  if (mode === 'cookie') {
    return (
      <input
        className="border p-2 rounded w-full"
        placeholder="Cookie: sid=abc; jwt=eyJ..."
        value={values.cookie || ''}
        onChange={(e) => onChange({ ...values, cookie: e.target.value })}
      />
    );
  }
  if (mode === 'bearer') {
    return (
      <input
        className="border p-2 rounded w-full"
        placeholder="Bearer token"
        value={values.bearer_token || ''}
        onChange={(e) => onChange({ ...values, bearer_token: e.target.value })}
      />
    );
  }
  if (mode === 'form') {
    return (
      <div className="grid grid-cols-2 gap-2 w-full">
        <input className="border p-2 rounded" placeholder="Login URL"
               value={values.login_url || ''} onChange={(e)=>onChange({ ...values, login_url: e.target.value })}/>
        <input className="border p-2 rounded" placeholder="Username"
               value={values.username || ''} onChange={(e)=>onChange({ ...values, username: e.target.value })}/>
        <input className="border p-2 rounded" placeholder="Password"
               value={values.password || ''} onChange={(e)=>onChange({ ...values, password: e.target.value })}/>
        <input className="border p-2 rounded" placeholder="Username selector (e.g. input[name=email])"
               value={values.username_selector || ''} onChange={(e)=>onChange({ ...values, username_selector: e.target.value })}/>
        <input className="border p-2 rounded" placeholder="Password selector"
               value={values.password_selector || ''} onChange={(e)=>onChange({ ...values, password_selector: e.target.value })}/>
        <input className="border p-2 rounded" placeholder="Submit selector"
               value={values.submit_selector || ''} onChange={(e)=>onChange({ ...values, submit_selector: e.target.value })}/>
      </div>
    );
  }
  return null;
}

export default function CrawlForm({ onResults, onJobReady }) {
  const [url, setUrl] = useState('');
  const [authMode, setAuthMode] = useState('none'); // none|cookie|bearer|form
  const [authValues, setAuthValues] = useState({});
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    const target_url = url.trim();
    if (!target_url) return toast.error('Enter a valid URL');

    setLoading(true);
    try {
      // 1) Start job
      const { job_id } = await startJob({ target: target_url });
      onJobReady?.(job_id);

      // 2) Build auth payload
      let auth;
      if (authMode === 'cookie') auth = { mode: 'cookie', cookie: authValues.cookie || '' };
      else if (authMode === 'bearer') auth = { mode: 'bearer', bearer_token: authValues.bearer_token || '' };
      else if (authMode === 'form') auth = {
        mode: 'form',
        login_url: authValues.login_url || '',
        username: authValues.username || '',
        password: authValues.password || '',
        username_selector: authValues.username_selector || '',
        password_selector: authValues.password_selector || '',
        submit_selector: authValues.submit_selector || ''
      };
      else auth = { mode: 'none' };

      // 3) Trigger crawl
      await crawlTarget({ job_id, target_url, auth });
      toast.info('Crawl started');

      // 4) Poll status
      let status = 'running';
      while (status === 'running') {
        await new Promise(r => setTimeout(r, 1200));
        status = (await getCrawlStatus(job_id)).status || 'unknown';
      }
      if (status !== 'completed') {
        toast.warn(`Crawl ended with status: ${status}`);
      }

      // 5) Fetch result
      const res = await getCrawlResult(job_id);
      onResults?.({
        job_id,
        target_url,
        endpoints: res.endpoints || [],
        captured_requests: res.captured_requests || []
      });
      toast.success('Crawl completed');
    } catch (err) {
      console.error(err);
      toast.error('Crawl failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <div className="flex gap-2">
        <input
          className="border p-2 rounded flex-1"
          placeholder="http://localhost:8082"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <select className="border p-2 rounded"
                value={authMode}
                onChange={(e)=>{ setAuthMode(e.target.value); setAuthValues({}); }}>
          <option value="none">No auth</option>
          <option value="cookie">Cookie</option>
          <option value="bearer">Bearer</option>
          <option value="form">Form login</option>
        </select>
        <button className="bg-blue-600 text-white px-4 py-2 rounded" disabled={loading}>
          {loading ? 'Crawling…' : 'Start Crawl'}
        </button>
      </div>
      <AuthFields mode={authMode} values={authValues} onChange={setAuthValues}/>
    </form>
  );
}
