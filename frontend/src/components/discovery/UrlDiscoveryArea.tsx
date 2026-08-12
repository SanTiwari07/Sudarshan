import { useState, useCallback, useEffect } from 'react';
import { Search, Loader2, AlertCircle, CheckCircle2, FileArchive, ArrowRight } from 'lucide-react';
import { API_BASE } from '../../config';
import { getToken } from '../../pages/Login';

export type Candidate = {
  id: string;
  source_url: string;
  discovery_url: string;
  filename: string | null;
  source_type: string;
  package_id: string | null;
  download_status: string;
  validation_status: string | null;
  sha256: string | null;
  size: number | null;
  error: string | null;
};

export type DiscoverySessionResponse = {
  session_id: string;
  status: 'in_progress' | 'completed' | 'failed';
  pages_scanned: number;
  error: string | null;
  progress_logs: string[];
};

type UrlDiscoveryAreaProps = {
  onAnalyzeCandidate: (candidateId: string, sessionId: string, filename: string) => void;
  disabled?: boolean;
};

export default function UrlDiscoveryArea({ onAnalyzeCandidate, disabled }: UrlDiscoveryAreaProps) {
  const [url, setUrl] = useState('');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [sessionStatus, setSessionStatus] = useState<DiscoverySessionResponse | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [error, setError] = useState<string | null>(null);

  const startDiscovery = async () => {
    if (!url) return;
    setError(null);
    setSessionId(null);
    setSessionStatus(null);
    setCandidates([]);

    try {
      const res = await fetch(`${API_BASE}/discovery/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${getToken()}`,
        },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || 'Failed to start discovery');
      }

      const data = await res.json();
      setSessionId(data.session_id);
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    if (!sessionId) return;

    let intervalId: ReturnType<typeof setInterval>;

    const poll = async () => {
      try {
        const [statusRes, resultsRes] = await Promise.all([
          fetch(`${API_BASE}/discovery/${sessionId}/status`, {
            headers: { Authorization: `Bearer ${getToken()}` },
          }),
          fetch(`${API_BASE}/discovery/${sessionId}/results`, {
            headers: { Authorization: `Bearer ${getToken()}` },
          }),
        ]);

        if (statusRes.ok) {
          const statusData = await statusRes.json();
          setSessionStatus(statusData);

          if (statusData.status === 'failed') {
            setError(statusData.error || 'Discovery session failed.');
            clearInterval(intervalId);
          } else if (statusData.status === 'completed') {
            clearInterval(intervalId);
          }
        }

        if (resultsRes.ok) {
          const resultsData = await resultsRes.json();
          setCandidates(resultsData.candidates);
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    };

    poll(); // initial
    intervalId = setInterval(poll, 2000);

    return () => clearInterval(intervalId);
  }, [sessionId]);

  const isBusy = sessionStatus?.status === 'in_progress';

  return (
    <div className="space-y-6">
      <div className="flex gap-3">
        <div className="relative flex-1">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4">
            <Search className="h-5 w-5 text-slate-400" aria-hidden="true" />
          </div>
          <input
            type="url"
            name="url"
            id="url"
            disabled={disabled || isBusy}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="block w-full rounded-xl border-0 py-3.5 pl-11 pr-4 text-slate-900 ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6"
            placeholder="https://example.com"
            onKeyDown={(e) => {
              if (e.key === 'Enter') startDiscovery();
            }}
          />
        </div>
        <button
          onClick={startDiscovery}
          disabled={!url || disabled || isBusy}
          className="flex items-center gap-2 rounded-xl bg-blue-700 px-6 py-3.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 disabled:bg-slate-300 disabled:cursor-not-allowed transition-colors"
        >
          {isBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Discover'}
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-sm text-red-700 bg-red-50 border border-red-200 rounded-xl p-4">
          <AlertCircle className="h-5 w-5 shrink-0" />
          {error}
        </div>
      )}

      {sessionStatus && (
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-900">Discovery Progress</h3>
            {isBusy ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-medium text-blue-800">
                <Loader2 className="h-3 w-3 animate-spin" />
                Scanning
              </span>
            ) : sessionStatus.status === 'completed' ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                <CheckCircle2 className="h-3 w-3" />
                Completed
              </span>
            ) : null}
          </div>

          <div className="space-y-1 bg-slate-900 rounded-lg p-4 font-mono text-xs text-slate-300 h-48 overflow-y-auto">
            {sessionStatus.progress_logs.map((log, i) => (
              <div key={i}>{log}</div>
            ))}
            {isBusy && (
              <div className="animate-pulse flex gap-1 mt-2">
                <div className="w-1.5 h-1.5 bg-slate-500 rounded-full"></div>
                <div className="w-1.5 h-1.5 bg-slate-500 rounded-full animation-delay-200"></div>
                <div className="w-1.5 h-1.5 bg-slate-500 rounded-full animation-delay-400"></div>
              </div>
            )}
          </div>
        </div>
      )}

      {candidates.length > 0 && (
        <div className="mt-8 space-y-4">
          <h3 className="text-sm font-semibold text-slate-900">Discovered Applications</h3>
          {candidates.map((c) => (
            <div
              key={c.id}
              className="flex items-center justify-between p-4 bg-white border border-slate-200 rounded-xl shadow-sm"
            >
              <div className="flex items-start gap-4">
                <div className={`p-2 rounded-lg ${c.validation_status === 'valid_apk' ? 'bg-green-50 text-green-600' : c.download_status === 'download_failed' || c.validation_status === 'invalid_apk' ? 'bg-red-50 text-red-600' : 'bg-blue-50 text-blue-600'}`}>
                  {c.validation_status === 'valid_apk' ? <CheckCircle2 className="h-6 w-6" /> : c.download_status === 'download_failed' || c.validation_status === 'invalid_apk' ? <AlertCircle className="h-6 w-6" /> : <FileArchive className="h-6 w-6" />}
                </div>
                <div>
                  <p className="font-mono text-sm font-medium text-slate-900">
                    {c.filename || c.package_id || 'Unknown Candidate'}
                  </p>
                  <div className="mt-1 flex items-center gap-3 text-xs text-slate-500">
                    <span>Source: {c.source_type}</span>
                    {c.size && <span>{(c.size / 1024 / 1024).toFixed(2)} MB</span>}
                  </div>
                  {c.sha256 && (
                    <p className="mt-1 text-xs font-mono text-slate-400 max-w-[200px] truncate sm:max-w-none">
                      {c.sha256}
                    </p>
                  )}
                  {c.error && <p className="mt-1 text-xs text-red-600">{c.error}</p>}
                </div>
              </div>

              <button
                onClick={() => onAnalyzeCandidate(c.id, c.session_id, c.filename || c.package_id || 'URL Candidate')}
                disabled={c.validation_status !== 'valid_apk' || disabled}
                className="flex items-center gap-2 rounded-lg bg-slate-50 px-4 py-2 text-sm font-medium text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Analyze
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
