import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import { API_BASE } from '../../config';
import { getToken } from '../../pages/Login';

export type AnalysisSessionState =
  | 'idle'
  | 'uploading'
  | 'analyzing'
  | 'complete'
  | 'error';

const ESTIMATED_MS = 4 * 60 * 1000;

async function sha256Hex(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function useAnalysisSession(onComplete: (data: FraudCardData) => void) {
  const navigate = useNavigate();
  const [phase, setPhase] = useState<AnalysisSessionState>('idle');
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [smoothProgress, setSmoothProgress] = useState(0);
  const [result, setResult] = useState<FraudCardData | null>(null);

  const abortRef = useRef(false);
  const progressRef = useRef(0);
  const rafRef = useRef<number | null>(null);
  const startedAtRef = useRef<number | null>(null);

  const reset = useCallback(() => {
    abortRef.current = true;
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    abortRef.current = false;
    progressRef.current = 0;
    startedAtRef.current = null;
    setPhase('idle');
    setFile(null);
    setError(null);
    setSmoothProgress(0);
    setResult(null);
  }, []);

  const isBusy = phase === 'uploading' || phase === 'analyzing';

  useEffect(() => {
    if (!isBusy) return;

    const animate = () => {
      const started = startedAtRef.current ?? Date.now();
      const elapsed = Date.now() - started;
      const timeTarget = Math.min(92, 5 + (elapsed / ESTIMATED_MS) * 87);
      const target = Math.max(progressRef.current, timeTarget);
      const next = progressRef.current + (target - progressRef.current) * 0.08;
      progressRef.current = next;
      setSmoothProgress(next);

      if (phase === 'analyzing' && next < 92) {
        rafRef.current = requestAnimationFrame(animate);
      }
    };

    rafRef.current = requestAnimationFrame(animate);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [isBusy, phase]);

  const pollJob = useCallback(
    async (jobId: string, token: string | null): Promise<FraudCardData> => {
      const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
      for (;;) {
        if (abortRef.current) throw new Error('Analysis cancelled');
        const res = await fetch(`${API_BASE}/status/${jobId}`, { headers });
        if (res.status === 401) {
          navigate('/login');
          throw new Error('Session expired');
        }
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.detail || 'Status poll failed');
        }
        const data = await res.json();
        if (data.status === 'queued') {
          progressRef.current = Math.max(progressRef.current, 8);
        } else if (data.status === 'processing') {
          progressRef.current = Math.max(progressRef.current, 15);
        } else if (data.status === 'done' && data.result) {
          return data.result as FraudCardData;
        } else if (data.status === 'failed') {
          throw new Error(data.error || 'Analysis job failed');
        }
        await new Promise((r) => setTimeout(r, 1500));
      }
    },
    [navigate],
  );

  const startAnalysis = useCallback(async () => {
    if (!file || isBusy) return;

    setError(null);
    setPhase('uploading');
    startedAtRef.current = Date.now();
    progressRef.current = 2;
    setSmoothProgress(2);

    const token = getToken();
    await sha256Hex(file);

    const makeFormData = () => {
      const fd = new FormData();
      fd.append('file', file);
      return fd;
    };

    try {
      progressRef.current = 5;
      const asyncRes = await fetch(`${API_BASE}/analyze/async`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: makeFormData(),
      });

      if (asyncRes.status === 401) {
        navigate('/login');
        return;
      }

      let analysisResult: FraudCardData;

      if (asyncRes.status === 202) {
        const { job_id } = await asyncRes.json();
        setPhase('analyzing');
        analysisResult = await pollJob(job_id, token);
      } else if (asyncRes.ok) {
        setPhase('analyzing');
        analysisResult = await asyncRes.json();
      } else {
        const syncRes = await fetch(`${API_BASE}/analyze`, {
          method: 'POST',
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          body: makeFormData(),
        });
        if (syncRes.status === 401) {
          navigate('/login');
          return;
        }
        if (!syncRes.ok) {
          const errorData = await syncRes.json().catch(() => ({}));
          throw new Error(errorData.detail || 'Analysis failed');
        }
        setPhase('analyzing');
        analysisResult = await syncRes.json();
      }

      progressRef.current = 100;
      setSmoothProgress(100);
      setResult(analysisResult);
      onComplete(analysisResult);
      setPhase('complete');
    } catch (err: unknown) {
      setPhase('error');
      setError(err instanceof Error ? err.message : 'Analysis pipeline failed.');
    }
  }, [file, isBusy, pollJob, navigate, onComplete]);

  return {
    phase,
    file,
    setFile,
    error,
    smoothProgress,
    result,
    isBusy,
    startAnalysis,
    reset,
  };
}
