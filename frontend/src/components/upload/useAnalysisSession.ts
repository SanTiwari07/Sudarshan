import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import { API_BASE } from '../../config';
import { getToken } from '../../pages/Login';
import { resolvePipelineUi, type BackendPipelineState } from './backendPipelineStages';

export type AnalysisSessionState =
  | 'idle'
  | 'uploading'
  | 'analyzing'
  | 'complete'
  | 'error';

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
  const [pipelineUi, setPipelineUi] = useState<ReturnType<typeof resolvePipelineUi> | null>(
    null,
  );

  const abortRef = useRef(false);
  const targetProgressRef = useRef(0);

  const reset = useCallback(() => {
    abortRef.current = true;
    abortRef.current = false;
    targetProgressRef.current = 0;
    setPhase('idle');
    setFile(null);
    setError(null);
    setSmoothProgress(0);
    setResult(null);
    setPipelineUi(null);
  }, []);

  const isBusy = phase === 'uploading' || phase === 'analyzing';

  useEffect(() => {
    if (!isBusy) return;
    let raf: number;
    const tick = () => {
      setSmoothProgress((prev) => {
        const target = targetProgressRef.current;
        if (Math.abs(target - prev) < 0.5) return target;
        return prev + (target - prev) * 0.15;
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [isBusy]);

  const applyBackendPipeline = useCallback((data: BackendPipelineState & { status?: string }) => {
    const ui = resolvePipelineUi(data);
    setPipelineUi(ui);
    if (typeof data.progress_pct === 'number') {
      targetProgressRef.current = data.progress_pct;
    } else if (data.status === 'processing') {
      targetProgressRef.current = Math.max(targetProgressRef.current, ui.progress);
    }
  }, []);

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
        applyBackendPipeline(data);

        if (data.status === 'queued') {
          targetProgressRef.current = Math.max(targetProgressRef.current, 3);
        } else if (data.status === 'processing') {
          targetProgressRef.current = Math.max(
            targetProgressRef.current,
            typeof data.progress_pct === 'number' ? data.progress_pct : 5,
          );
        } else if (data.status === 'done' && data.result) {
          targetProgressRef.current = 100;
          setSmoothProgress(100);
          return data.result as FraudCardData;
        } else if (data.status === 'failed') {
          throw new Error(data.error || 'Analysis job failed');
        }
        await new Promise((r) => setTimeout(r, 1200));
      }
    },
    [navigate, applyBackendPipeline],
  );

  const startAnalysis = useCallback(async () => {
    if (!file || isBusy) return;

    setError(null);
    setPhase('uploading');
    targetProgressRef.current = 2;
    setSmoothProgress(2);
    setPipelineUi(
      resolvePipelineUi({
        pipeline_stage: 'VALIDATING',
        pipeline_message: 'Uploading APK to Sudarshan gateway…',
        progress_pct: 2,
      }),
    );

    const token = getToken();
    await sha256Hex(file);

    const makeFormData = () => {
      const fd = new FormData();
      fd.append('file', file);
      return fd;
    };

    try {
      targetProgressRef.current = 5;
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
        applyBackendPipeline({
          pipeline_stage: 'QUEUED',
          pipeline_message: 'Job queued - waiting for worker…',
          progress_pct: 5,
        });
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

      targetProgressRef.current = 100;
      setSmoothProgress(100);
      setPipelineUi(resolvePipelineUi({ pipeline_stage: 'COMPLETED', progress_pct: 100 }));
      setResult(analysisResult);
      onComplete(analysisResult);
      setPhase('complete');
    } catch (err: unknown) {
      setPhase('error');
      setError(err instanceof Error ? err.message : 'Analysis pipeline failed.');
    }
  }, [file, isBusy, pollJob, navigate, onComplete, applyBackendPipeline]);

  return {
    phase,
    file,
    setFile,
    error,
    smoothProgress,
    result,
    pipelineUi,
    isBusy,
    startAnalysis,
    reset,
  };
}
