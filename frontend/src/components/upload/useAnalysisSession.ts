import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { FraudCardData } from '../../types/case';
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

// Threat-intel correlation (VirusTotal family attribution and the score uplift it
// carries) is not run by the analysis pipeline. It runs lazily, server-side, the
// first time GET /cases/{sha256} is called. So the job result a fresh upload polls
// for still says family "Unknown" and carries the pre-correlation score, while the
// same case opened later from Case History shows the real family and a higher
// score. Fetching the case once, here, both triggers that correlation and gives
// the just-uploaded view the same numbers the case page will show.
//
// Only the correlation-derived fields are taken. The case record uses different
// names for some collections (dangerous_perms vs dangerous_permissions,
// services_list vs services), so replacing the object wholesale would blank the
// panels that read the response-model names.
const INTEL_FIELDS = [
  'family_classification',
  'final_risk_score',
  'risk_band',
  'base_score',
  'confidence',
  'ai_confidence_multiplier',
  'recommended_action',
  'risk_explanation',
  'threat_correlation',
  'threat_scenario_table',
  'frs_breakdown',
] as const;

async function mergeCorrelatedIntel(
  result: FraudCardData,
  token: string | null,
): Promise<FraudCardData> {
  const sha256 = (result as unknown as { sha256?: string }).sha256;
  if (!sha256) return result;
  try {
    const res = await fetch(`${API_BASE}/cases/${sha256}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) return result;
    const enriched = (await res.json()) as Record<string, unknown>;
    const merged: Record<string, unknown> = { ...(result as unknown as Record<string, unknown>) };
    for (const key of INTEL_FIELDS) {
      if (enriched[key] !== undefined && enriched[key] !== null) merged[key] = enriched[key];
    }
    return merged as unknown as FraudCardData;
  } catch {
    // A correlation lookup that fails must not fail the analysis the analyst is
    // watching. Fall back to the uncorrelated result.
    return result;
  }
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
          return await mergeCorrelatedIntel(data.result as FraudCardData, token);
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

  const startAnalysisFromJob = useCallback(async (jobId: string, filename: string) => {
    if (isBusy) return;

    setError(null);
    setPhase('analyzing');
    targetProgressRef.current = 5;
    setSmoothProgress(5);
    setPipelineUi(
      resolvePipelineUi({
        pipeline_stage: 'QUEUED',
        pipeline_message: 'Job queued - waiting for worker…',
        progress_pct: 5,
      }),
    );
    // Create a mock file object just for the UI name display
    setFile(new File([], filename));

    const token = getToken();

    try {
      const analysisResult = await pollJob(jobId, token);
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
  }, [isBusy, pollJob, onComplete]);

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
    startAnalysisFromJob,
    reset,
  };
}
