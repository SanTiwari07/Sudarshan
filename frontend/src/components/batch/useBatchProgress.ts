import { useState, useEffect, useCallback, useRef } from 'react';
import { API_BASE, authHeaders } from '../../config';
import type { BatchDetail, BatchJob } from '../../types/batch';

interface CaseRiskCache {
  [sha256: string]: {
    final_risk_score: number | null;
    risk_band: string | null;
  };
}

export function useBatchProgress(batchId: string | null) {
  const [batch, setBatch] = useState<BatchDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<boolean>(false);

  const caseCacheRef = useRef<CaseRiskCache>({});
  const isPollingRef = useRef<boolean>(false);

  const fetchBatch = useCallback(async () => {
    if (!batchId) return;

    try {
      const res = await fetch(`${API_BASE}/batches/${batchId}`, {
        headers: authHeaders(),
      });

      if (!res.ok) {
        if (res.status === 404) {
          setError('Batch not found');
          return;
        }
        throw new Error(`Failed to load batch (${res.status})`);
      }

      const data: BatchDetail = await res.json();

      // For completed jobs with case_sha256, enrich with risk info if available
      const completedSha256s = data.jobs
        .filter((j) => j.status === 'COMPLETED' && j.case_sha256 && !caseCacheRef.current[j.case_sha256])
        .map((j) => j.case_sha256 as string);

      if (completedSha256s.length > 0) {
        // Fetch lightweight case summary for newly completed items in parallel
        await Promise.allSettled(
          completedSha256s.map(async (sha256) => {
            try {
              const caseRes = await fetch(`${API_BASE}/cases/${sha256}`, {
                headers: authHeaders(),
              });
              if (caseRes.ok) {
                const cData = await caseRes.json();
                caseCacheRef.current[sha256] = {
                  final_risk_score: cData.final_risk_score ?? null,
                  risk_band: cData.risk_band ?? null,
                };
              }
            } catch {
              // Ignore individual case fetch errors
            }
          })
        );
      }

      // Merge cached case scores into jobs
      const enrichedJobs: BatchJob[] = data.jobs.map((job) => {
        if (job.case_sha256 && caseCacheRef.current[job.case_sha256]) {
          return {
            ...job,
            final_risk_score: caseCacheRef.current[job.case_sha256].final_risk_score,
            risk_band: caseCacheRef.current[job.case_sha256].risk_band,
          };
        }
        return job;
      });

      // Calculate risk summary counts
      let critical_count = 0;
      let high_risk_count = 0;
      let suspicious_count = 0;
      let safe_count = 0;

      enrichedJobs.forEach((j) => {
        if (j.status === 'COMPLETED' && j.risk_band) {
          const band = j.risk_band.toLowerCase();
          if (band.includes('critical')) critical_count++;
          else if (band.includes('high')) high_risk_count++;
          else if (band.includes('suspicious')) suspicious_count++;
          else safe_count++;
        }
      });

      setBatch({
        ...data,
        jobs: enrichedJobs,
        critical_count,
        high_risk_count,
        suspicious_count,
        safe_count,
      });
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Error fetching batch status');
    } finally {
      setLoading(false);
    }
  }, [batchId]);

  // Initial load
  useEffect(() => {
    if (!batchId) {
      setBatch(null);
      return;
    }
    setLoading(true);
    fetchBatch();
  }, [batchId, fetchBatch]);

  // Periodic polling for active batch
  useEffect(() => {
    if (!batchId) return;

    const isTerminal =
      batch?.status === 'COMPLETED' ||
      batch?.status === 'PARTIAL' ||
      batch?.status === 'FAILED' ||
      batch?.status === 'CANCELLED';

    if (isTerminal) return;

    const interval = setInterval(() => {
      if (!isPollingRef.current) {
        isPollingRef.current = true;
        fetchBatch().finally(() => {
          isPollingRef.current = false;
        });
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [batchId, batch?.status, fetchBatch]);

  const pauseBatch = async () => {
    if (!batchId) return;
    setActionLoading(true);
    try {
      const res = await fetch(`${API_BASE}/batches/${batchId}/pause`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || 'Failed to pause batch');
      }
      await fetchBatch();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const resumeBatch = async () => {
    if (!batchId) return;
    setActionLoading(true);
    try {
      const res = await fetch(`${API_BASE}/batches/${batchId}/resume`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || 'Failed to resume batch');
      }
      await fetchBatch();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const cancelBatch = async () => {
    if (!batchId) return;
    setActionLoading(true);
    try {
      const res = await fetch(`${API_BASE}/batches/${batchId}/cancel`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || 'Failed to cancel batch');
      }
      await fetchBatch();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const retryJob = async (jobId: string) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API_BASE}/batch-jobs/${jobId}/retry`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || 'Failed to retry job');
      }
      await fetchBatch();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  return {
    batch,
    loading,
    error,
    actionLoading,
    refresh: fetchBatch,
    pauseBatch,
    resumeBatch,
    cancelBatch,
    retryJob,
  };
}
