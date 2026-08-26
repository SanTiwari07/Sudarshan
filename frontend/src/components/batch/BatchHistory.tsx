import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layers, ArrowRight, Clock, CheckCircle2, AlertTriangle, XCircle, Loader2, RefreshCw } from 'lucide-react';
import { API_BASE, authHeaders } from '../../config';
import type { BatchSummary, BatchListResponse } from '../../types/batch';
import { fmtDate } from '../../utils/derive';

export default function BatchHistory() {
  const navigate = useNavigate();
  const [batches, setBatches] = useState<BatchSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchBatches = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/batches?limit=20&offset=0`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        throw new Error(`Failed to load batches (${res.status})`);
      }
      const data: BatchListResponse = await res.json();
      setBatches(data.batches);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.message || 'Error fetching batch history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBatches();
  }, []);

  const getStatusPill = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
            <CheckCircle2 className="w-3 h-3" /> Completed
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-200">
            <AlertTriangle className="w-3 h-3" /> Partial
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-200 animate-pulse">
            <Loader2 className="w-3 h-3 animate-spin" /> Processing
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-800 border border-red-200">
            <XCircle className="w-3 h-3" /> Failed
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-300">
            <XCircle className="w-3 h-3" /> Cancelled
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
            <Clock className="w-3 h-3" /> {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-bold text-slate-900 font-mono tracking-tight flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-600" />
            Batch History ({total})
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Previous bulk analysis sessions and their execution status.
          </p>
        </div>
        <button
          type="button"
          onClick={fetchBatches}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 transition-colors shadow-2xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700">
          {error}
        </div>
      )}

      {loading && batches.length === 0 ? (
        <div className="py-12 text-center text-slate-400 text-sm flex flex-col items-center gap-2">
          <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
          <span>Loading batch history…</span>
        </div>
      ) : batches.length === 0 ? (
        <div className="py-12 px-4 text-center border-2 border-dashed border-slate-200 rounded-xl bg-surface-secondary">
          <Layers className="w-8 h-8 text-slate-400 mx-auto mb-2" />
          <p className="text-sm font-semibold text-slate-700">No batches analyzed yet</p>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Upload multiple APK files to launch your first enterprise bulk analysis.
          </p>
        </div>
      ) : (
        <div className="bg-surface-card border border-slate-200/80 rounded-xl shadow-xs overflow-hidden w-full">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-[13px] font-bold text-slate-500 uppercase tracking-wider font-mono bg-surface-secondary">
                  <th className="py-3 px-4">Batch ID</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Date & Time</th>
                  <th className="py-3 px-4">APKs & Execution</th>
                  <th className="py-3 px-4 min-w-[180px]">Overall Progress</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-xs">
                {batches.map((batch) => (
                  <tr
                    key={batch.batch_id}
                    onClick={() => navigate(`/batch/${batch.batch_id}`)}
                    className="hover:bg-blue-50/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-bold text-slate-900 whitespace-nowrap">
                      #{batch.batch_id.slice(0, 8)}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getStatusPill(batch.status)}
                    </td>
                    <td className="py-3.5 px-4 text-slate-500 text-[13px] whitespace-nowrap">
                      {fmtDate(batch.created_at)}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="font-semibold text-slate-800">
                        {batch.total_jobs} APK{batch.total_jobs === 1 ? '' : 's'}
                      </span>
                      <span className="text-slate-400 text-[13px] ml-1.5">
                        ({batch.completed_jobs} done{batch.failed_jobs > 0 ? `, ${batch.failed_jobs} failed` : ''})
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2.5">
                        <div className="h-2 flex-1 bg-slate-100 rounded-full overflow-hidden border border-slate-200/60">
                          <div
                            className={`h-full transition-all duration-300 ${
                              batch.status === 'COMPLETED'
                                ? 'bg-emerald-600'
                                : batch.status === 'FAILED'
                                ? 'bg-red-500'
                                : 'bg-blue-600'
                            }`}
                            style={{ width: `${batch.progress_pct}%` }}
                          />
                        </div>
                        <span className="text-[13px] text-slate-600 font-semibold w-10 text-right">
                          {batch.progress_pct}%
                        </span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 font-semibold text-blue-700 group-hover:text-blue-900 text-xs">
                        View Batch <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
