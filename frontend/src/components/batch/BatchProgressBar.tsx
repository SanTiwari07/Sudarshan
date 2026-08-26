import { CheckCircle2, Clock, AlertTriangle, XCircle, Loader2, PauseCircle } from 'lucide-react';
import type { BatchSummary } from '../../types/batch';

interface BatchProgressBarProps {
  batch: BatchSummary;
  scanningCount?: number;
  queuedCount?: number;
  className?: string;
}

export default function BatchProgressBar({
  batch,
  scanningCount = 0,
  queuedCount = 0,
  className = '',
}: BatchProgressBarProps) {
  const {
    total_jobs,
    completed_jobs,
    failed_jobs,
    cancelled_jobs,
    status,
    progress_pct,
  } = batch;

  // Active scanning calculation
  const activeScanning = scanningCount > 0 ? scanningCount : status === 'RUNNING' ? 1 : 0;
  // Queued calculation
  const remainingQueued =
    queuedCount > 0
      ? queuedCount
      : Math.max(0, total_jobs - completed_jobs - failed_jobs - cancelled_jobs - activeScanning);

  const getStatusBadge = () => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
            <CheckCircle2 className="w-3.5 h-3.5" /> Completed
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-200">
            <AlertTriangle className="w-3.5 h-3.5" /> Partial
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-200 animate-pulse">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Processing
          </span>
        );
      case 'PAUSED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-800 border border-slate-300">
            <PauseCircle className="w-3.5 h-3.5" /> Paused
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-800 border border-red-200">
            <XCircle className="w-3.5 h-3.5" /> Failed
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-300">
            <XCircle className="w-3.5 h-3.5" /> Cancelled
          </span>
        );
      case 'QUEUED':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
            <Clock className="w-3.5 h-3.5" /> Queued
          </span>
        );
    }
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Header & Percentage */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="text-xl font-bold text-slate-900 font-mono tracking-tight">
            {completed_jobs} / {total_jobs} completed
          </span>
          {getStatusBadge()}
        </div>
        <span className="text-sm font-semibold font-mono text-slate-600">
          {progress_pct}% overall
        </span>
      </div>

      {/* Modern Multi-segment Progress Bar */}
      <div className="h-3 w-full bg-slate-100 rounded-full overflow-hidden flex border border-slate-200 shadow-inner">
        {completed_jobs > 0 && (
          <div
            className="bg-emerald-600 transition-all duration-500 ease-out"
            style={{ width: `${(completed_jobs / total_jobs) * 100}%` }}
            title={`Completed: ${completed_jobs}`}
          />
        )}
        {activeScanning > 0 && (
          <div
            className="bg-blue-600 animate-pulse transition-all duration-500 ease-out"
            style={{ width: `${(activeScanning / total_jobs) * 100}%` }}
            title={`Scanning: ${activeScanning}`}
          />
        )}
        {failed_jobs > 0 && (
          <div
            className="bg-red-500 transition-all duration-500 ease-out"
            style={{ width: `${(failed_jobs / total_jobs) * 100}%` }}
            title={`Failed: ${failed_jobs}`}
          />
        )}
        {cancelled_jobs > 0 && (
          <div
            className="bg-slate-400 transition-all duration-500 ease-out"
            style={{ width: `${(cancelled_jobs / total_jobs) * 100}%` }}
            title={`Cancelled: ${cancelled_jobs}`}
          />
        )}
      </div>

      {/* Discrete Counter Pills */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1">
        <div className="flex items-center gap-2 p-2 rounded-lg bg-emerald-50/70 border border-emerald-100">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-emerald-800 uppercase tracking-wider">
              Completed
            </div>
            <div className="text-sm font-bold font-mono text-emerald-950">
              {completed_jobs}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 p-2 rounded-lg bg-blue-50/70 border border-blue-100">
          <Loader2 className={`w-4 h-4 text-blue-600 shrink-0 ${activeScanning > 0 ? 'animate-spin' : ''}`} />
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-blue-800 uppercase tracking-wider">
              Scanning
            </div>
            <div className="text-sm font-bold font-mono text-blue-950">
              {activeScanning}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 border border-slate-200">
          <Clock className="w-4 h-4 text-slate-500 shrink-0" />
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-slate-600 uppercase tracking-wider">
              Queued
            </div>
            <div className="text-sm font-bold font-mono text-slate-800">
              {remainingQueued}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 p-2 rounded-lg bg-red-50/70 border border-red-100">
          <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-red-800 uppercase tracking-wider">
              Failed
            </div>
            <div className="text-sm font-bold font-mono text-red-950">
              {failed_jobs}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 border border-slate-200 col-span-2 sm:col-span-1">
          <XCircle className="w-4 h-4 text-slate-500 shrink-0" />
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-slate-600 uppercase tracking-wider">
              Cancelled
            </div>
            <div className="text-sm font-bold font-mono text-slate-800">
              {cancelled_jobs}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
