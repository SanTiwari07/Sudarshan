import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Layers,
  ArrowLeft,
  PauseCircle,
  PlayCircle,
  XCircle,
  RefreshCw,
  Clock,
  ShieldCheck,
  User,
} from 'lucide-react';
import { SocCard } from '../ui/Card';
import BatchProgressBar from './BatchProgressBar';
import BatchJobRow from './BatchJobRow';
import { useBatchProgress } from './useBatchProgress';
import { fmtDate } from '../../utils/derive';
import { LoadingSpinner, ErrorState } from '../ui/Skeleton';

export default function BatchDetailPage() {
  const { batch_id } = useParams<{ batch_id: string }>();
  const navigate = useNavigate();

  const {
    batch,
    loading,
    error,
    actionLoading,
    refresh,
    pauseBatch,
    resumeBatch,
    cancelBatch,
    retryJob,
  } = useBatchProgress(batch_id || null);

  if (loading && !batch) {
    return (
      <div className="py-20">
        <LoadingSpinner label={`Loading Batch ${batch_id?.slice(0, 8)}…`} />
      </div>
    );
  }

  if (error && !batch) {
    return (
      <div className="max-w-4xl mx-auto py-10 px-4">
        <ErrorState
          title="Batch Not Found"
          message={error || `Could not find batch with ID ${batch_id}`}
        />
        <div className="mt-4 text-center">
          <Link
            to="/batch"
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" /> Back to Batch Scan
          </Link>
        </div>
      </div>
    );
  }

  if (!batch) return null;

  const isScanning = batch.status === 'RUNNING';
  const isPaused = batch.status === 'PAUSED';
  const isTerminal =
    batch.status === 'COMPLETED' ||
    batch.status === 'PARTIAL' ||
    batch.status === 'FAILED' ||
    batch.status === 'CANCELLED';

  return (
    <div className="upload-fade-in flex justify-center px-4 py-8 sm:py-12">
      <div className="w-full max-w-[72rem] space-y-6">
        {/* Navigation & Header */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => navigate('/batch')}
              className="p-2 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
              title="Back to Batch Scan"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100 font-mono">
                  Enterprise Batch
                </span>
                <span className="text-xs font-mono text-slate-400">
                  ID: {batch.batch_id}
                </span>
              </div>
              <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 font-mono tracking-tight mt-0.5">
                Batch #{batch.batch_id.slice(0, 8)}
              </h1>
            </div>
          </div>

          {/* Action Controls */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => refresh()}
              disabled={actionLoading}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 shadow-2xs transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${actionLoading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>

            {isScanning && (
              <button
                type="button"
                onClick={pauseBatch}
                disabled={actionLoading}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold text-amber-700 bg-amber-50 border border-amber-200 hover:bg-amber-100 shadow-2xs transition-colors cursor-pointer"
              >
                <PauseCircle className="w-3.5 h-3.5" />
                <span>Pause Queue</span>
              </button>
            )}

            {isPaused && (
              <button
                type="button"
                onClick={resumeBatch}
                disabled={actionLoading}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 hover:bg-emerald-100 shadow-2xs transition-colors cursor-pointer"
              >
                <PlayCircle className="w-3.5 h-3.5" />
                <span>Resume Queue</span>
              </button>
            )}

            {!isTerminal && (
              <button
                type="button"
                onClick={cancelBatch}
                disabled={actionLoading}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold text-red-700 bg-red-50 border border-red-200 hover:bg-red-100 shadow-2xs transition-colors cursor-pointer"
              >
                <XCircle className="w-3.5 h-3.5" />
                <span>Cancel Remaining</span>
              </button>
            )}
          </div>
        </div>

        {/* Progress & Overview Card */}
        <SocCard className="p-6 sm:p-8 border-slate-200/80 shadow-sm">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 pb-6 border-b border-slate-100">
            {/* Metadata column */}
            <div className="space-y-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
                Batch Metadata
              </span>
              <div className="space-y-1.5 text-xs">
                <div className="flex items-center justify-between text-slate-600">
                  <span className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-slate-400" /> Created:
                  </span>
                  <span className="font-mono font-medium text-slate-800">
                    {fmtDate(batch.created_at)}
                  </span>
                </div>
                {batch.started_at && (
                  <div className="flex items-center justify-between text-slate-600">
                    <span className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-400" /> Started:
                    </span>
                    <span className="font-mono font-medium text-slate-800">
                      {fmtDate(batch.started_at)}
                    </span>
                  </div>
                )}
                {batch.completed_at && (
                  <div className="flex items-center justify-between text-slate-600">
                    <span className="flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-slate-400" /> Completed:
                    </span>
                    <span className="font-mono font-medium text-slate-800">
                      {fmtDate(batch.completed_at)}
                    </span>
                  </div>
                )}
                <div className="flex items-center justify-between text-slate-600">
                  <span className="flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-slate-400" /> Analyst ID:
                  </span>
                  <span className="font-mono font-medium text-slate-800">
                    #{batch.created_by}
                  </span>
                </div>
              </div>
            </div>

            {/* Live Progress Bar column (spans 2) */}
            <div className="lg:col-span-2 flex flex-col justify-center">
              <BatchProgressBar batch={batch} />
            </div>
          </div>

          {/* Risk Summary Pills for Completed APKs */}
          {batch.completed_jobs > 0 && (
            <div className="pt-4 flex flex-wrap items-center gap-2 text-xs">
              <span className="font-semibold text-slate-500 font-mono mr-1">
                Risk Distribution:
              </span>
              {batch.critical_count ? (
                <span className="px-2.5 py-0.5 rounded-full font-bold bg-red-600 text-white font-mono">
                  {batch.critical_count} Critical
                </span>
              ) : null}
              {batch.high_risk_count ? (
                <span className="px-2.5 py-0.5 rounded-full font-bold bg-orange-500 text-white font-mono">
                  {batch.high_risk_count} High Risk
                </span>
              ) : null}
              {batch.suspicious_count ? (
                <span className="px-2.5 py-0.5 rounded-full font-bold bg-amber-400 text-gray-900 font-mono">
                  {batch.suspicious_count} Suspicious
                </span>
              ) : null}
              {batch.safe_count ? (
                <span className="px-2.5 py-0.5 rounded-full font-bold bg-emerald-600 text-white font-mono">
                  {batch.safe_count} Safe
                </span>
              ) : null}
            </div>
          )}
        </SocCard>

        {/* Jobs / Results Table */}
        <SocCard className="overflow-hidden border-slate-200/80 shadow-sm">
          <div className="py-4 px-6 border-b border-slate-200/80 bg-slate-50/50 flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-900 font-mono uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-600" />
              Analysis Queue & Results ({batch.jobs.length})
            </h2>
            <span className="text-xs text-slate-500 font-mono">
              FIFO Sequential Execution
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-[11px] font-bold text-slate-500 uppercase tracking-wider font-mono bg-slate-50/80">
                  <th className="py-3 px-4">APK File</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Risk Band</th>
                  <th className="py-3 px-4">FRS</th>
                  <th className="py-3 px-4">Stage / SHA</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {batch.jobs.map((job) => (
                  <BatchJobRow
                    key={job.job_id}
                    job={job}
                    onRetry={retryJob}
                    actionLoading={actionLoading}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </SocCard>
      </div>
    </div>
  );
}
