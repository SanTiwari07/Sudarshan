import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Eye, RotateCw, AlertCircle, CheckCircle2, Clock, Loader2, XCircle, ChevronDown, ChevronUp } from 'lucide-react';
import type { BatchJob } from '../../types/batch';
import Badge from '../ui/Badge';
import { fmtScore } from '../../utils/derive';

interface BatchJobRowProps {
  job: BatchJob;
  onRetry?: (jobId: string) => Promise<void>;
  actionLoading?: boolean;
}

export default function BatchJobRow({ job, onRetry, actionLoading }: BatchJobRowProps) {
  const navigate = useNavigate();
  const [showError, setShowError] = useState(false);

  const handleView = () => {
    if (job.case_sha256) {
      navigate(`/history/${job.case_sha256}`);
    } else if (job.sha256) {
      navigate(`/history/${job.sha256}`);
    }
  };

  const renderStatus = () => {
    switch (job.status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <CheckCircle2 className="w-3.5 h-3.5" /> Completed
          </span>
        );
      case 'SCANNING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200 animate-pulse">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Scanning
          </span>
        );
      case 'QUEUED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-50 text-slate-600 border border-slate-200">
            <Clock className="w-3.5 h-3.5" /> Queued (#{job.queue_position + 1})
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
            <XCircle className="w-3.5 h-3.5" /> Failed
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-100 text-slate-500 border border-slate-200">
            <XCircle className="w-3.5 h-3.5" /> Cancelled
          </span>
        );
      default:
        return <span className="text-xs text-slate-500">{job.status}</span>;
    }
  };

  const renderRisk = () => {
    if (job.status !== 'COMPLETED') {
      return <span className="text-slate-400 font-mono text-xs">-</span>;
    }
    if (!job.risk_band) {
      return <span className="text-slate-400 font-mono text-xs">Analyzed</span>;
    }
    return <Badge label={job.risk_band} variant="risk" />;
  };

  const renderScore = () => {
    if (job.status !== 'COMPLETED' || job.final_risk_score == null) {
      return <span className="text-slate-400 font-mono text-xs">-</span>;
    }
    return (
      <span className="font-mono font-bold text-sm text-slate-800">
        {fmtScore(job.final_risk_score)}
      </span>
    );
  };

  const renderStageOrInfo = () => {
    if (job.status === 'SCANNING') {
      return (
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-medium text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
            {job.current_stage || 'Processing'}
          </span>
          {job.progress_pct > 0 && (
            <span className="text-[13px] font-mono text-slate-500">
              {job.progress_pct}%
            </span>
          )}
        </div>
      );
    }
    if (job.status === 'FAILED' && job.error) {
      return (
        <button
          type="button"
          onClick={() => setShowError(!showError)}
          className="inline-flex items-center gap-1 text-xs text-red-600 hover:text-red-800 font-medium cursor-pointer"
        >
          <AlertCircle className="w-3.5 h-3.5" />
          <span>Error details</span>
          {showError ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </button>
      );
    }
    if (job.status === 'COMPLETED' && job.case_sha256) {
      return (
        <span className="text-xs font-mono text-slate-500 truncate max-w-[120px] block" title={job.case_sha256}>
          {job.case_sha256.slice(0, 10)}…
        </span>
      );
    }
    return <span className="text-slate-400 font-mono text-xs">-</span>;
  };

  const renderAction = () => {
    if (job.status === 'COMPLETED' && (job.case_sha256 || job.sha256)) {
      return (
        <button
          type="button"
          onClick={handleView}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-blue-700 hover:bg-blue-800 shadow-xs hover:shadow transition-all duration-150 cursor-pointer"
        >
          <Eye className="w-3.5 h-3.5" />
          <span>View</span>
        </button>
      );
    }
    if (job.status === 'FAILED' && onRetry) {
      return (
        <button
          type="button"
          disabled={actionLoading}
          onClick={() => onRetry(job.job_id)}
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 hover:text-slate-900 disabled:opacity-50 transition-all cursor-pointer"
        >
          <RotateCw className={`w-3.5 h-3.5 ${actionLoading ? 'animate-spin' : ''}`} />
          <span>Retry</span>
        </button>
      );
    }
    return <span className="text-slate-300 font-mono text-xs">-</span>;
  };

  return (
    <>
      <tr className="border-b border-slate-100 hover:bg-slate-50/70 transition-colors">
        {/* APK Filename & SHA256 */}
        <td className="py-3.5 px-4 font-medium text-slate-900">
          <div className="flex flex-col">
            <span className="text-xs sm:text-sm font-semibold truncate max-w-[220px] sm:max-w-[280px]" title={job.filename}>
              {job.filename}
            </span>
            {job.sha256 && (
              <span className="text-[12px] font-mono text-slate-400 truncate max-w-[160px]">
                SHA: {job.sha256.slice(0, 12)}…
              </span>
            )}
          </div>
        </td>

        {/* Status */}
        <td className="py-3.5 px-4">{renderStatus()}</td>

        {/* Risk Band */}
        <td className="py-3.5 px-4">{renderRisk()}</td>

        {/* Deterministic FRS Score */}
        <td className="py-3.5 px-4">{renderScore()}</td>

        {/* Stage / Info */}
        <td className="py-3.5 px-4">{renderStageOrInfo()}</td>

        {/* Action */}
        <td className="py-3.5 px-4 text-right">{renderAction()}</td>
      </tr>

      {/* Expandable Error Detail Row */}
      {showError && job.error && (
        <tr className="bg-red-50/50 border-b border-red-100">
          <td colSpan={6} className="py-2.5 px-4">
            <div className="text-xs font-mono text-red-800 p-2.5 rounded bg-red-100/50 border border-red-200 break-all">
              <span className="font-bold">Failure reason: </span>
              {job.error}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

