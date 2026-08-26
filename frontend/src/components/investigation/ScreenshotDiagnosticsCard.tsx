import { Link } from 'react-router-dom';
import {
  AlertCircle,
  Camera,
  Clock,
  GitBranch,
  RefreshCw,
  ScrollText,
  Terminal,
} from 'lucide-react';
import type { FraudCardData } from '../../App';
import type { RuntimeScreenshotMeta } from '../../lib/screenshotManifest';
import { formatScreenshotTime, inferFailureReasonFromCase } from '../../lib/screenshotManifest';
import type { ScreenshotUxState } from '../../lib/investigationRuntime';
import { useCaseLinks } from '../../hooks/useCaseLinks';

const POSSIBLE_CAUSES = [
  'App crashed during launch',
  'No UI screens were reached',
  'Emulator unavailable',
  'Capture service stopped',
  'Timeout exceeded',
];

type Props = {
  data: FraudCardData;
  runtime: RuntimeScreenshotMeta | null;
  captured: number;
  uxState?: ScreenshotUxState;
  compact?: boolean;
};

export default function ScreenshotDiagnosticsCard({
  data,
  runtime,
  captured,
  uxState,
  compact = false,
}: Props) {
  const links = useCaseLinks();
  const reason =
    runtime?.failureReason || inferFailureReasonFromCase(data, captured) || 'Screenshots unavailable';

  const expected = runtime?.expected ?? '-';
  const reported = runtime?.reportedCaptured ?? runtime?.captured ?? 0;
  const interval =
    runtime?.captureIntervalSeconds != null ? `${runtime.captureIntervalSeconds}s` : '-';
  const duration =
    runtime?.dynamicDurationSeconds != null
      ? `${Math.round(runtime.dynamicDurationSeconds)}s`
      : (data.dynamic_analysis as { duration_seconds?: number } | undefined)?.duration_seconds != null
        ? `${Math.round(Number((data.dynamic_analysis as { duration_seconds?: number }).duration_seconds))}s`
        : '-';
  const lastCapture = runtime?.lastCaptureTimestampMs
    ? formatScreenshotTime(runtime.lastCaptureTimestampMs)
    : runtime?.lastCaptureIso
      ? new Date(runtime.lastCaptureIso).toLocaleTimeString()
      : '-';

  return (
    <div
      className={`rounded-xl border border-slate-200 bg-gradient-to-br from-slate-50 to-white p-4 shadow-sm ${
        compact ? 'max-h-none' : 'max-h-[280px] overflow-y-auto'
      }`}
    >
      <div className="flex gap-3">
        <div className="p-2 rounded-lg bg-amber-50 text-amber-700 border border-amber-100 shrink-0 h-fit">
          <Camera className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1 space-y-2">
          <div>
            <p className="text-sm font-semibold text-slate-900 flex items-center gap-1.5">
              <AlertCircle className="h-3.5 w-3.5 text-amber-600 shrink-0" />
              {uxState === 'CAPTURE_FAILED' ? 'View runtime diagnostics' : reason}
            </p>
            {!compact && (
              <p className="text-[11px] text-slate-500 mt-1 leading-snug">
                Visual sandbox captures were not available for this run. Metadata below reflects the dynamic analysis
                session.
              </p>
            )}
          </div>

          {!compact && (
            <>
              <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-3 gap-y-1 text-[10px]">
            <div>
              <dt className="text-slate-500 uppercase tracking-wide">Expected</dt>
              <dd className="font-mono font-semibold text-slate-800">{expected}</dd>
            </div>
            <div>
              <dt className="text-slate-500 uppercase tracking-wide">Captured</dt>
              <dd className="font-mono font-semibold text-slate-800">{reported}</dd>
            </div>
            <div>
              <dt className="text-slate-500 uppercase tracking-wide">Interval</dt>
              <dd className="font-mono text-slate-700">{interval}</dd>
            </div>
            <div>
              <dt className="text-slate-500 uppercase tracking-wide">Dyn. duration</dt>
              <dd className="font-mono text-slate-700 flex items-center gap-1">
                <Clock className="h-3 w-3 text-slate-500" />
                {duration}
              </dd>
            </div>
            <div className="col-span-2 sm:col-span-2">
              <dt className="text-slate-500 uppercase tracking-wide">Last capture</dt>
              <dd className="font-mono text-slate-700">{lastCapture}</dd>
            </div>
          </dl>

          <div>
            <p className="text-[10px] font-bold uppercase text-slate-500 mb-1">Possible causes</p>
            <ul className="text-[10px] text-slate-600 columns-1 sm:columns-2 gap-x-4 leading-relaxed">
              {POSSIBLE_CAUSES.map((c) => (
                <li key={c} className="break-inside-avoid">
                  · {c}
                </li>
              ))}
            </ul>
          </div>
            </>
          )}

          <div className="flex flex-wrap gap-2 pt-1">
            <Link
              to="/"
              className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-semibold text-white bg-blue-700 rounded-md hover:bg-blue-800"
            >
              <RefreshCw className="h-3 w-3" />
              Retry Dynamic Analysis
            </Link>
            <Link
              to="/"
              className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-semibold text-slate-700 bg-white border border-slate-200 rounded-md hover:border-blue-300"
              title="Re-run full pipeline including capture"
            >
              <Camera className="h-3 w-3" />
              Retry Capture
            </Link>
            <Link
              to={links.evidence}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-semibold text-slate-700 bg-white border border-slate-200 rounded-md hover:border-blue-300"
            >
              <ScrollText className="h-3 w-3" />
              Runtime Logs
            </Link>
            <a
              href="#evidence-timeline"
              className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-semibold text-slate-700 bg-white border border-slate-200 rounded-md hover:border-blue-300"
            >
              <GitBranch className="h-3 w-3" />
              Timeline
            </a>
          </div>

          {runtime?.warnings && runtime.warnings.length > 0 && (
            <p className="text-[10px] text-amber-800 bg-amber-50 border border-amber-100 rounded px-2 py-1 flex gap-1">
              <Terminal className="h-3 w-3 shrink-0 mt-0.5" />
              {runtime.warnings[0]}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
