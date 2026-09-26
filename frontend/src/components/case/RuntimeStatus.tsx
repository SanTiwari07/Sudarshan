import { Activity, HelpCircle, Camera, Network, ShieldCheck, ChevronRight } from 'lucide-react';
import CardTitle from '../ui/CardTitle';
import type { FraudCardData } from '../../types/case';
import { useNavigate } from 'react-router-dom';

export default function RuntimeStatus({ data }: { data: FraudCardData }) {
  const navigate = useNavigate();
  const dynamic = data.dynamic_analysis;
  const breakdown = data.frs_breakdown;
  const assertions = data.execution_assertions;

  const targetUrl = `/case/${data.sha256}/evidence?section=dynamic`;

  const handleClick = () => {
    navigate(targetUrl);
  };

  if (!dynamic) {
    return (
      <div
        onClick={handleClick}
        className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between hover:border-blue-400 hover:shadow-md transition-all cursor-pointer group"
      >
        <div className="flex items-center justify-between mb-2">
          <CardTitle icon={Activity} title="Sandbox run" tone="sky" info="Whether the app was actually launched on an instrumented Android emulator. Hooks: sensitive actions intercepted. Screenshots: screens captured. Network: connections it made. Coverage: how much of the app was explored. 'Failed' or 'Unavailable' means only static evidence was used." infoAlign="right" />
          <span className="text-[11px] font-bold uppercase tracking-widest px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
            SKIPPED
          </span>
        </div>
        <div className="my-auto py-3 text-center">
          <HelpCircle className="h-8 w-8 text-slate-300 mx-auto mb-2" />
          <p className="text-xs text-slate-500">
            No dynamic sandbox telemetry available for this sample.
          </p>
        </div>
        <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs text-slate-400">
          <span>Static execution only</span>
          <span className="text-blue-600 font-semibold inline-flex items-center gap-0.5 group-hover:translate-x-0.5 transition-transform">
            View evidence <ChevronRight className="h-3.5 w-3.5" />
          </span>
        </div>
      </div>
    );
  }

  const ran = breakdown?.dynamic_ran ?? assertions?.dynamic_ran ?? dynamic.available;
  const conclusive = breakdown?.dynamic_conclusive ?? !assertions?.incomplete_exercise;
  const exclusionReason = breakdown?.dynamic_exclusion_reason;

  const eventsObserved =
    assertions?.threat_events_observed ??
    ((dynamic.api_calls?.length || 0) + (dynamic.network_logs?.length || 0));

  const hookCount =
    (dynamic.api_calls?.length || 0) +
    (dynamic.files_accessed?.length || 0);

  const screenshotCount = dynamic.screenshots?.length || 0;
  const networkCount = dynamic.network_logs?.length || 0;
  const coverageRatio = assertions?.coverage_ratio;

  let badgeColor = 'bg-blue-50 text-blue-700 border-blue-200';
  let badgeText = 'COMPLETED';
  let reasonText = 'Runtime behaviour recorded and incorporated into score.';

  if (!ran) {
    badgeColor = 'bg-red-50 text-red-700 border-red-200';
    badgeText = 'FAILED';
    reasonText = exclusionReason || 'Sandbox instrumentation or launch failed.';
  } else if (!conclusive) {
    badgeColor = 'bg-amber-50 text-amber-700 border-amber-200';
    badgeText = 'INCONCLUSIVE';
    reasonText =
      exclusionReason ||
      (eventsObserved === 0
        ? 'No runtime events observed. Anti-analysis evasion or stalled launch.'
        : 'Execution incomplete. Sample stalled or evasion triggered.');
  } else if (eventsObserved === 0) {
    badgeColor = 'bg-slate-100 text-slate-700 border-slate-200';
    badgeText = '0 EVENTS';
    reasonText = 'Sandbox ran to completion; no hostile behavioural actions triggered.';
  }

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleClick();
        }
      }}
      aria-label="Runtime Sandbox Status. Click to view runtime evidence."
      className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between hover:border-blue-400 hover:shadow-md transition-all cursor-pointer group focus:outline-none focus:ring-2 focus:ring-blue-500"
    >
      <div>
        <div className="flex items-center justify-between mb-3">
          <CardTitle icon={Activity} title="Sandbox run" tone="sky" info="Whether the app was actually launched on an instrumented Android emulator. Hooks: sensitive actions intercepted. Screenshots: screens captured. Network: connections it made. Coverage: how much of the app was explored. 'Failed' or 'Unavailable' means only static evidence was used." infoAlign="right" />
          <span
            className={`text-[10px] font-extrabold uppercase tracking-wider px-2 py-0.5 rounded border ${badgeColor}`}
          >
            {badgeText}
          </span>
        </div>

        <p className="text-xs text-slate-600 leading-relaxed font-medium line-clamp-2 mb-3">
          {reasonText}
        </p>

        {/* Dense Metrics Grid */}
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="p-3 rounded-xl bg-slate-50 flex flex-col gap-1.5 min-w-0">
            <span className="text-slate-500 text-xs font-medium flex items-center gap-1.5 truncate">
              <Activity className="h-3 w-3 text-slate-400" />
              Hooks
            </span>
            <span className="text-lg font-semibold tabular-nums text-slate-900 leading-none">{hookCount}</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-50 flex flex-col gap-1.5 min-w-0">
            <span className="text-slate-500 text-xs font-medium flex items-center gap-1.5 truncate">
              <Camera className="h-3 w-3 text-slate-400" />
              Screenshots
            </span>
            <span className="text-lg font-semibold tabular-nums text-slate-900 leading-none">{screenshotCount}</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-50 flex flex-col gap-1.5 min-w-0">
            <span className="text-slate-500 text-xs font-medium flex items-center gap-1.5 truncate">
              <Network className="h-3 w-3 text-slate-400" />
              Network
            </span>
            <span className="text-lg font-semibold tabular-nums text-slate-900 leading-none">{networkCount}</span>
          </div>

          <div className="p-3 rounded-xl bg-slate-50 flex flex-col gap-1.5 min-w-0">
            <span className="text-slate-500 text-xs font-medium flex items-center gap-1.5 truncate">
              <ShieldCheck className="h-3 w-3 text-slate-400" />
              Coverage
            </span>
            <span className="text-lg font-semibold tabular-nums text-slate-900 leading-none">
              {coverageRatio !== undefined ? `${Math.round(coverageRatio * 100)}%` : 'N/A'}
            </span>
          </div>
        </div>
      </div>

      <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-xs">
        <span className="text-slate-400 font-medium">Events: {eventsObserved}</span>
        <span className="inline-flex items-center gap-1 font-semibold text-blue-600 group-hover:text-blue-700 transition-colors">
          <span>Runtime tab</span>
          <ChevronRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
        </span>
      </div>
    </div>
  );
}
