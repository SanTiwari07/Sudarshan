import { Activity, AlertCircle, CheckCircle2, HelpCircle } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { Link } from 'react-router-dom';

export default function RuntimeStatus({ data }: { data: FraudCardData }) {
  const dynamic = data.dynamic_analysis;
  const breakdown = data.frs_breakdown;
  const assertions = data.execution_assertions;
  
  if (!dynamic) {
    return (
      <StatusCard 
        title="DYNAMIC ANALYSIS"
        status="SKIPPED"
        icon={HelpCircle}
        iconColor="text-slate-400"
        bgClass="bg-slate-50"
        borderClass="border-slate-200"
        reason="No dynamic analysis data available for this case."
      />
    );
  }

  const ran = breakdown?.dynamic_ran ?? assertions?.dynamic_ran ?? dynamic.available;
  const conclusive = breakdown?.dynamic_conclusive ?? !assertions?.incomplete_exercise;
  const exclusionReason = breakdown?.dynamic_exclusion_reason;
  
  const eventsObserved = assertions?.threat_events_observed ?? 
    ((dynamic.api_calls?.length || 0) + (dynamic.network_logs?.length || 0));
    
  const coverage = assertions?.coverage_ratio;

  if (!ran) {
    return (
      <StatusCard 
        title="DYNAMIC ANALYSIS"
        status="FAILED"
        icon={AlertCircle}
        iconColor="text-red-500"
        bgClass="bg-red-50"
        borderClass="border-red-200"
        reason={exclusionReason || "Instrumentation or environment launch failed."}
      />
    );
  }

  if (!conclusive) {
    return (
      <StatusCard 
        title="DYNAMIC ANALYSIS"
        status="INCONCLUSIVE"
        icon={Activity}
        iconColor="text-amber-500"
        bgClass="bg-amber-50/50"
        borderClass="border-amber-200"
        reason={exclusionReason || "Sandbox launched but execution was incomplete or sample stalled."}
        events={eventsObserved}
        coverage={coverage}
      />
    );
  }

  if (eventsObserved === 0) {
    return (
      <StatusCard 
        title="DYNAMIC ANALYSIS"
        status="COMPLETED"
        icon={CheckCircle2}
        iconColor="text-emerald-500"
        bgClass="bg-emerald-50/50"
        borderClass="border-emerald-200"
        reason="Analysis completed successfully but no fraud behaviour was triggered."
        events={0}
        coverage={coverage}
      />
    );
  }

  return (
    <StatusCard 
      title="DYNAMIC ANALYSIS"
      status="COMPLETED"
      icon={Activity}
      iconColor="text-blue-500"
      bgClass="bg-blue-50/50"
      borderClass="border-blue-200"
      reason="Runtime behaviour recorded and incorporated into score."
      events={eventsObserved}
      coverage={coverage}
      link={`/case/${data.sha256}/evidence`}
    />
  );
}

function StatusCard({
  title, status, icon: Icon, iconColor, bgClass, borderClass, reason, events, coverage, link
}: {
  title: string; status: string; icon: any; iconColor: string; bgClass: string; borderClass: string; reason: string; events?: number; coverage?: number; link?: string;
}) {
  return (
    <div className={`rounded-xl border ${borderClass} ${bgClass} p-5 shadow-sm h-full flex flex-col`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500">
          {title}
        </h2>
        <span className={`text-[11px] font-bold uppercase tracking-widest ${iconColor}`}>
          {status}
        </span>
      </div>

      <div className="flex items-start gap-3 flex-1">
        <div className={`mt-0.5 ${iconColor}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="flex-1">
          <p className="text-sm text-slate-700 leading-relaxed mb-3">
            {reason}
          </p>
          
          {(events !== undefined || coverage !== undefined) && (
            <div className="grid grid-cols-2 gap-4 border-t border-slate-200/60 pt-3 mt-3">
              {events !== undefined && (
                <div>
                  <div className="text-xs text-slate-500 mb-1">Fraud events</div>
                  <div className="text-sm font-semibold text-slate-900">{events}</div>
                </div>
              )}
              {coverage !== undefined && (
                <div>
                  <div className="text-xs text-slate-500 mb-1">Coverage</div>
                  <div className="text-sm font-semibold text-slate-900">{(coverage * 100).toFixed(0)}%</div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      {link && (
        <div className="mt-4 pt-3 border-t border-slate-200/60">
          <Link to={link} className="text-xs font-medium text-blue-600 hover:text-blue-800 transition-colors inline-flex items-center">
            View runtime details
          </Link>
        </div>
      )}
    </div>
  );
}
