import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import SocCard from '../ui/Card';
import { CheckCircle2, Circle, FileText, GitBranch, PlayCircle, Shield, Sparkles } from 'lucide-react';

type StepStatus = 'complete' | 'partial' | 'pending';

type Step = {
  id: string;
  label: string;
  status: StepStatus;
  detail: string;
  icon: React.ReactNode;
};

function statusLabel(status: StepStatus): string {
  if (status === 'complete') return 'Complete';
  if (status === 'partial') return 'Partial';
  return 'Pending';
}

function statusChipClass(status: StepStatus): string {
  if (status === 'complete') return 'bg-emerald-50 text-emerald-800 border-emerald-200';
  if (status === 'partial') return 'bg-amber-50 text-amber-900 border-amber-200';
  return 'bg-slate-50 text-slate-600 border-slate-200';
}

function StepStatusIcon({ status }: { status: StepStatus }) {
  if (status === 'complete') {
    return <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0" aria-hidden />;
  }
  if (status === 'partial') {
    return <Circle className="h-4 w-4 text-amber-500 shrink-0" aria-hidden />;
  }
  return <Circle className="h-4 w-4 text-slate-300 shrink-0" aria-hidden />;
}

export default function InvestigationProgressPanel({
  data,
  bundle,
  embedded = false,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
  embedded?: boolean;
}) {
  const frs = data.frs_breakdown;
  const staticDone =
    bundle.counts.staticFindings > 0 ||
    (frs?.stei ?? 0) > 0 ||
    bundle.evidenceRecords.some((e) => e.category === 'static');

  let dynamicStatus: StepStatus = 'pending';
  let dynamicDetail = 'Not run';
  if (frs?.dynamic_ran) {
    dynamicStatus = frs.dynamic_conclusive ? 'complete' : 'partial';
    dynamicDetail = frs.dynamic_conclusive ? 'Behaviours captured' : 'Inconclusive';
  } else if (data.dynamic_available || data.dynamic_analysis) {
    dynamicStatus = 'partial';
    dynamicDetail = 'Limited data';
  }

  const threatDone =
    data.family_classification !== 'Unknown' ||
    (data.threat_correlation?.ioc_reputation?.length ?? 0) > 0 ||
    (data.threat_correlation?.threat_score ?? 0) > 0 ||
    bundle.evidenceRecords.some((e) => e.category === 'scenario');

  const riskDone = Number.isFinite(data.final_risk_score);

  const reportDone =
    Boolean(data.intelligence_report?.plain_english_narrative) ||
    Boolean(data.executive_view?.plain_english_narrative) ||
    Boolean(data.recommended_action);

  const steps: Step[] = [
    {
      id: 'static',
      label: 'Static',
      status: staticDone ? 'complete' : 'pending',
      detail: staticDone ? `${bundle.counts.staticFindings} signals` : 'Pending',
      icon: <FileText className="h-3.5 w-3.5" />,
    },
    {
      id: 'dynamic',
      label: 'Dynamic',
      status: dynamicStatus,
      detail: dynamicDetail,
      icon: <PlayCircle className="h-3.5 w-3.5" />,
    },
    {
      id: 'threat',
      label: 'Threat intel',
      status: threatDone ? 'complete' : 'pending',
      detail:
        threatDone && data.family_classification !== 'Unknown'
          ? data.family_classification
          : threatDone
            ? 'Correlated'
            : 'Pending',
      icon: <GitBranch className="h-3.5 w-3.5" />,
    },
    {
      id: 'risk',
      label: 'Risk engine',
      status: riskDone ? 'complete' : 'pending',
      detail: riskDone ? `${data.final_risk_score.toFixed(0)}/100` : '—',
      icon: <Shield className="h-3.5 w-3.5" />,
    },
    {
      id: 'report',
      label: 'Report',
      status: reportDone ? 'complete' : 'partial',
      detail: reportDone ? 'Ready' : 'Partial',
      icon: <Sparkles className="h-3.5 w-3.5" />,
    },
  ];

  const inner = (
    <>
      <div
        className={`px-4 sm:px-5 py-3 border-b border-slate-100 ${embedded ? 'bg-slate-50/40' : ''}`}
      >
        <h3 className="text-sm font-semibold text-slate-900">Investigation progress</h3>
        <p className="text-xs text-slate-500 mt-0.5">Pipeline stages for this case</p>
      </div>
      <div className="p-4 sm:px-5">
        <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {steps.map((step) => (
            <li
              key={step.id}
              className="rounded-lg border border-slate-100 bg-slate-50/50 px-3 py-3 min-w-0 static"
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-white border border-slate-200 text-slate-600">
                  {step.icon}
                </span>
                <span className="text-xs font-semibold text-slate-900 truncate">{step.label}</span>
                <StepStatusIcon status={step.status} />
              </div>
              <p className="text-[11px] text-slate-500 mt-2 leading-snug line-clamp-2" title={step.detail}>
                {step.detail}
              </p>
              <span
                className={`inline-flex mt-2 text-[10px] font-medium px-2 py-0.5 rounded-full border ${statusChipClass(step.status)}`}
              >
                {statusLabel(step.status)}
              </span>
            </li>
          ))}
        </ol>
      </div>
    </>
  );

  if (embedded) {
    return <div className="border-b border-slate-100">{inner}</div>;
  }

  return (
    <SocCard className="shadow-none relative static">
      {inner}
    </SocCard>
  );
}
