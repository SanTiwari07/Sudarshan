import type { ReactNode } from 'react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import SocCard from '../ui/Card';
import {
  Activity,
  Check,
  FileCode,
  FileText,
  Globe,
  Shield,
} from 'lucide-react';

type StepState = 'complete' | 'inconclusive' | 'failed' | 'pending';

type Step = {
  num: string;
  id: string;
  label: string;
  state: StepState;
  value: string;
  support?: string;
  icon: ReactNode;
  emphasize?: boolean;
};

function stepStatusLabel(state: StepState, stepId: string): string {
  if (state === 'complete') return 'Complete';
  if (state === 'inconclusive') {
    return stepId === 'dynamic' ? 'Inconclusive' : 'Review';
  }
  if (state === 'failed') return 'Failed';
  return 'Pending';
}

function StepNode({ step, showConnector }: { step: Step; showConnector: boolean }) {
  const emphasize = step.emphasize || step.state === 'inconclusive';
  return (
    <li className="flex min-w-0 flex-1 items-start">
      <div className="flex flex-col items-center shrink-0 w-[4.75rem] sm:w-[5.25rem]">
        <span className="text-[10px] font-mono text-slate-400 tabular-nums">{step.num}</span>
        <div className="flex items-center w-full mt-1">
          <span
            className={`flex h-8 w-8 items-center justify-center rounded-lg border shrink-0 ${
              emphasize
                ? 'border-amber-300 bg-amber-50/80 text-amber-800'
                : step.state === 'complete'
                  ? 'border-slate-200 bg-white text-slate-600'
                  : 'border-slate-200 bg-slate-50 text-slate-400'
            }`}
          >
            {step.icon}
          </span>
          {showConnector && (
            <div className="hidden lg:block h-px flex-1 bg-slate-200 ml-2 min-w-[0.5rem]" aria-hidden />
          )}
        </div>
      </div>
      <div className={`min-w-0 flex-1 pb-3 pr-2 ${emphasize ? 'text-amber-950' : ''}`}>
        <p className="text-[12px] font-semibold text-slate-900 leading-tight">{step.label}</p>
        <p className="text-[12px] text-slate-600 mt-0.5 leading-snug">{step.value}</p>
        {step.support && (
          <p className="text-[11px] text-amber-800/90 mt-1 leading-snug max-w-[15rem]">{step.support}</p>
        )}
        <p
          className={`mt-1.5 inline-flex items-center gap-0.5 text-[10px] font-bold uppercase tracking-wide ${
            step.state === 'complete'
              ? 'text-emerald-700'
              : step.state === 'inconclusive'
                ? 'text-amber-700'
                : step.state === 'failed'
                  ? 'text-red-700'
                  : 'text-slate-400'
          }`}
        >
          {step.state === 'complete' && <Check className="h-3 w-3" aria-hidden />}
          {stepStatusLabel(step.state, step.id)}
        </p>
      </div>
    </li>
  );
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

  let dynamicState: StepState = 'pending';
  let dynamicValue = 'Not run';
  let dynamicSupport: string | undefined;
  if (frs?.dynamic_ran) {
    if (frs.dynamic_conclusive) {
      dynamicState = 'complete';
      dynamicValue = 'Behaviours captured';
    } else {
      dynamicState = 'inconclusive';
      dynamicValue = 'Inconclusive';
      dynamicSupport = 'Runtime behavior could not be conclusively observed.';
    }
  } else if (data.dynamic_available || data.dynamic_analysis) {
    dynamicState = 'inconclusive';
    dynamicValue = 'Limited data';
    dynamicSupport = 'Runtime behavior could not be conclusively observed.';
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
      num: '01',
      id: 'static',
      label: 'Static',
      state: staticDone ? 'complete' : 'pending',
      value: staticDone ? `${bundle.counts.staticFindings} signals` : 'Pending',
      icon: <FileCode className="h-4 w-4" aria-hidden />,
    },
    {
      num: '02',
      id: 'dynamic',
      label: 'Dynamic',
      state: dynamicState,
      value: dynamicValue,
      support: dynamicSupport,
      icon: <Activity className="h-4 w-4" aria-hidden />,
      emphasize: dynamicState === 'inconclusive',
    },
    {
      num: '03',
      id: 'threat',
      label: 'Threat Intel',
      state: threatDone ? 'complete' : 'pending',
      value:
        threatDone && data.family_classification !== 'Unknown'
          ? data.family_classification
          : threatDone
            ? 'Correlated'
            : 'Pending',
      icon: <Globe className="h-4 w-4" aria-hidden />,
    },
    {
      num: '04',
      id: 'risk',
      label: 'Risk',
      state: riskDone ? 'complete' : 'pending',
      value: riskDone ? `${data.final_risk_score.toFixed(0)} / 100` : '-',
      icon: <Shield className="h-4 w-4" aria-hidden />,
    },
    {
      num: '05',
      id: 'report',
      label: 'Report',
      state: reportDone ? 'complete' : 'pending',
      value: reportDone ? 'Ready' : 'Partial',
      icon: <FileText className="h-4 w-4" aria-hidden />,
    },
  ];

  const inner = (
    <div className="py-3">
      <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-400 mb-2">
        Investigation pipeline
      </p>
      <ol className="flex flex-col lg:flex-row lg:items-start gap-4 lg:gap-0 border-t border-slate-100 lg:border-0 pt-3">
        {steps.map((step, i) => (
          <StepNode key={step.id} step={step} showConnector={i < steps.length - 1} />
        ))}
      </ol>
    </div>
  );

  if (embedded) {
    return <div className="border-b border-slate-200">{inner}</div>;
  }

  return (
    <SocCard className="shadow-none relative static">
      {inner}
    </SocCard>
  );
}
