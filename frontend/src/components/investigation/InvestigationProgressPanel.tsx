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
  const isComplete = step.state === 'complete';
  const isInconclusive = step.state === 'inconclusive';
  const isFailed = step.state === 'failed';

  return (
    <li className="relative flex-1 flex flex-col min-w-0">
      <div className="flex items-center w-full">
        {/* Node Icon Circle */}
        <div
          className={`relative z-10 flex h-8 w-8 items-center justify-center rounded-lg border shrink-0 font-semibold transition-colors ${
            isComplete
              ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
              : isInconclusive
                ? 'border-amber-300 bg-amber-50 text-amber-800'
                : isFailed
                  ? 'border-red-200 bg-red-50 text-red-700'
                  : 'border-slate-200 bg-slate-50 text-slate-400'
          }`}
        >
          {step.icon}
        </div>

        {/* Connector Line */}
        {showConnector && (
          <div className="hidden lg:block flex-1 h-0.5 bg-slate-200 mx-2" aria-hidden />
        )}
      </div>

      {/* Node Content */}
      <div className="mt-2 min-w-0 pr-2">
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] font-mono font-bold text-slate-400">{step.num}</span>
          <span className="text-xs font-semibold text-slate-900 truncate">{step.label}</span>
        </div>
        <p className="text-xs font-mono text-slate-700 font-medium truncate mt-0.5">{step.value}</p>
        {step.support && (
          <p className="text-[11px] text-amber-800/90 leading-tight mt-1 truncate" title={step.support}>
            {step.support}
          </p>
        )}
        <div className="mt-1.5 flex items-center gap-1">
          <span
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
              isComplete
                ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                : isInconclusive
                  ? 'bg-amber-50 text-amber-800 border border-amber-200'
                  : isFailed
                    ? 'bg-red-50 text-red-800 border border-red-200'
                    : 'bg-slate-100 text-slate-500 border border-slate-200'
            }`}
          >
            {isComplete && <Check className="h-3 w-3" aria-hidden />}
            {stepStatusLabel(step.state, step.id)}
          </span>
        </div>
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
      dynamicSupport = 'Runtime behavior not observed';
    }
  } else if (data.dynamic_available || data.dynamic_analysis) {
    dynamicState = 'inconclusive';
    dynamicValue = 'Limited data';
    dynamicSupport = 'Runtime behavior not observed';
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
    <div className="p-4 sm:p-5">
      <div className="flex items-center justify-between gap-2 mb-4">
        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
          INVESTIGATION PIPELINE
        </span>
        <span className="text-xs text-slate-400 font-mono">5 STAGES</span>
      </div>
      <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 lg:gap-0">
        {steps.map((step, i) => (
          <StepNode key={step.id} step={step} showConnector={i < steps.length - 1} />
        ))}
      </ol>
    </div>
  );

  if (embedded) {
    return <SocCard className="overflow-hidden">{inner}</SocCard>;
  }

  return (
    <SocCard className="overflow-hidden">
      {inner}
    </SocCard>
  );
}
