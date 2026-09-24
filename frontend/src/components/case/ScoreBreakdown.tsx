import type { FraudCardData } from '../../types/case';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import type { ScoreInfluenceAxis } from '../../lib/scoreInfluenceModel';
import { Calculator, ChevronRight, Activity, Cpu, Globe2, Building2 } from 'lucide-react';

export default function ScoreBreakdown({ data }: { data: FraudCardData }) {
  const { openLedger, openInfluenceDetail } = useInvestigationUI();
  const breakdown = data.frs_breakdown;

  const rawAxes: {
    key: string;
    axisKey: ScoreInfluenceAxis;
    label: string;
    icon: typeof Activity;
    value: number;
    color: string;
  }[] = [
    {
      key: 'stei',
      axisKey: 'static',
      label: 'Static Threat',
      icon: Cpu,
      value: breakdown?.stei ?? 0,
      color: 'bg-blue-600',
    },
    {
      key: 'dynamic',
      axisKey: 'dynamic',
      label: 'Dynamic Behaviour',
      icon: Activity,
      value: breakdown?.dynamic ?? 0,
      color: 'bg-indigo-600',
    },
    {
      key: 'correlation',
      axisKey: 'threat_intel',
      label: 'Threat Intelligence',
      icon: Globe2,
      value: breakdown?.correlation ?? 0,
      color: 'bg-amber-600',
    },
    {
      key: 'banking_impact',
      axisKey: 'vide',
      label: 'Banking Impact',
      icon: Building2,
      value: breakdown?.banking_impact ?? 0,
      color: 'bg-red-600',
    },
  ];

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500">
          SCORE INFLUENCE BREAKDOWN
        </h2>
        <button
          type="button"
          onClick={() => openLedger('full')}
          className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800 transition-colors cursor-pointer"
        >
          <Calculator className="h-3.5 w-3.5" />
          <span>Ledger</span>
          <ChevronRight className="h-3 w-3" />
        </button>
      </div>

      <div className="space-y-3 flex-1 flex flex-col justify-center">
        {rawAxes.map((axis) => {
          const Icon = axis.icon;
          const displayVal = axis.value > 0 ? `+${axis.value.toFixed(1)}` : '0.0';
          const pct = Math.min(100, Math.max(4, (axis.value / 100) * 100));

          return (
            <button
              key={axis.key}
              type="button"
              onClick={() => openInfluenceDetail(axis.axisKey)}
              className="w-full text-left p-2.5 rounded-xl border border-slate-100 bg-slate-50/50 hover:bg-slate-100 hover:border-slate-300 transition-all cursor-pointer group shadow-2xs focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <div className="flex items-center justify-between text-xs mb-1.5">
                <div className="flex items-center gap-2">
                  <Icon className="h-3.5 w-3.5 text-slate-500 group-hover:text-blue-600 transition-colors" />
                  <span className="font-semibold text-slate-800 group-hover:text-slate-900">
                    {axis.label}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="font-mono text-xs font-bold text-slate-900">{displayVal}</span>
                  <ChevronRight className="h-3.5 w-3.5 text-slate-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all" />
                </div>
              </div>
              <div className="h-1.5 w-full bg-slate-200/80 rounded-full overflow-hidden">
                <div
                  className={`h-full ${axis.color} rounded-full transition-all duration-300`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </button>
          );
        })}
      </div>

      <div className="mt-3 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
        <span>Click any axis to inspect contributing findings</span>
        <span>Deterministic weights</span>
      </div>
    </div>
  );
}
