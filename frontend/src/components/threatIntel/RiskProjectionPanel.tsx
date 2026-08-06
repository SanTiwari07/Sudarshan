import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { TrendingUp } from 'lucide-react';

type Props = {
  current: number;
  projected: number;
  maximum: number;
  explanation: string;
};

export default function RiskProjectionPanel({ current, projected, maximum, explanation }: Props) {
  return (
    <SocCard>
      <SectionHeader icon={<TrendingUp className="h-4 w-4" />} title="Risk projection" subtitle="Current vs runtime-confirmed potential" />
      <div className="p-4 flex flex-wrap items-center justify-center gap-6">
        <ScoreBlock label="Current risk" value={current} />
        <span className="text-2xl text-slate-400">→</span>
        <ScoreBlock label="Projected runtime risk" value={projected} highlight={projected > current} />
        <span className="text-slate-300 hidden sm:inline">|</span>
        <ScoreBlock label="Potential maximum" value={maximum} />
      </div>
      <p className="px-4 pb-4 text-[11px] text-slate-600 leading-relaxed border-t border-slate-100 pt-3 mx-4 mb-4 bg-slate-50 rounded-lg">
        {explanation}
      </p>
    </SocCard>
  );
}

function ScoreBlock({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className="text-center">
      <div className="text-[10px] uppercase tracking-wide text-slate-500 font-semibold">{label}</div>
      <div
        className={`text-3xl font-black tabular-nums mt-1 ${highlight ? 'text-orange-600' : 'text-blue-800'}`}
      >
        {Math.round(value)}
      </div>
    </div>
  );
}
