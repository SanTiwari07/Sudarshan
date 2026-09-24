import type { FraudCardData } from '../../types/case';

export default function ScoreBreakdown({ data }: { data: FraudCardData }) {
  const breakdown = data.frs_breakdown;
  if (!breakdown) return null;

  const axes = [
    { key: 'stei', label: 'Static Threat', value: breakdown.stei },
    { key: 'dynamic', label: 'Dynamic Behaviour', value: breakdown.dynamic },
    { key: 'correlation', label: 'Threat Intelligence', value: breakdown.correlation },
    { key: 'banking_impact', label: 'Banking Impact', value: breakdown.banking_impact },
  ].filter(a => a.value !== undefined && a.value > 0);

  if (axes.length === 0) return null;

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500">
          WHY THIS SCORE MATTERS
        </h2>
        <button className="text-xs font-medium text-blue-600 hover:text-blue-800 transition-colors">
          How this was calculated
        </button>
      </div>

      <div className="flex-1 flex flex-col justify-center gap-4">
        {axes.map((axis) => (
          <div key={axis.key}>
            <div className="flex items-center justify-between text-sm mb-1.5">
              <span className="font-medium text-slate-700">{axis.label}</span>
              <span className="font-mono text-slate-900">+{axis.value.toFixed(1)}</span>
            </div>
            <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
              <div 
                className="h-full bg-slate-400 rounded-full" 
                style={{ width: `${Math.min(100, (axis.value / 100) * 100)}%` }} 
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
