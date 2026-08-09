import type { ReactNode } from 'react';

export function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="text-xs font-bold uppercase tracking-wide text-slate-500">{title}</h3>
      {children}
    </section>
  );
}

export function FlowSteps({ steps }: { steps: string[] }) {
  return (
    <ol className="space-y-2 text-xs text-slate-700">
      {steps.map((step, i) => (
        <li key={step} className="flex gap-2">
          <span className="text-slate-400 font-mono shrink-0">{i < steps.length - 1 ? '↓' : '•'}</span>
          <span className={i === steps.length - 1 ? 'font-semibold text-slate-900' : ''}>{step}</span>
        </li>
      ))}
    </ol>
  );
}

export function FrsAxisTransparencyTable({
  rows,
}: {
  rows: import('../../../lib/scoreInfluenceModel').FrsAxisRow[];
}) {
  return (
    <div className="rounded-lg border border-slate-200 overflow-hidden text-xs">
      <table className="w-full">
        <thead className="bg-slate-50 text-slate-500">
          <tr>
            <th className="text-left px-3 py-2 font-semibold">FRS axis</th>
            <th className="text-left px-3 py-2 font-semibold">Status</th>
            <th className="text-right px-3 py-2 font-semibold">Weight</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((r) => (
            <tr key={r.key}>
              <td className="px-3 py-2 text-slate-800">{r.label}</td>
              <td className="px-3 py-2">
                {r.included ? (
                  <span className="text-emerald-800 font-semibold">Included</span>
                ) : (
                  <span className="text-amber-800 font-semibold">
                    Excluded{r.reason ? ` - ${r.reason}` : ''}
                  </span>
                )}
              </td>
              <td className="px-3 py-2 text-right font-mono tabular-nums">
                {r.weightPct != null ? `${r.weightPct.toFixed(1)}%` : '-'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MonoBlock({ children }: { children: string }) {
  return (
    <code className="block text-[11px] font-mono bg-slate-50 border border-slate-200 rounded px-2 py-1.5 break-all text-slate-800">
      {children}
    </code>
  );
}
