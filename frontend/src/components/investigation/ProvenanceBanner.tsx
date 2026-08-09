import type { FraudCardData } from '../../App';

export default function ProvenanceBanner({ data }: { data: FraudCardData }) {
  const frs = data.frs_breakdown;
  if (!frs) return null;

  const excluded = frs.axes_excluded || [];
  const flags: string[] = [];
  if (frs.verdict_floored_for_visibility) flags.push('Verdict floored for visibility');
  if (frs.concealed_payload) flags.push('Concealed payload detected');
  if (frs.dynamic_ran && !frs.dynamic_conclusive) flags.push('Runtime inconclusive - sandbox evidence not used in score');
  if (excluded.length) flags.push(`Axes excluded: ${excluded.join(', ')}`);

  if (!flags.length) return null;

  return (
    <div className="mb-4 px-4 py-2 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900">
      <strong className="uppercase tracking-wide text-[10px]">Scoring notes for analysts</strong>
      <ul className="mt-1 space-y-0.5 list-disc pl-4">
        {flags.map((f) => (
          <li key={f}>{f}</li>
        ))}
      </ul>
    </div>
  );
}
