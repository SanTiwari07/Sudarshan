import { HelpCircle } from 'lucide-react';
import type { TechnicalFindingId } from '../../lib/technicalFindings';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

export default function ExplainFindingButton({
  findingId,
  className = '',
}: {
  findingId: TechnicalFindingId;
  className?: string;
}) {
  const { openFindingExplanation } = useInvestigationUI();

  return (
    <button
      type="button"
      className={`inline-flex shrink-0 rounded-full p-0.5 text-slate-400 hover:text-blue-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 ${className}`}
      aria-label="Explain this finding"
      title="Explain this finding"
      onClick={(e) => {
        e.stopPropagation();
        e.preventDefault();
        openFindingExplanation(findingId);
      }}
    >
      <HelpCircle className="h-3.5 w-3.5" />
    </button>
  );
}
