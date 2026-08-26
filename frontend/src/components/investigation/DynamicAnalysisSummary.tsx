import { Link } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import { computeWeightedContribution, getAxesUsed } from '../../lib/scoreLedger';
import {
  resolveRuntimeDynamicStatus,
  runtimeStatusExplanation,
  runtimeStatusHeadline,
} from '../../lib/investigationRuntime';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import HelpTerm from './HelpTerm';
import { Activity, Terminal } from 'lucide-react';
import { useCaseLinks } from '../../hooks/useCaseLinks';

export default function DynamicAnalysisSummary({ data }: { data: FraudCardData }) {
  const { openInfluenceDetail } = useInvestigationUI();
  const links = useCaseLinks();
  const status = resolveRuntimeDynamicStatus(data);
  const frs = data.frs_breakdown;
  const dyn =
    (data.dynamic_result && typeof data.dynamic_result === 'object' && !Array.isArray(data.dynamic_result)
      ? data.dynamic_result
      : data.dynamic_analysis) || {};

  const bfci =
    typeof (dyn as { bfci?: number }).bfci === 'number'
      ? (dyn as { bfci: number }).bfci
      : frs?.dynamic ?? null;

  const axesUsed = getAxesUsed(data);
  const included = Boolean(frs?.dynamic_conclusive && !frs.axes_excluded?.includes('dynamic'));
  const contribution = included && bfci != null ? computeWeightedContribution('dynamic', bfci, axesUsed) : null;

  const exclusionReason =
    !included && frs?.dynamic_ran
      ? 'The risk engine intentionally excludes inconclusive runtime evidence rather than treating missing evidence as zero.'
      : null;

  return (
    <SocCard>
      <SectionHeader
        icon={<Activity className="h-4 w-4" />}
        title="Dynamic analysis"
        subtitle="Runtime behaviour observed in the isolated Android sandbox"
      />
      <div className="p-3.5 space-y-3.5">
        <div>
          <p className="text-xs text-slate-750 leading-relaxed font-medium">
            {status === 'INCONCLUSIVE'
              ? 'Runtime behaviour could not be confirmed.'
              : runtimeStatusExplanation(status)}
          </p>
        </div>

        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="rounded-md border border-slate-200 bg-white p-2.5">
            <dt className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Status</dt>
            <dd className="font-mono font-bold text-slate-900 mt-1 text-xs">{runtimeStatusHeadline(status)}</dd>
          </div>
          {bfci != null && frs?.dynamic_ran && (
            <div className="rounded-md border border-slate-200 bg-white p-2.5">
              <dt className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                <HelpTerm term="BFCI">Observed runtime score</HelpTerm>
              </dt>
              <dd className="font-mono font-bold text-slate-900 mt-1">{bfci.toFixed(1)} / 100</dd>
            </div>
          )}
          <div className="rounded-md border border-slate-200 bg-white p-2.5 sm:col-span-2">
            <dt className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Contribution to final FRS</dt>
            <dd className="font-semibold text-slate-900 mt-1 text-xs">
              {included && contribution != null ? `${contribution.toFixed(2)} points` : 'Not included'}
            </dd>
            {exclusionReason && (
              <p className="text-[13px] text-amber-850 mt-1.5 leading-normal">
                <HelpTerm term="Axis Excluded">Why excluded?</HelpTerm> {exclusionReason}
              </p>
            )}
          </div>
        </dl>

        <div className="flex flex-wrap gap-2">
          <a
            href="#runtime-screenshots"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-blue-800 bg-blue-50 border border-blue-200/50 rounded hover:bg-blue-100/50 transition-all"
          >
            View runtime evidence
          </a>
          <button
            type="button"
            onClick={() => openInfluenceDetail('dynamic')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-slate-700 bg-white border border-slate-250 rounded hover:border-slate-350 hover:bg-slate-50 transition-all"
          >
            View scoring details
          </button>
          <Link
            to={links.intel}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-slate-500 hover:text-blue-700 transition-colors"
          >
            Threat intelligence →
          </Link>
        </div>

        {status === 'RUNNING' && (
          <p className="text-[13px] text-slate-500 flex items-center gap-1.5 font-mono">
            <Terminal className="h-3.5 w-3.5 text-blue-600 animate-pulse" />
            Sandbox still running - refresh to update runtime evidence.
          </p>
        )}
      </div>
    </SocCard>
  );
}
