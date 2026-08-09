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

export default function DynamicAnalysisSummary({ data }: { data: FraudCardData }) {
  const { openInfluenceDetail } = useInvestigationUI();
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
      <div className="p-4 sm:p-5 space-y-4">
        <div>
          <p className="text-sm text-slate-700 leading-relaxed">
            {status === 'INCONCLUSIVE'
              ? 'Runtime behaviour could not be confirmed.'
              : runtimeStatusExplanation(status)}
          </p>
        </div>

        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3">
            <dt className="text-[10px] font-bold uppercase text-slate-500">Status</dt>
            <dd className="font-mono font-bold text-slate-900 mt-1">{runtimeStatusHeadline(status)}</dd>
          </div>
          {bfci != null && frs?.dynamic_ran && (
            <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3">
              <dt className="text-[10px] font-bold uppercase text-slate-500">
                <HelpTerm term="BFCI">Observed runtime score</HelpTerm>
              </dt>
              <dd className="font-mono font-bold text-slate-900 mt-1">{bfci.toFixed(1)} / 100</dd>
            </div>
          )}
          <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 sm:col-span-2">
            <dt className="text-[10px] font-bold uppercase text-slate-500">Contribution to final FRS</dt>
            <dd className="font-semibold text-slate-900 mt-1">
              {included && contribution != null ? `${contribution.toFixed(2)} points` : 'Not included'}
            </dd>
            {exclusionReason && (
              <p className="text-xs text-amber-800 mt-2 leading-relaxed">
                <HelpTerm term="Axis Excluded">Why excluded?</HelpTerm> {exclusionReason}
              </p>
            )}
          </div>
        </dl>

        <div className="flex flex-wrap gap-2">
          <a
            href="#runtime-screenshots"
            className="inline-flex items-center gap-1 px-3 py-2 text-xs font-semibold text-blue-800 bg-blue-50 border border-blue-100 rounded-lg hover:bg-blue-100"
          >
            View runtime evidence
          </a>
          <button
            type="button"
            onClick={() => openInfluenceDetail('runtime')}
            className="inline-flex items-center gap-1 px-3 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:border-blue-300"
          >
            View scoring details
          </button>
          <Link
            to="/threat-intel"
            className="inline-flex items-center gap-1 px-3 py-2 text-xs font-semibold text-slate-600 hover:text-blue-700"
          >
            Threat intelligence →
          </Link>
        </div>

        {status === 'RUNNING' && (
          <p className="text-xs text-slate-500 flex items-center gap-1">
            <Terminal className="h-3.5 w-3.5" />
            Sandbox still running - refresh to update runtime evidence.
          </p>
        )}
      </div>
    </SocCard>
  );
}
