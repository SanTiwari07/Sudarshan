import { useMemo, useState } from 'react';
import type { InvestigationBundle, InvestigationEvidence } from '../../types/investigation';
import SocCard from '../ui/Card';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { buildFindingExplanation } from '../../lib/findingExplanation';
import {
  isCriticalSeverity,
} from '../../lib/findingAnalystView';
import { ChevronRight } from 'lucide-react';
import EvidenceToolbar, { type EvidenceFilter } from './EvidenceToolbar';
import {
  SeverityIndicator,
  SourceIndicator,
} from './FindingIndicators';

const GENERIC_SUMMARY = 'Contributes to overall fraud risk assessment';

function matchesFilter(row: InvestigationEvidence, filter: EvidenceFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'critical') return isCriticalSeverity(row.severity);
  if (filter === 'static') return row.category === 'static';
  if (filter === 'runtime') return row.category === 'runtime';
  if (filter === 'threat') return row.category === 'intel' || row.category === 'scenario';
  return true;
}

function matchesSearch(row: InvestigationEvidence, q: string): boolean {
  if (!q.trim()) return true;
  const hay = `${row.id} ${row.title} ${row.description || ''}`.toLowerCase();
  return hay.includes(q.trim().toLowerCase());
}

function WhyMattersCell({ evidence }: { evidence: InvestigationEvidence }) {
  const text = buildFindingExplanation(evidence).summary;
  const generic = text === GENERIC_SUMMARY;
  return (
    <p
      className={`text-[12px] leading-relaxed break-words break-all ${
        generic ? 'text-slate-400' : 'text-slate-600'
      }`}
    >
      {text}
    </p>
  );
}

function FindingCell({ row }: { row: InvestigationEvidence }) {
  return (
    <div className="min-w-0 space-y-0.5">
      <p className="font-mono text-[11px] text-slate-400 leading-none">{row.id}</p>
      <p className="text-[13px] font-semibold text-slate-900 leading-snug break-words break-all">{row.title}</p>
    </div>
  );
}

function FindingRowMobile({
  row,
  onOpen,
}: {
  row: InvestigationEvidence;
  onOpen: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="w-full text-left px-4 py-2.5 border-b border-slate-100 hover:bg-slate-50/80 transition-colors group"
    >
      <FindingCell row={row} />
      <div className="mt-1.5 flex flex-wrap items-center gap-3">
        <SeverityIndicator severity={row.severity} />
        <SourceIndicator evidence={row} />
        <span className="text-[12px] font-semibold text-slate-700 tabular-nums">{row.confidence}%</span>
      </div>
      <div className="mt-1">
        <WhyMattersCell evidence={row} />
      </div>
      <ChevronRight
        className="h-4 w-4 text-slate-300 group-hover:text-slate-500 mt-1"
        aria-hidden
      />
    </button>
  );
}

export default function FindingsRegistryTable({
  bundle,
  embedded = false,
}: {
  bundle: InvestigationBundle;
  embedded?: boolean;
}) {
  const { openEvidence } = useInvestigationUI();
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<EvidenceFilter>('all');

  const rows = useMemo(() => {
    return bundle.evidenceRecords.filter(
      (r) => matchesFilter(r, filter) && matchesSearch(r, search),
    );
  }, [bundle.evidenceRecords, filter, search]);

  const openRow = (id: string) => openEvidence(id);

  const tableBlock = (
    <>
      {embedded && (
        <EvidenceToolbar
          total={bundle.evidenceRecords.length}
          search={search}
          onSearchChange={setSearch}
          filter={filter}
          onFilterChange={setFilter}
        />
      )}
      {!embedded && (
        <div className="px-4 py-2.5 border-b border-slate-100 text-xs text-slate-600">
          {bundle.evidenceRecords.length} verified records - evidence-backed findings only.
        </div>
      )}

      <div className="hidden md:block w-full overflow-hidden">
        <table className="w-full table-fixed text-left border-collapse">
          <thead>
            <tr className="bg-slate-50/80 border-b border-slate-200 text-[10px] font-bold uppercase tracking-wider text-slate-500">
              <th className="py-2.5 px-4 w-[38%]">
                FINDING
              </th>
              <th className="py-2.5 px-4 w-[48%]">
                WHY IT MATTERS
              </th>
              <th className="py-2.5 px-4 w-[14%] text-right pr-6 whitespace-nowrap">
                SEVERITY
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.length === 0 ? (
              <tr>
                <td colSpan={3} className="py-8 text-center text-sm text-slate-500">
                  No findings match your search or filters.
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => openRow(row.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      openRow(row.id);
                    }
                  }}
                  tabIndex={0}
                  className="group cursor-pointer hover:bg-slate-50/90 transition-colors"
                >
                  <td className="py-2.5 px-4 align-middle">
                    <FindingCell row={row} />
                  </td>
                  <td className="py-2.5 px-4 align-middle">
                    <WhyMattersCell evidence={row} />
                  </td>
                  <td className="py-2.5 px-4 align-middle text-right pr-6 whitespace-nowrap">
                    <SeverityIndicator severity={row.severity} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="md:hidden border-t border-slate-100 divide-y divide-slate-100">
        {rows.length === 0 ? (
          <p className="py-6 text-center text-sm text-slate-500">No findings match your search or filters.</p>
        ) : (
          rows.map((row) => (
            <FindingRowMobile key={row.id} row={row} onOpen={() => openRow(row.id)} />
          ))
        )}
      </div>
    </>
  );

  if (embedded) {
    return <SocCard className="overflow-hidden">{tableBlock}</SocCard>;
  }

  return <SocCard className="overflow-hidden">{tableBlock}</SocCard>;
}
