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
  ConfidenceIndicator,
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
      className={`text-[12px] leading-relaxed break-words ${
        generic ? 'text-slate-400' : 'text-slate-600'
      }`}
    >
      {text}
    </p>
  );
}

function FindingCell({ row }: { row: InvestigationEvidence }) {
  return (
    <div className="min-w-0 space-y-1">
      <p className="font-mono text-[11px] text-slate-400 leading-none">{row.id}</p>
      <p className="text-[13px] font-medium text-slate-900 leading-snug">{row.title}</p>
      {row.description?.trim() && (
        <p className="text-[12px] text-slate-500 leading-relaxed line-clamp-2">{row.description.trim()}</p>
      )}
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
      className="w-full text-left px-4 py-3 border-b border-slate-100 hover:bg-slate-50/80 transition-colors group"
    >
      <FindingCell row={row} />
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <SeverityIndicator severity={row.severity} />
        <SourceIndicator evidence={row} />
        <span className="text-[12px] font-semibold text-slate-700 tabular-nums">{row.confidence}%</span>
      </div>
      <WhyMattersCell evidence={row} />
      <ChevronRight
        className="h-4 w-4 text-slate-300 group-hover:text-slate-500 mt-2"
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
        <div className="px-4 py-3 border-b border-slate-100 text-xs text-slate-600">
          {bundle.evidenceRecords.length} verified records — evidence-backed findings only.
        </div>
      )}

      <div className="hidden md:block">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-200">
              <th className="py-2.5 pl-0 pr-4 text-[11px] font-bold uppercase tracking-wide text-slate-400 w-[38%]">
                Finding
              </th>
              <th className="py-2.5 px-4 text-[11px] font-bold uppercase tracking-wide text-slate-400 w-[24%]">
                Why it matters
              </th>
              <th className="py-2.5 px-3 text-[11px] font-bold uppercase tracking-wide text-slate-400">
                Severity
              </th>
              <th className="py-2.5 px-3 text-[11px] font-bold uppercase tracking-wide text-slate-400">
                Source
              </th>
              <th className="py-2.5 px-3 text-[11px] font-bold uppercase tracking-wide text-slate-400 text-right">
                Confidence
              </th>
              <th className="py-2.5 w-8" aria-hidden />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-sm text-slate-500">
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
                  className="group cursor-pointer border-b border-slate-100 hover:bg-slate-50/90 transition-colors"
                >
                  <td className="py-3 pr-4 align-top">
                    <FindingCell row={row} />
                  </td>
                  <td className="py-3 px-4 align-top">
                    <WhyMattersCell evidence={row} />
                  </td>
                  <td className="py-3 px-3 align-top">
                    <SeverityIndicator severity={row.severity} />
                  </td>
                  <td className="py-3 px-3 align-top">
                    <SourceIndicator evidence={row} />
                  </td>
                  <td className="py-3 px-3 align-top">
                    <ConfidenceIndicator confidence={row.confidence} />
                  </td>
                  <td className="py-3 align-top">
                    <ChevronRight
                      className="h-4 w-4 text-slate-200 group-hover:text-slate-500 transition-colors"
                      aria-hidden
                    />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="md:hidden border-t border-slate-100">
        {rows.length === 0 ? (
          <p className="py-8 text-center text-sm text-slate-500">No findings match your search or filters.</p>
        ) : (
          rows.map((row) => (
            <FindingRowMobile key={row.id} row={row} onOpen={() => openRow(row.id)} />
          ))
        )}
      </div>
    </>
  );

  if (embedded) {
    return <div className="pb-2">{tableBlock}</div>;
  }

  return <SocCard>{tableBlock}</SocCard>;
}
