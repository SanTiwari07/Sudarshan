import { useMemo, useState } from 'react';
import type { InvestigationBundle, InvestigationEvidence } from '../../types/investigation';
import SocCard from '../ui/Card';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { buildFindingExplanation } from '../../lib/findingExplanation';
import { TYPOGRAPHY } from '../../theme/typography';
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
      className={`${TYPOGRAPHY.bodySmall} break-words break-all ${
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
      <p className={`${TYPOGRAPHY.codeSm} text-slate-400 leading-none`}>{row.id}</p>
      <p className={`${TYPOGRAPHY.bodySmall} font-bold text-slate-900 leading-snug break-words break-all`}>{row.title}</p>
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
        <span className={`${TYPOGRAPHY.codeSm} font-bold text-slate-700 tabular-nums`}>{row.confidence}%</span>
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
        <div className={`px-3 py-2 border-b border-slate-200 bg-slate-50/50 ${TYPOGRAPHY.label}`}>
          {bundle.evidenceRecords.length} VERIFIED RECORDS · EVIDENCE-BACKED FINDINGS ONLY
        </div>
      )}

      <div className="hidden md:block w-full overflow-hidden">
        <div className="soc-table-wrap !border-0 rounded-none">
          <table className="soc-table">
            <thead>
              <tr>
                <th className={`py-2 px-3 w-[38%] !bg-slate-50/80 ${TYPOGRAPHY.tableHeader}`}>
                  Finding
                </th>
                <th className={`py-2 px-3 w-[48%] !bg-slate-50/80 ${TYPOGRAPHY.tableHeader}`}>
                  Why It Matters
                </th>
                <th className={`py-2 px-3 w-[14%] text-right pr-4 whitespace-nowrap !bg-slate-50/80 ${TYPOGRAPHY.tableHeader}`}>
                  Severity
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={3} className={`py-8 text-center ${TYPOGRAPHY.caption}`}>
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
                    <td className="py-1.5 px-3 align-middle border-r border-slate-100/50">
                      <FindingCell row={row} />
                    </td>
                    <td className="py-1.5 px-3 align-middle border-r border-slate-100/50">
                      <WhyMattersCell evidence={row} />
                    </td>
                    <td className="py-1.5 px-3 align-middle text-right pr-4 whitespace-nowrap">
                      <SeverityIndicator severity={row.severity} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="md:hidden border-t border-slate-200 divide-y divide-slate-150">
        {rows.length === 0 ? (
          <p className={`py-6 text-center ${TYPOGRAPHY.caption}`}>No findings match your search or filters.</p>
        ) : (
          rows.map((row) => (
            <FindingRowMobile key={row.id} row={row} onOpen={() => openRow(row.id)} />
          ))
        )}
      </div>
    </>
  );

  return <SocCard className="overflow-hidden">{tableBlock}</SocCard>;
}
