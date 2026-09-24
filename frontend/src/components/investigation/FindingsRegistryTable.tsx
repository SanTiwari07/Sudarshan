import { useMemo, useState } from 'react';
import type { InvestigationBundle, InvestigationEvidence } from '../../types/investigation';
import SocCard from '../ui/Card';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { buildFindingExplanation } from '../../lib/findingExplanation';
import { TYPOGRAPHY } from '../../theme/typography';
import { ChevronRight } from 'lucide-react';
import EvidenceToolbar, {
  type SeverityFilter,
  type SourceFilter,
} from './EvidenceToolbar';
import { SeverityIndicator, SourceIndicator } from './FindingIndicators';

const GENERIC_SUMMARY = 'Contributes to overall fraud risk assessment';

function matchesSeverity(row: InvestigationEvidence, filter: SeverityFilter): boolean {
  if (filter === 'all') return true;
  return row.severity.toLowerCase() === filter.toLowerCase();
}

function matchesSource(row: InvestigationEvidence, filter: SourceFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'static') return row.category === 'static' || row.sourceEngine.includes('static');
  if (filter === 'dynamic') return row.category === 'runtime' || row.sourceEngine.includes('dynamic') || row.sourceEngine.includes('frida');
  if (filter === 'intel') return row.category === 'intel' || row.category === 'scenario' || row.sourceEngine.includes('intel');
  if (filter === 'vide') return (row.category as string) === 'visual' || row.sourceEngine.toLowerCase().includes('vide');
  return true;
}

function matchesSearch(row: InvestigationEvidence, q: string): boolean {
  if (!q.trim()) return true;
  const hay = `${row.id} ${row.title} ${row.description || ''} ${row.sourceEngine} ${row.mitreId || ''}`.toLowerCase();
  return hay.includes(q.trim().toLowerCase());
}

function WhyMattersCell({ evidence }: { evidence: InvestigationEvidence }) {
  const text = buildFindingExplanation(evidence).summary;
  const generic = text === GENERIC_SUMMARY;
  return (
    <p
      className={`${TYPOGRAPHY.bodySmall} break-words break-all ${
        generic ? 'text-slate-500' : 'text-slate-600'
      }`}
    >
      {text}
    </p>
  );
}

function FindingCell({ row }: { row: InvestigationEvidence }) {
  return (
    <div className="min-w-0 space-y-0.5">
      <div className="flex items-center gap-1.5">
        <span className="font-mono text-[11px] font-bold text-slate-500">{row.id}</span>
        {row.mitreId && (
          <span className="font-mono text-[10px] text-slate-400 bg-slate-100 px-1 py-0.2 rounded border border-slate-200">
            {row.mitreId}
          </span>
        )}
      </div>
      <p className={`${TYPOGRAPHY.bodySmall} font-semibold text-slate-900 leading-snug break-words break-all`}>
        {row.title}
      </p>
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
      className="w-full text-left px-4 py-3 border-b border-slate-100 hover:bg-slate-50/80 transition-colors group cursor-pointer"
    >
      <FindingCell row={row} />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <SeverityIndicator severity={row.severity} />
        <SourceIndicator evidence={row} />
        {row.confidence != null && (
          <span className={`${TYPOGRAPHY.codeSm} font-semibold text-slate-700 tabular-nums`}>
            {row.confidence}%
          </span>
        )}
      </div>
      <div className="mt-1.5">
        <WhyMattersCell evidence={row} />
      </div>
      <div className="mt-2 flex items-center justify-end text-xs text-blue-600 font-semibold gap-0.5">
        <span>Inspect evidence</span>
        <ChevronRight className="h-3.5 w-3.5" />
      </div>
    </button>
  );
}

export default function FindingsRegistryTable({
  bundle,
  embedded: _embedded = false,
}: {
  bundle: InvestigationBundle;
  embedded?: boolean;
}) {
  const { openEvidence } = useInvestigationUI();
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<SeverityFilter>('all');
  const [srcFilter, setSrcFilter] = useState<SourceFilter>('all');

  const rows = useMemo(() => {
    return bundle.evidenceRecords.filter(
      (r) =>
        matchesSeverity(r, sevFilter) &&
        matchesSource(r, srcFilter) &&
        matchesSearch(r, search),
    );
  }, [bundle.evidenceRecords, sevFilter, srcFilter, search]);

  const openRow = (id: string) => openEvidence(id);

  const tableBlock = (
    <>
      <EvidenceToolbar
        search={search}
        onSearchChange={setSearch}
        severityFilter={sevFilter}
        onSeverityChange={setSevFilter}
        sourceFilter={srcFilter}
        onSourceChange={setSrcFilter}
      />

      <div className={`px-4 py-2 border-b border-slate-200 bg-slate-50/70 flex items-center justify-between text-xs`}>
        <span className="font-semibold text-slate-700">
          Showing {rows.length} of {bundle.evidenceRecords.length} verified records
        </span>
        <span className="text-slate-400 font-mono text-[11px]">
          EVIDENCE-BACKED FINDINGS ONLY
        </span>
      </div>

      <div className="hidden md:block w-full overflow-hidden">
        <div className="soc-table-wrap !border-0 rounded-none">
          <table className="soc-table w-full">
            <thead>
              <tr>
                <th className={`py-2 px-3 w-[34%] !bg-slate-50/80 ${TYPOGRAPHY.tableHeader}`}>
                  Finding & ID
                </th>
                <th className={`py-2 px-3 w-[16%] !bg-slate-50/80 ${TYPOGRAPHY.tableHeader}`}>
                  Source
                </th>
                <th className={`py-2 px-3 w-[38%] !bg-slate-50/80 ${TYPOGRAPHY.tableHeader}`}>
                  Why It Matters
                </th>
                <th className={`py-2 px-3 w-[12%] text-right pr-4 whitespace-nowrap !bg-slate-50/80 ${TYPOGRAPHY.tableHeader}`}>
                  Severity
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-12 text-center text-slate-500 text-sm">
                    No evidence records match your search query or selected filters.
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
                    className="group cursor-pointer hover:bg-blue-50/40 transition-colors focus:outline-none focus:bg-blue-50/60"
                  >
                    <td className="py-2 px-3 align-top border-r border-slate-100/60">
                      <FindingCell row={row} />
                    </td>
                    <td className="py-2 px-3 align-top border-r border-slate-100/60">
                      <SourceIndicator evidence={row} />
                    </td>
                    <td className="py-2 px-3 align-top border-r border-slate-100/60">
                      <WhyMattersCell evidence={row} />
                    </td>
                    <td className="py-2 px-3 align-top text-right pr-4 whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <SeverityIndicator severity={row.severity} />
                        <ChevronRight className="h-3.5 w-3.5 text-slate-300 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all" />
                      </div>
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
          <p className="py-8 text-center text-slate-500 text-xs">No findings match your search or filters.</p>
        ) : (
          rows.map((row) => (
            <FindingRowMobile key={row.id} row={row} onOpen={() => openRow(row.id)} />
          ))
        )}
      </div>
    </>
  );

  return <SocCard className="overflow-hidden shadow-xs border-slate-200">{tableBlock}</SocCard>;
}
