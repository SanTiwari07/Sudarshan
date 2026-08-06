import { Fragment, useMemo, useState } from 'react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle, InvestigationEvidence } from '../../types/investigation';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import {
  affectedBankingBehaviour,
  evidencePlainText,
  formatEvidenceSource,
  formatSeverityLabel,
  fraudImpact,
  recommendedAnalystAction,
  technicalExplanation,
  whyThisMatters,
} from '../../lib/findingAnalystView';
import { ChevronDown, ChevronRight, Info, List } from 'lucide-react';

const EVIDENCE_GROUPS: {
  id: string;
  title: string;
  match: (r: InvestigationEvidence) => boolean;
}[] = [
  { id: 'static', title: 'Static analysis', match: (r) => r.category === 'static' },
  { id: 'runtime', title: 'Runtime analysis', match: (r) => r.category === 'runtime' },
  {
    id: 'threat',
    title: 'Threat intelligence',
    match: (r) => r.category === 'intel' || r.category === 'scenario',
  },
  { id: 'risk', title: 'Risk engine', match: (r) => r.category === 'score' },
  {
    id: 'other',
    title: 'Report & other',
    match: (r) => !['static', 'runtime', 'intel', 'scenario', 'score'].includes(r.category),
  },
];

function ExpandedFindingDetail({
  evidence,
  data,
}: {
  evidence: InvestigationEvidence;
  data: FraudCardData;
}) {
  const mitre =
    evidence.mitreId
      ? `${evidence.mitreId}${evidence.mitreName ? ` — ${evidence.mitreName}` : ''}`
      : 'Not mapped to a specific MITRE technique for this row';

  const sections: { label: string; body: string }[] = [
    { label: 'Evidence', body: evidencePlainText(evidence) },
    { label: 'Technical explanation', body: technicalExplanation(evidence) },
    { label: 'Fraud impact', body: fraudImpact(evidence, data) },
    { label: 'MITRE technique', body: mitre },
    { label: 'Affected banking behaviour', body: affectedBankingBehaviour(evidence, data) },
    { label: 'Recommended analyst action', body: recommendedAnalystAction(evidence, data) },
  ];

  return (
    <div className="px-4 py-4 bg-slate-50/90 border-t border-slate-200 space-y-3">
      {sections.map((s) => (
        <div key={s.label}>
          <div className="text-xs font-medium text-slate-500">{s.label}</div>
          <p className="text-sm text-slate-700 mt-1 leading-relaxed break-words">{s.body}</p>
        </div>
      ))}
    </div>
  );
}

function FindingRows({
  rows,
  data,
  expandedId,
  onToggle,
}: {
  rows: InvestigationEvidence[];
  data: FraudCardData;
  expandedId: string | null;
  onToggle: (id: string) => void;
}) {
  return (
    <>
      {rows.map((row) => {
        const open = expandedId === row.id;
        return (
          <Fragment key={row.id}>
            <tr
              className="cursor-pointer"
              onClick={() => onToggle(row.id)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onToggle(row.id);
                }
              }}
              tabIndex={0}
            >
              <td className="text-slate-400 w-10">
                {open ? <ChevronDown className="h-4 w-4" aria-hidden /> : <ChevronRight className="h-4 w-4" aria-hidden />}
              </td>
              <td className="font-mono text-xs text-slate-600 whitespace-nowrap">{row.id}</td>
              <td className="font-medium text-slate-900 min-w-[10rem] max-w-[16rem] break-words">{row.title}</td>
              <td className="text-slate-600 min-w-[10rem] max-w-[18rem] break-words leading-relaxed">{whyThisMatters(row)}</td>
              <td>
                <span
                  className={
                    formatSeverityLabel(row.severity) === 'Critical'
                      ? 'text-red-700 font-semibold'
                      : 'text-slate-700'
                  }
                >
                  {formatSeverityLabel(row.severity)}
                </span>
              </td>
              <td className="text-slate-600 whitespace-nowrap">{formatEvidenceSource(row)}</td>
              <td className="text-right tabular-nums text-slate-700 sticky right-0 bg-inherit shadow-[-8px_0_12px_-8px_rgba(15,23,42,0.12)]">
                {row.confidence}%
              </td>
            </tr>
            {open && (
              <tr>
                <td colSpan={7} className="p-0">
                  <ExpandedFindingDetail evidence={row} data={data} />
                </td>
              </tr>
            )}
          </Fragment>
        );
      })}
    </>
  );
}

export default function FindingsRegistryTable({
  bundle,
  data,
  embedded = false,
}: {
  bundle: InvestigationBundle;
  data: FraudCardData;
  embedded?: boolean;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const toggle = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const grouped = useMemo(() => {
    const records = bundle.evidenceRecords;
    const assigned = new Set<string>();
    const groups = EVIDENCE_GROUPS.map((g) => {
      const rows = records.filter((r) => {
        if (assigned.has(r.id)) return false;
        if (!g.match(r)) return false;
        assigned.add(r.id);
        return true;
      });
      return { ...g, rows };
    }).filter((g) => g.rows.length > 0);
    const leftover = records.filter((r) => !assigned.has(r.id));
    if (leftover.length > 0) {
      groups.push({ id: 'leftover', title: 'Additional evidence', match: () => true, rows: leftover });
    }
    return groups;
  }, [bundle.evidenceRecords]);

  const tableBlock = (
    <>
      {!embedded && (
        <>
          <div className="px-4 py-3 border-b border-slate-100 bg-slate-50/50 flex items-start gap-2">
            <Info className="h-4 w-4 text-slate-500 shrink-0 mt-0.5" aria-hidden />
            <p className="text-xs text-slate-600 leading-relaxed">
              Complete evidence log for this investigation. Every row is backed by static analysis, runtime analysis,
              or threat intelligence — not AI-generated text.
            </p>
          </div>
          <SectionHeader
            icon={<List className="h-4 w-4" />}
            title="Findings registry"
            subtitle={`${bundle.evidenceRecords.length} verified records`}
          />
        </>
      )}
      {embedded && (
        <div className="px-4 sm:px-5 py-3 border-b border-slate-100 flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-slate-900">All findings</h3>
          <span className="text-xs text-slate-500 tabular-nums">{bundle.evidenceRecords.length} records</span>
        </div>
      )}
      <div className="soc-table-wrap max-h-[32rem]">
        <table className="soc-table">
          <thead>
            <tr>
              <th className="w-10" aria-label="Expand" />
              <th>ID</th>
              <th>Finding</th>
              <th>Why this matters</th>
              <th>Severity</th>
              <th>Source</th>
              <th className="text-right sticky right-0 bg-slate-50/95">Confidence</th>
            </tr>
          </thead>
          <tbody>
            {grouped.map((group, gi) => (
              <Fragment key={group.id}>
                <tr className="!bg-slate-100/80 hover:!bg-slate-100/80">
                  <td colSpan={7} className="!py-2 !px-4 text-xs font-semibold text-slate-600 tracking-tight">
                    {group.title}
                    <span className="ml-2 font-normal text-slate-500 tabular-nums">({group.rows.length})</span>
                  </td>
                </tr>
                <FindingRows rows={group.rows} data={data} expandedId={expandedId} onToggle={toggle} />
                {gi < grouped.length - 1 && (
                  <tr aria-hidden className="!border-0">
                    <td colSpan={7} className="!p-0 h-2" />
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );

  if (embedded) {
    return <div className="border-b border-slate-100">{tableBlock}</div>;
  }

  return <SocCard>{tableBlock}</SocCard>;
}
