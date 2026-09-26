import CardTitle from '../ui/CardTitle';
import type { FraudCardData } from '../../types/case';
import { useAnalysis } from '../../context/AnalysisContext';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { ShieldAlert, ArrowRight, FileSearch } from 'lucide-react';
import { SeverityIndicator } from '../investigation/FindingIndicators';

export default function KeyFindings({ data: _data }: { data: FraudCardData }) {
  const { investigationBundle } = useAnalysis();
  const { openEvidence } = useInvestigationUI();
  const records = investigationBundle?.evidenceRecords || [];

  // Sort by severity (critical > high > medium > low) and pick top 5
  const topFindings = [...records]
    .sort((a, b) => {
      const sevMap: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (sevMap[b.severity] || 0) - (sevMap[a.severity] || 0);
    })
    .slice(0, 5);

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-4">
          <CardTitle icon={ShieldAlert} title="Key findings" tone="red" info="The most serious individual problems found in the app, ranked by severity. Each one links to the exact evidence that proves it." infoAlign="left" />
          <span className="text-xs font-medium text-slate-600 bg-slate-100 px-2.5 py-0.5 rounded-full whitespace-nowrap">
            Top {topFindings.length} Prioritized
          </span>
        </div>

        <div className="space-y-2">
          {topFindings.length > 0 ? (
            topFindings.map((finding) => (
              <button
                key={finding.id}
                type="button"
                onClick={() => openEvidence(finding.id)}
                className="w-full text-left p-2.5 rounded-xl border border-slate-100 bg-slate-50/60 hover:bg-slate-100 hover:border-slate-300 transition-all cursor-pointer group shadow-2xs focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <SeverityIndicator severity={finding.severity} />
                    <span className="font-mono text-[11px] font-semibold text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded whitespace-nowrap shrink-0">
                      {finding.id}
                    </span>
                    <span className="text-xs font-bold text-slate-900 group-hover:text-blue-700 transition-colors truncate">
                      {finding.title}
                    </span>
                  </div>
                  <ArrowRight className="h-3.5 w-3.5 text-slate-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all shrink-0 mt-0.5" />
                </div>

                {finding.description && (
                  <p className="text-[11px] text-slate-500 line-clamp-1 mt-1 pl-1 font-normal">
                    {finding.description}
                  </p>
                )}
              </button>
            ))
          ) : (
            <div className="py-8 text-center text-slate-400">
              <FileSearch className="h-8 w-8 mx-auto mb-2 text-slate-300" />
              <p className="text-xs">No high-severity forensic findings recorded.</p>
            </div>
          )}
        </div>
      </div>

      <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
        <span>Click any finding to inspect evidence details</span>
        <span>Deterministic proof</span>
      </div>
    </div>
  );
}
