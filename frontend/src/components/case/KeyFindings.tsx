import { Link } from 'react-router-dom';
import type { FraudCardData } from '../../types/case';
import { useAnalysis } from '../../context/AnalysisContext';

export default function KeyFindings({ data }: { data: FraudCardData }) {
  const { investigationBundle } = useAnalysis();
  const records = investigationBundle?.evidenceRecords || [];
  
  // Try to find the highest severity records
  const topFindings = [...records]
    .sort((a, b) => {
      const sevMap: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (sevMap[b.severity] || 0) - (sevMap[a.severity] || 0);
    })
    .slice(0, 4);

  // Fallback to simple strings if we don't have structured bundle records
  const fallbackFindings = [];
  if (topFindings.length === 0) {
    if (data.targets_indian_banks) fallbackFindings.push("Targets Indian Banking Applications");
    if (data.has_accessibility_abuse) fallbackFindings.push("Accessibility Service Abuse");
    if (data.has_sms_read_write) fallbackFindings.push("SMS Interception Capability");
    if (data.dynamic_analysis?.activities_triggered?.length) {
      fallbackFindings.push("Suspicious Runtime Activity Detected");
    }
    if (data.has_reflection) fallbackFindings.push("Dynamic Class Invocation / Reflection");
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-4">
        KEY FINDINGS
      </h2>
      
      <div className="space-y-3">
        {topFindings.length > 0 ? (
          topFindings.map((finding) => (
            <Link 
              key={finding.id}
              to={`/case/${data.sha256}/evidence?record=${finding.id}`}
              className="block group p-3 rounded-lg border border-slate-100 bg-slate-50 hover:bg-slate-100 hover:border-slate-200 transition-colors"
            >
              <div className="flex items-start gap-3">
                <div className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${finding.severity === 'high' || finding.severity === 'critical' ? 'bg-red-500' : finding.severity === 'medium' ? 'bg-amber-500' : 'bg-slate-400'}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-slate-900 group-hover:text-blue-700 transition-colors truncate">
                    {finding.title}
                  </p>
                  <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">
                    {finding.description}
                  </p>
                </div>
              </div>
            </Link>
          ))
        ) : fallbackFindings.length > 0 ? (
          fallbackFindings.map((finding, idx) => (
            <div key={idx} className="flex items-center gap-3 p-3 rounded-lg border border-slate-100 bg-slate-50">
              <div className="w-1.5 h-1.5 rounded-full bg-slate-400 shrink-0" />
              <p className="text-sm font-medium text-slate-900">{finding}</p>
            </div>
          ))
        ) : (
          <p className="text-sm text-slate-500">No significant findings recorded.</p>
        )}
      </div>
    </div>
  );
}
