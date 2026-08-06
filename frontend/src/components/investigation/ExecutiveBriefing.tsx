import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import { buildExecutiveSummaryParagraph, buildWhatThisMeans } from '../../lib/analystCopy';
import { FileText, Lightbulb } from 'lucide-react';

export default function ExecutiveBriefing({ data }: { data: FraudCardData }) {
  const summary = buildExecutiveSummaryParagraph(data);
  const meaning = buildWhatThisMeans(data);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <SocCard className="h-full">
        <div className="px-5 py-4 border-b border-slate-200 bg-gradient-to-r from-blue-900 to-blue-800">
          <div className="flex items-center gap-2 text-blue-100">
            <FileText className="h-4 w-4 text-blue-300" />
            <h2 className="text-base font-bold text-white tracking-tight">Executive Case Summary</h2>
          </div>
          <p className="text-[11px] text-blue-200/90 mt-1">
            Overall security posture based on verified evidence.
          </p>
        </div>
        <div className="p-5">
          <p className="text-sm text-slate-700 leading-relaxed">{summary}</p>
        </div>
      </SocCard>

      <SocCard className="h-full">
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50">
          <div className="flex items-center gap-2">
            <Lightbulb className="h-4 w-4 text-amber-600" />
            <h2 className="text-base font-bold text-slate-900 tracking-tight">What this means</h2>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Business impact in plain language.</p>
        </div>
        <div className="p-5">
          <p className="text-sm text-slate-700 leading-relaxed">{meaning}</p>
        </div>
      </SocCard>
    </div>
  );
}
