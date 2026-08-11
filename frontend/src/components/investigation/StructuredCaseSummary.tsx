import { buildStructuredCaseSummary } from '../../lib/executiveIntelligence';
import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import { FileText } from 'lucide-react';

export default function StructuredCaseSummary({ data }: { data: FraudCardData }) {
  const sections = buildStructuredCaseSummary(data);

  return (
    <SocCard className="upload-fade-in border border-slate-200 rounded-md">
      <div className="px-4 py-3 border-b border-slate-200 bg-slate-900 text-white flex items-center gap-2">
        <FileText className="h-4 w-4 text-blue-400" />
        <h2 className="text-xs font-bold uppercase tracking-wider font-mono">Structured Case Intelligence</h2>
      </div>
      <div className="p-4 sm:p-5 grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-5">
        {sections.map((section) => (
          <div key={section.heading} className="min-w-0">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 font-mono mb-2 border-b border-slate-100 pb-1">{section.heading}</h3>
            <ul className="space-y-1.5">
              {section.lines.map((line, i) => (
                <li key={i} className="text-xs text-slate-700 leading-relaxed flex gap-2">
                  <span className="text-blue-600 mt-1.5 w-1 h-1 rounded-full bg-blue-600 shrink-0" />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </SocCard>
  );
}
