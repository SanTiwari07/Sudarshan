import { buildStructuredCaseSummary } from '../../lib/executiveIntelligence';
import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import { FileText } from 'lucide-react';

export default function StructuredCaseSummary({ data }: { data: FraudCardData }) {
  const sections = buildStructuredCaseSummary(data);

  return (
    <SocCard className="upload-fade-in">
      <div className="px-5 py-4 border-b border-slate-200 bg-gradient-to-r from-blue-900 to-blue-800">
        <div className="flex items-center gap-2 text-blue-100">
          <FileText className="h-4 w-4 text-blue-300" />
          <h2 className="text-base font-bold text-white tracking-tight">Case Summary</h2>
        </div>
        <p className="text-[11px] text-blue-200/90 mt-1">Structured fraud intelligence for executives and analysts.</p>
      </div>
      <div className="p-5 sm:p-6 grid grid-cols-1 md:grid-cols-2 gap-5 sm:gap-6">
        {sections.map((section) => (
          <div key={section.heading} className="min-w-0">
            <h3 className="text-xs font-bold uppercase tracking-wide text-slate-500 mb-2">{section.heading}</h3>
            <ul className="space-y-1.5">
              {section.lines.map((line, i) => (
                <li key={i} className="text-sm text-slate-700 leading-relaxed flex gap-2">
                  <span className="text-blue-500 mt-1.5 w-1 h-1 rounded-full bg-blue-500 shrink-0" />
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
