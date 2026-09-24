import { Link } from 'react-router-dom';
import { Database, ChevronRight } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

export default function EvidenceSummary({ sha256 }: { sha256: string }) {
  const { investigationBundle } = useAnalysis();
  
  const records = investigationBundle?.counts.evidenceRecords || 0;
  const staticCount = investigationBundle?.counts.staticFindings || 0;
  const runtimeCount = investigationBundle?.counts.runtimeBehaviors || 0;
  const networkCount = (investigationBundle?.evidenceRecords || []).filter(r => r.title.toLowerCase().includes('network')).length || 0;
  // Fallback to 0 if visual isn't in bundle (or calculate from screenshots)
  const visualCount = investigationBundle?.counts.screenshots || 0; 

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm h-full flex flex-col">
      <div className="flex items-center gap-2 mb-1">
        <Database className="h-4 w-4 text-slate-400" />
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500">
          EVIDENCE
        </h2>
      </div>
      
      <p className="text-2xl font-semibold text-slate-900 mb-4 mt-2">
        {records} <span className="text-sm font-normal text-slate-500">verified records</span>
      </p>
      
      <div className="grid grid-cols-2 gap-y-3 gap-x-4 mb-6">
        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
          <span className="text-sm text-slate-600">Static</span>
          <span className="text-sm font-medium text-slate-900">{staticCount}</span>
        </div>
        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
          <span className="text-sm text-slate-600">Runtime</span>
          <span className="text-sm font-medium text-slate-900">{runtimeCount}</span>
        </div>
        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
          <span className="text-sm text-slate-600">Network</span>
          <span className="text-sm font-medium text-slate-900">{networkCount}</span>
        </div>
        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
          <span className="text-sm text-slate-600">Visual</span>
          <span className="text-sm font-medium text-slate-900">{visualCount}</span>
        </div>
      </div>
      
      <div className="mt-auto">
        <Link 
          to={`/case/${sha256}/evidence`} 
          className="inline-flex items-center text-sm font-medium text-blue-600 hover:text-blue-800 transition-colors group"
        >
          View all evidence
          <ChevronRight className="h-4 w-4 ml-0.5 group-hover:translate-x-0.5 transition-transform" />
        </Link>
      </div>
    </div>
  );
}
