import { Link } from 'react-router-dom';
import CardTitle from '../ui/CardTitle';
import { Database, ChevronRight, Cpu, Activity, Globe, Eye, ShieldAlert } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

export default function EvidenceSummary({ sha256 }: { sha256: string }) {
  const { investigationBundle } = useAnalysis();

  const totalRecords = investigationBundle?.counts.evidenceRecords || 0;
  const staticCount = investigationBundle?.counts.staticFindings || 0;
  const runtimeCount = investigationBundle?.counts.runtimeBehaviors || 0;
  const networkCount =
    (investigationBundle?.evidenceRecords || []).filter(
      (r) =>
        r.category.toLowerCase().includes('network') ||
        r.title.toLowerCase().includes('network') ||
        r.title.toLowerCase().includes('domain') ||
        r.title.toLowerCase().includes('traffic'),
    ).length || 0;
  const visualCount =
    investigationBundle?.counts.screenshots ||
    (investigationBundle?.evidenceRecords || []).filter((r) =>
      r.category.toLowerCase().includes('visual'),
    ).length || 0;
  const intelCount =
    (investigationBundle?.evidenceRecords || []).filter(
      (r) =>
        r.sourceEngine.toLowerCase().includes('intel') ||
        r.category.toLowerCase().includes('threat') ||
        r.category.toLowerCase().includes('intel'),
    ).length || 0;

  const categories = [
    {
      label: 'Static Analysis',
      count: staticCount,
      icon: Cpu,
      path: `/case/${sha256}/evidence?section=static`,
      hint: 'Decompiled code & manifest',
    },
    {
      label: 'Runtime Behavior',
      count: runtimeCount,
      icon: Activity,
      path: `/case/${sha256}/evidence?section=dynamic`,
      hint: 'Frida hooks & execution',
    },
    {
      label: 'Network Traffic',
      count: networkCount,
      icon: Globe,
      path: `/case/${sha256}/evidence?section=network`,
      hint: 'C2 endpoints & DNS',
    },
    {
      label: 'Visual & Overlay',
      count: visualCount,
      icon: Eye,
      path: `/case/${sha256}/evidence?section=visual`,
      hint: 'Screenshots & UI matching',
    },
    {
      label: 'Threat Intelligence',
      count: intelCount,
      icon: ShieldAlert,
      path: `/case/${sha256}/intel`,
      hint: 'OSINT correlation feeds',
    },
  ];

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-3">
          <CardTitle icon={Database} title="Evidence collected" tone="blue" info="How many pieces of evidence were collected from each source. Click a source to open those records on the Evidence tab." infoAlign="left" />
          <span className="text-xs font-semibold bg-blue-50 text-blue-700 px-2.5 py-0.5 rounded-full whitespace-nowrap">
            {totalRecords} Total Records
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 my-2">
          {categories.map((cat) => {
            const Icon = cat.icon;
            return (
              <Link
                key={cat.label}
                to={cat.path}
                className="p-3 rounded-xl border border-slate-100 bg-slate-50/50 hover:bg-blue-50/40 hover:border-blue-200 transition-all flex flex-col justify-between group shadow-2xs"
              >
                <div className="flex items-center justify-between mb-1">
                  <Icon className="h-3.5 w-3.5 text-slate-500 group-hover:text-blue-600 transition-colors" />
                  <ChevronRight className="h-3.5 w-3.5 text-slate-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all" />
                </div>
                <div className="text-2xl font-semibold tracking-[-0.02em] tabular-nums text-slate-900 group-hover:text-blue-700 transition-colors">
                  {cat.count}
                </div>
                <div className="text-[11px] font-semibold text-slate-700 group-hover:text-slate-900 truncate mt-0.5">
                  {cat.label}
                </div>
                <div className="text-[10px] text-slate-400 truncate">
                  {cat.hint}
                </div>
              </Link>
            );
          })}
        </div>
      </div>

      <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-xs">
        <span className="text-slate-400 text-[11px]">Click any category to jump to evidence tab</span>
        <Link
          to={`/case/${sha256}/evidence`}
          className="inline-flex items-center gap-1 font-semibold text-blue-600 hover:text-blue-800 transition-colors group"
        >
          <span>All Evidence Explorer</span>
          <ChevronRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
        </Link>
      </div>
    </div>
  );
}
