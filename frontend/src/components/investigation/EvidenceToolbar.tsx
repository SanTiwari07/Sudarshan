import { Search, ShieldAlert, Cpu } from 'lucide-react';

export type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
export type SourceFilter = 'all' | 'static' | 'dynamic' | 'intel' | 'vide';

export type EvidenceFilter = 'all' | 'critical' | 'static' | 'runtime' | 'threat';

const SEVERITY_OPTIONS: { id: SeverityFilter; label: string }[] = [
  { id: 'all', label: 'All Severities' },
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
  { id: 'medium', label: 'Medium' },
  { id: 'low', label: 'Low' },
];

const SOURCE_OPTIONS: { id: SourceFilter; label: string }[] = [
  { id: 'all', label: 'All Sources' },
  { id: 'static', label: 'Static' },
  { id: 'dynamic', label: 'Dynamic' },
  { id: 'intel', label: 'Intel' },
  { id: 'vide', label: 'VIDE' },
];

export default function EvidenceToolbar({
  search,
  onSearchChange,
  severityFilter = 'all',
  onSeverityChange,
  sourceFilter = 'all',
  onSourceChange,
  // Backwards compatibility props
  filter: _filter,
  onFilterChange,
}: {
  search: string;
  onSearchChange: (v: string) => void;
  severityFilter?: SeverityFilter;
  onSeverityChange?: (v: SeverityFilter) => void;
  sourceFilter?: SourceFilter;
  onSourceChange?: (v: SourceFilter) => void;
  filter?: EvidenceFilter;
  onFilterChange?: (v: EvidenceFilter) => void;
}) {
  const handleSev = (sev: SeverityFilter) => {
    if (onSeverityChange) onSeverityChange(sev);
    if (onFilterChange) {
      if (sev === 'critical') onFilterChange('critical');
      else if (sev === 'all') onFilterChange('all');
    }
  };

  const handleSource = (src: SourceFilter) => {
    if (onSourceChange) onSourceChange(src);
    if (onFilterChange) {
      if (src === 'static') onFilterChange('static');
      else if (src === 'dynamic') onFilterChange('runtime');
      else if (src === 'intel') onFilterChange('threat');
      else onFilterChange('all');
    }
  };

  return (
    <div className="px-4 py-3 border-b border-slate-200 bg-white space-y-3">
      {/* Top Controls: Search and Filters */}
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        {/* Search Bar */}
        <div className="relative w-full lg:w-72 shrink-0">
          <Search
            className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400"
            aria-hidden
          />
          <input
            type="search"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search evidence ID, title, description…"
            className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 bg-slate-50/50 text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-all font-medium"
            aria-label="Search evidence records"
          />
        </div>

        {/* Severity Filter Badges */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 lg:pb-0">
          <div className="flex items-center gap-1 text-[11px] font-bold text-slate-400 uppercase mr-1 shrink-0">
            <ShieldAlert className="h-3 w-3" />
            <span>Severity:</span>
          </div>
          <div className="inline-flex rounded-lg border border-slate-200 p-0.5 bg-slate-50 shrink-0">
            {SEVERITY_OPTIONS.map((opt) => {
              const active = (severityFilter || 'all') === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => handleSev(opt.id)}
                  className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-all ${
                    active
                      ? 'bg-white text-blue-700 shadow-2xs font-bold'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Source Filter Badges */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 lg:pb-0">
          <div className="flex items-center gap-1 text-[11px] font-bold text-slate-400 uppercase mr-1 shrink-0">
            <Cpu className="h-3 w-3" />
            <span>Source:</span>
          </div>
          <div className="inline-flex rounded-lg border border-slate-200 p-0.5 bg-slate-50 shrink-0">
            {SOURCE_OPTIONS.map((opt) => {
              const active = (sourceFilter || 'all') === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => handleSource(opt.id)}
                  className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-all ${
                    active
                      ? 'bg-white text-indigo-700 shadow-2xs font-bold'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
