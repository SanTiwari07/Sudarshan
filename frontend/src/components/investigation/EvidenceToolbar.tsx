import { Search } from 'lucide-react';

export type EvidenceFilter = 'all' | 'critical' | 'static' | 'runtime' | 'threat';

const FILTERS: { id: EvidenceFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'critical', label: 'Critical' },
  { id: 'static', label: 'Static' },
  { id: 'runtime', label: 'Runtime' },
  { id: 'threat', label: 'Threat Intel' },
];

export default function EvidenceToolbar({
  total,
  search,
  onSearchChange,
  filter,
  onFilterChange,
}: {
  total: number;
  search: string;
  onSearchChange: (v: string) => void;
  filter: EvidenceFilter;
  onFilterChange: (v: EvidenceFilter) => void;
}) {
  return (
    <div className="py-4 border-b border-slate-200 space-y-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-[17px] font-semibold text-slate-900 tracking-tight">Evidence registry</h2>
          <p className="text-[12px] text-slate-500 mt-0.5 leading-relaxed">
            {total} verified finding{total === 1 ? '' : 's'} · Static analysis · runtime instrumentation · threat
            correlation
          </p>
        </div>
        <div className="relative w-full sm:w-64 shrink-0">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" aria-hidden />
          <input
            type="search"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search findings…"
            className="w-full pl-8 pr-3 py-2 text-[13px] rounded-lg border border-slate-200 bg-white text-slate-800 placeholder:text-slate-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-slate-300"
            aria-label="Search findings"
          />
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {FILTERS.map((f) => {
          const active = filter === f.id;
          return (
            <button
              key={f.id}
              type="button"
              onClick={() => onFilterChange(f.id)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-colors ${
                active
                  ? 'bg-slate-900 text-white'
                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
              }`}
            >
              {f.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
