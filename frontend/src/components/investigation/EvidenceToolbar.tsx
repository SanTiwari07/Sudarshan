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
    <div className="p-4 sm:p-5 border-b border-slate-100 bg-slate-50/50">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between mb-4">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">Evidence Registry</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            {total} verified finding{total === 1 ? '' : 's'} · Static, runtime, and threat correlation evidence
          </p>
        </div>
      </div>
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          {FILTERS.map((f) => {
            const active = filter === f.id;
            return (
              <button
                key={f.id}
                type="button"
                onClick={() => onFilterChange(f.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  active
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-50 hover:text-slate-900'
                }`}
              >
                {f.label}
              </button>
            );
          })}
        </div>

        {/* Search Bar */}
        <div className="relative w-full sm:w-64 shrink-0">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" aria-hidden />
          <input
            type="search"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search findings…"
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 bg-white text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500 shadow-xs"
            aria-label="Search findings"
          />
        </div>
      </div>
    </div>
  );
}
