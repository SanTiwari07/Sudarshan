import { useMemo, useState } from 'react';
import { Database, Search, Filter, ChevronLeft, ChevronRight, CheckCircle2 } from 'lucide-react';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import CopyButton from '../ui/CopyButton';
import Badge from '../ui/Badge';
import type { IntelApiPayload } from '../../lib/threatIntelModel';

export default function ThreatIocRegistry({
  iocs,
}: {
  iocs: IntelApiPayload['iocs'];
}) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [typeFilter, setTypeFilter] = useState('All');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  const filteredIocs = useMemo(() => {
    return iocs.filter((ioc) => {
      const matchSearch =
        ioc.value.toLowerCase().includes(search.toLowerCase()) ||
        ioc.type.toLowerCase().includes(search.toLowerCase()) ||
        ioc.source.toLowerCase().includes(search.toLowerCase());
      const matchSeverity = severityFilter === 'All' || ioc.severity === severityFilter;
      const matchType = typeFilter === 'All' || ioc.type === typeFilter;
      return matchSearch && matchSeverity && matchType;
    });
  }, [iocs, search, severityFilter, typeFilter]);

  const totalPages = Math.ceil(filteredIocs.length / pageSize) || 1;
  const paginatedIocs = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredIocs.slice(start, start + pageSize);
  }, [filteredIocs, currentPage]);

  const types = Array.from(new Set(iocs.map((i) => i.type)));

  const severityBadge = (severity: string) => {
    const map: Record<string, string> = {
      Critical: 'bg-red-100 text-red-800 border-red-200',
      High: 'bg-orange-100 text-orange-800 border-orange-200',
      Medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      Low: 'bg-blue-100 text-blue-800 border-blue-200',
    };
    const cls = map[severity] || 'bg-slate-100 text-slate-700 border-slate-200';
    return (
      <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${cls}`}>{severity.toUpperCase()}</span>
    );
  };

  return (
    <SocCard>
      <SectionHeader icon={<Database className="h-4 w-4" />} title="IOC registry" subtitle="Filtered by graph selection when active" />
      <div className="p-4 bg-slate-50 border-b border-slate-200 grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setCurrentPage(1);
            }}
            placeholder="Search indicator…"
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-slate-400"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-slate-400" />
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full py-1.5 px-2 text-xs bg-white border border-slate-200 rounded-lg"
          >
            <option value="All">All severities</option>
            {['Critical', 'High', 'Medium', 'Low', 'Info'].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <select
          value={typeFilter}
          onChange={(e) => {
            setTypeFilter(e.target.value);
            setCurrentPage(1);
          }}
          className="w-full py-1.5 px-2 text-xs bg-white border border-slate-200 rounded-lg"
        >
          <option value="All">All types ({types.length})</option>
          {types.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>
      {paginatedIocs.length === 0 ? (
        <div className="p-8 text-center text-slate-400 text-xs">
          <CheckCircle2 className="h-8 w-8 text-emerald-500 mx-auto mb-2 opacity-80" />
          No indicators matched your filters.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left text-slate-600">
            <thead className="sticky top-0 z-10 bg-slate-100 text-slate-700 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-200 shadow-sm">
              <tr>
                <th className="px-4 py-2.5">Indicator</th>
                <th className="px-4 py-2.5">Type</th>
                <th className="px-4 py-2.5">Severity</th>
                <th className="px-4 py-2.5">Source</th>
                <th className="px-4 py-2.5">Reputation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {paginatedIocs.map((ioc, idx) => (
                <tr key={`${ioc.value}-${idx}`} className="hover:bg-slate-50/80 transition-colors">
                  <td className="px-4 py-3 font-mono text-slate-900">
                    <div className="flex items-center justify-between gap-2 max-w-lg">
                      <span className="truncate" title={ioc.value}>
                        {ioc.value}
                      </span>
                      <CopyButton value={ioc.value} />
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="px-2 py-0.5 text-[10px] bg-slate-100 border border-slate-200 rounded">{ioc.type}</span>
                  </td>
                  <td className="px-4 py-2.5">{severityBadge(ioc.severity)}</td>
                  <td className="px-4 py-2.5 text-slate-500">{ioc.source}</td>
                  <td className="px-4 py-2.5">
                    <Badge label={ioc.reputation} variant="risk" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="px-4 py-3 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
        <span>
          Showing {paginatedIocs.length} of {filteredIocs.length} indicators
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={currentPage === 1}
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            className="p-1 border border-slate-200 rounded hover:bg-slate-100 disabled:opacity-40"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span>
            Page {currentPage} of {totalPages}
          </span>
          <button
            type="button"
            disabled={currentPage >= totalPages}
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            className="p-1 border border-slate-200 rounded hover:bg-slate-100 disabled:opacity-40"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </SocCard>
  );
}
