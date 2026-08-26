import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Database, Search,
  RefreshCw, XCircle, Clock, UploadCloud, ChevronRight,
} from 'lucide-react';
import { getToken } from './Login';
import { API_BASE } from '../config';
import { useAnalysis } from '../context/AnalysisContext';
import Badge from '../components/ui/Badge';
import CopyButton from '../components/ui/CopyButton';
import { fmtDate } from '../utils/derive';
import { formatScore } from '../lib/verdictCopy';
import { getRiskAccent } from '../theme/colors';
import { TYPOGRAPHY } from '../theme/typography';

interface CaseSummary {
  sha256: string;
  package_name: string | null;
  app_name: string | null;
  analysis_mode: string | null;
  family_classification: string | null;
  final_risk_score: number | null;
  risk_band: string | null;
  confidence: number | null;
  dynamic_available: boolean;
  obfuscation_score: number;
  has_reflection: boolean;
  created_at: string;
}

interface CaseListResponse {
  total: number;
  limit: number;
  offset: number;
  cases: CaseSummary[];
}

const BANDS = [
  { value: 'all', label: 'All bands' },
  { value: 'critical', label: 'Critical' },
  { value: 'high risk', label: 'High risk' },
  { value: 'suspicious', label: 'Suspicious' },
  { value: 'safe', label: 'Safe' },
];

const LIMIT = 15;

export default function History() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { loadCaseByHash } = useAnalysis();

  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState(searchParams.get('q') || '');
  const [filter, setFilter] = useState<string>('all');

  /**
   * Debounced so a typed query is one request per pause, not one per keystroke.
   * The query itself goes to the server: filtering the fifteen rows already on
   * screen meant a package on page four reported "no cases found".
   */
  const [appliedSearch, setAppliedSearch] = useState(search);
  useEffect(() => {
    const t = setTimeout(() => setAppliedSearch(search.trim()), 250);
    return () => clearTimeout(t);
  }, [search]);

  // Any change to the query resets to the first page - otherwise a narrowed
  // result set can leave the reader stranded on a page that no longer exists.
  useEffect(() => {
    setPage(0);
  }, [appliedSearch, filter]);

  useEffect(() => {
    const q = searchParams.get('q');
    if (q) setSearch(q);
  }, [searchParams]);

  useEffect(() => {
    let cancelled = false;

    const run = async () => {
      const token = getToken();
      if (!token) { navigate('/login'); return; }

      setLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams({
          limit: String(LIMIT),
          offset: String(page * LIMIT),
        });
        if (appliedSearch) params.set('q', appliedSearch);
        if (filter !== 'all') params.set('band', filter);

        const res = await fetch(`${API_BASE}/cases?${params.toString()}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.status === 401) { navigate('/login'); return; }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: CaseListResponse = await res.json();
        if (cancelled) return;
        setCases(data.cases);
        setTotal(data.total);
      } catch (e: unknown) {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Failed to load cases');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    run();
    return () => { cancelled = true; };
  }, [page, appliedSearch, filter, navigate]);

  const handleCaseClick = async (sha256: string) => {
    await loadCaseByHash(sha256);
    navigate(`/history/${sha256}`);
  };

  const totalPages = Math.max(1, Math.ceil(total / LIMIT));

  return (
    <div className="w-full min-w-0 max-w-[1600px] mx-auto space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h1 className={TYPOGRAPHY.h1}>Case registry</h1>
          <p className={`${TYPOGRAPHY.caption} mt-0.5`}>
            {total} {total === 1 ? 'case' : 'cases'}
            {appliedSearch || filter !== 'all' ? ' matching the current filter' : ' analysed'}
          </p>
        </div>
        <button
          type="button"
          onClick={() => navigate('/')}
          className={`${TYPOGRAPHY.button} bg-blue-700 text-white hover:bg-blue-800 px-4 py-2`}
        >
          <UploadCloud className="h-4 w-4" aria-hidden />
          Upload APK
        </button>
      </header>

      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" aria-hidden />
          <input
            type="search"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search hash, package, app name or family"
            aria-label="Search cases"
            className={`w-full pl-9 pr-3 py-2 rounded-md border border-slate-300 bg-white ${TYPOGRAPHY.body} focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
          />
        </div>

        {/* Bands as a segmented control: five mutually exclusive options are
            faster to hit than a select, and the current one stays visible. */}
        <div
          role="group"
          aria-label="Filter by risk band"
          className="inline-flex rounded-md border border-slate-300 bg-white overflow-hidden shrink-0"
        >
          {BANDS.map(b => (
            <button
              key={b.value}
              type="button"
              onClick={() => setFilter(b.value)}
              aria-pressed={filter === b.value}
              className={`px-3 py-2 text-[13px] font-medium border-r border-slate-200 last:border-r-0 transition-colors ${
                filter === b.value
                  ? 'bg-slate-900 text-white'
                  : 'text-slate-600 hover:bg-slate-50'
              }`}
            >
              {b.label}
            </button>
          ))}
        </div>

        <button
          type="button"
          onClick={() => setPage(p => p)}
          disabled={loading}
          className="p-2 rounded-md border border-slate-300 bg-white hover:bg-slate-50 transition-colors disabled:opacity-50 shrink-0"
          title="Refresh"
          aria-label="Refresh"
        >
          <RefreshCw className={`h-4 w-4 text-slate-500 ${loading ? 'animate-spin' : ''}`} aria-hidden />
        </button>
      </div>

      {error && (
        <div className={`flex items-center gap-2 px-4 py-3 rounded-md bg-red-50 border border-red-200 text-red-700 ${TYPOGRAPHY.bodySmall}`}>
          <XCircle className="h-4 w-4 shrink-0" aria-hidden />
          {error}
        </div>
      )}

      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        {loading && cases.length === 0 ? (
          <div className={`flex items-center justify-center py-16 text-slate-400 gap-3 ${TYPOGRAPHY.caption}`}>
            <RefreshCw className="h-5 w-5 animate-spin" aria-hidden />
            Loading cases
          </div>
        ) : cases.length === 0 ? (
          <div className={`py-16 text-center text-slate-400 ${TYPOGRAPHY.caption}`}>
            <Database className="h-8 w-8 mx-auto mb-2 opacity-40" aria-hidden />
            <p>No cases found{appliedSearch ? ` matching “${appliedSearch}”` : ''}.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <th className={`px-4 py-2.5 text-left ${TYPOGRAPHY.tableHeader}`}>Application</th>
                  <th className={`px-4 py-2.5 text-left ${TYPOGRAPHY.tableHeader}`}>Band</th>
                  <th className={`px-4 py-2.5 text-right ${TYPOGRAPHY.tableHeader}`}>Score</th>
                  <th className={`px-4 py-2.5 text-left ${TYPOGRAPHY.tableHeader}`}>Family</th>
                  <th className={`px-4 py-2.5 text-left ${TYPOGRAPHY.tableHeader}`}>Analysis</th>
                  <th className={`px-4 py-2.5 text-left hidden xl:table-cell ${TYPOGRAPHY.tableHeader}`}>SHA-256</th>
                  <th className={`px-4 py-2.5 text-left hidden md:table-cell ${TYPOGRAPHY.tableHeader}`}>
                    <Clock className="h-3.5 w-3.5 inline mr-1" aria-hidden />Scanned
                  </th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {cases.map(c => (
                  <tr
                    key={c.sha256}
                    className={`hover:bg-slate-50 transition-colors cursor-pointer group border-l-2 ${
                      getRiskAccent(c.risk_band).bar
                    }`}
                    onClick={() => handleCaseClick(c.sha256)}
                  >
                    {/* Identity leads. The hash is a lookup key, not a name. */}
                    <td className="px-4 py-2.5 min-w-[14rem]">
                      <div className={`${TYPOGRAPHY.h3} truncate`}>
                        {c.app_name || c.package_name || 'Unnamed'}
                      </div>
                      {c.app_name && c.package_name && (
                        <div className={`${TYPOGRAPHY.codeSm} text-slate-400 truncate`}>
                          {c.package_name}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge label={c.risk_band || 'Safe'} variant="risk" />
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span className="font-display text-sm font-semibold text-slate-900 tabular-nums tracking-[-0.02em]">
                        {formatScore(c.final_risk_score)}
                      </span>
                    </td>
                    <td className={`px-4 py-2.5 ${TYPOGRAPHY.tableCell}`}>
                      {c.family_classification && c.family_classification !== 'Unknown' ? (
                        c.family_classification
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className={`px-4 py-2.5 ${TYPOGRAPHY.tableCell}`}>
                      {c.dynamic_available ? 'Static + runtime' : 'Static only'}
                    </td>
                    <td className="px-4 py-2.5 hidden xl:table-cell">
                      <span
                        className={`flex items-center gap-1 ${TYPOGRAPHY.hash}`}
                        onClick={e => e.stopPropagation()}
                      >
                        {c.sha256.slice(0, 16)}…
                        <CopyButton value={c.sha256} />
                      </span>
                    </td>
                    <td className={`px-4 py-2.5 ${TYPOGRAPHY.caption} hidden md:table-cell whitespace-nowrap`}>
                      {fmtDate(c.created_at)}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <ChevronRight
                        className="h-4 w-4 text-slate-300 group-hover:text-blue-600 transition-colors inline"
                        aria-hidden
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-2.5 border-t border-slate-200 bg-slate-50/60">
            <span className={TYPOGRAPHY.caption}>
              {page * LIMIT + 1}–{Math.min((page + 1) * LIMIT, total)} of {total}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className={`${TYPOGRAPHY.buttonSm} border border-slate-300 bg-white disabled:opacity-40 hover:bg-slate-100`}
              >
                Previous
              </button>
              <span className={TYPOGRAPHY.caption}>
                Page {page + 1} of {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className={`${TYPOGRAPHY.buttonSm} border border-slate-300 bg-white disabled:opacity-40 hover:bg-slate-100`}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
