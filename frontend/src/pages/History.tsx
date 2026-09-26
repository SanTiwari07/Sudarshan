import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Search, Inbox, FolderOpen, Plus, Smartphone,
  RefreshCw, XCircle, UploadCloud, ChevronRight,
} from 'lucide-react';
import PageHeader from '../components/ui/PageHeader';
import { getToken } from './Login';
import { API_BASE } from '../config';
import { useAnalysis } from '../context/AnalysisContext';
import Badge from '../components/ui/Badge';
import CopyButton from '../components/ui/CopyButton';
import { fmtDate } from '../utils/derive';
import { formatScore } from '../lib/verdictCopy';
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
  { value: 'all', label: 'All cases' },
  { value: 'critical', label: 'Critical' },
  { value: 'high risk', label: 'High risk' },
  { value: 'suspicious', label: 'Suspicious' },
  { value: 'safe', label: 'Safe' },
];

const LIMIT = 15;

type Tone = { dot: string; bar: string; tile: string };

const BAND_TONE: Record<string, Tone> = {
  all: { dot: 'bg-blue-500', bar: 'bg-blue-500', tile: 'bg-blue-50 text-blue-600' },
  critical: { dot: 'bg-red-500', bar: 'bg-red-500', tile: 'bg-red-50 text-red-600' },
  'high risk': { dot: 'bg-orange-500', bar: 'bg-orange-500', tile: 'bg-orange-50 text-orange-600' },
  suspicious: { dot: 'bg-amber-400', bar: 'bg-amber-400', tile: 'bg-amber-50 text-amber-600' },
  safe: { dot: 'bg-emerald-500', bar: 'bg-emerald-500', tile: 'bg-emerald-50 text-emerald-600' },
};

function toneFor(band: string | null | undefined): Tone {
  const b = (band || '').toLowerCase();
  if (b.includes('critical')) return BAND_TONE.critical;
  if (b.includes('high')) return BAND_TONE['high risk'];
  if (b.includes('suspicious')) return BAND_TONE.suspicious;
  if (b.includes('safe')) return BAND_TONE.safe;
  return { dot: 'bg-slate-400', bar: 'bg-slate-400', tile: 'bg-slate-100 text-slate-500' };
}

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
  const [reloadKey, setReloadKey] = useState(0);
  const [bandCounts, setBandCounts] = useState<Record<string, number>>({});

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
  }, [page, appliedSearch, filter, navigate, reloadKey]);

  /*
   * Per-band totals for the summary tiles. One `limit=1` request per band -
   * the server already counts, so this costs five tiny queries rather than
   * pulling the whole registry to count client-side.
   */
  useEffect(() => {
    let cancelled = false;
    const token = getToken();
    if (!token) return;
    Promise.all(
      BANDS.map(async (b) => {
        const params = new URLSearchParams({ limit: '1', offset: '0' });
        if (b.value !== 'all') params.set('band', b.value);
        const res = await fetch(`${API_BASE}/cases?${params.toString()}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: CaseListResponse = await res.json();
        return [b.value, data.total] as const;
      }),
    )
      .then((pairs) => { if (!cancelled) setBandCounts(Object.fromEntries(pairs)); })
      .catch(() => { /* tiles fall back to a dash */ });
    return () => { cancelled = true; };
  }, [reloadKey]);

  const handleCaseClick = async (sha256: string) => {
    await loadCaseByHash(sha256);
    navigate(`/history/${sha256}`);
  };

  const totalPages = Math.max(1, Math.ceil(total / LIMIT));
  const filtered = Boolean(appliedSearch) || filter !== 'all';

  return (
    <div className="page-frame">
      <PageHeader
        icon={FolderOpen}
        title="Cases"
        description="Every app Sudarshan has analysed, with its verdict and risk score. Open a case to see the evidence behind it."
        actions={
          <button
            type="button"
            onClick={() => navigate('/')}
            className="inline-flex items-center gap-2 h-10 px-4 rounded-xl bg-blue-600 text-sm font-semibold text-white shadow-sm shadow-blue-600/20 hover:bg-blue-700 transition-colors"
          >
            <Plus className="h-4 w-4" aria-hidden />
            New analysis
          </button>
        }
      />

      {/* Band summary. Each tile doubles as the filter for that band. */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 sm:gap-4">
        {BANDS.map((b) => {
          const tone = BAND_TONE[b.value];
          const active = filter === b.value;
          return (
            <button
              key={b.value}
              type="button"
              onClick={() => setFilter(b.value)}
              aria-pressed={active}
              className={`group text-left rounded-2xl border bg-white p-4 transition-all ${
                active
                  ? 'border-blue-500 ring-4 ring-blue-500/10'
                  : 'border-slate-200/80 hover:border-slate-300 hover:shadow-sm'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${tone.dot}`} aria-hidden />
                <span className="text-[13px] font-medium text-slate-500">{b.label}</span>
              </div>
              <p className="mt-2 text-[28px] font-semibold tracking-[-0.03em] text-slate-900 tabular-nums leading-none">
                {bandCounts[b.value] ?? '–'}
              </p>
            </button>
          );
        })}
      </div>

      {error && (
        <div className={`flex items-center gap-2 px-4 py-3 rounded-xl bg-red-50 border border-red-200 text-red-700 ${TYPOGRAPHY.bodySmall}`}>
          <XCircle className="h-4 w-4 shrink-0" aria-hidden />
          {error}
        </div>
      )}

      <div className="bg-white border border-slate-200/80 rounded-2xl overflow-hidden shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
        {/* Toolbar */}
        <div className="flex flex-col sm:flex-row sm:items-center gap-3 p-4 border-b border-slate-100">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" aria-hidden />
            <input
              type="search"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by app name, package, family or SHA-256"
              aria-label="Search cases"
              className="w-full h-10 pl-10 pr-3 rounded-xl border border-slate-200 bg-slate-50/60 text-sm text-slate-900 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500 transition-colors"
            />
          </div>
          <p className="text-sm text-slate-500 whitespace-nowrap">
            {total} {total === 1 ? 'case' : 'cases'}
            {filtered ? ' match' : ''}
          </p>
          <button
            type="button"
            onClick={() => setReloadKey(k => k + 1)}
            disabled={loading}
            className="h-10 w-10 flex items-center justify-center rounded-xl border border-slate-200 bg-white hover:bg-slate-50 transition-colors disabled:opacity-50 shrink-0"
            title="Refresh"
            aria-label="Refresh"
          >
            <RefreshCw className={`h-4 w-4 text-slate-500 ${loading ? 'animate-spin' : ''}`} aria-hidden />
          </button>
        </div>

        {loading && cases.length === 0 ? (
          <div className="flex items-center justify-center py-20 text-sm text-slate-500 gap-3">
            <RefreshCw className="h-5 w-5 animate-spin" aria-hidden />
            Loading cases
          </div>
        ) : cases.length === 0 ? (
          <div className="py-20 px-6 text-center">
            <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-400">
              <Inbox className="h-7 w-7" aria-hidden />
            </span>
            <p className="mt-4 text-base font-semibold text-slate-900">
              {filtered ? 'No matching cases' : 'No cases yet'}
            </p>
            <p className="mt-1 text-sm text-slate-500 max-w-sm mx-auto">
              {filtered
                ? 'Try a different search term or risk band.'
                : 'Upload an APK and its case file will appear here when the analysis finishes.'}
            </p>
            {!filtered && (
              <button
                type="button"
                onClick={() => navigate('/')}
                className="mt-5 inline-flex items-center gap-2 h-10 px-4 rounded-xl bg-blue-600 text-sm font-semibold text-white hover:bg-blue-700 transition-colors"
              >
                <UploadCloud className="h-4 w-4" aria-hidden />
                Upload an APK
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50/70">
                <tr className="text-left text-xs font-semibold uppercase tracking-[0.06em] text-slate-500">
                  <th className="px-5 py-3">Application</th>
                  <th className="px-4 py-3">Verdict</th>
                  <th className="px-4 py-3">Risk score</th>
                  <th className="px-4 py-3">Family</th>
                  <th className="px-4 py-3 hidden lg:table-cell">Coverage</th>
                  <th className="px-4 py-3 hidden 2xl:table-cell">SHA-256</th>
                  <th className="px-4 py-3 hidden md:table-cell">Scanned</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {cases.map(c => {
                  const tone = toneFor(c.risk_band);
                  const score = c.final_risk_score ?? 0;
                  return (
                    <tr
                      key={c.sha256}
                      className="hover:bg-blue-50/40 transition-colors cursor-pointer group"
                      onClick={() => handleCaseClick(c.sha256)}
                    >
                      {/* Identity leads. The hash is a lookup key, not a name. */}
                      <td className="px-5 py-3.5 min-w-[16rem]">
                        <div className="flex items-center gap-3 min-w-0">
                          <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${tone.tile}`}>
                            <Smartphone className="h-5 w-5" aria-hidden />
                          </span>
                          <div className="min-w-0">
                            <div className="text-[15px] font-semibold text-slate-900 truncate">
                              {c.app_name || c.package_name || 'Unnamed'}
                            </div>
                            {c.package_name && c.package_name !== c.app_name && (
                              <div className="font-mono text-xs text-slate-500 truncate">{c.package_name}</div>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <Badge label={c.risk_band || 'Safe'} variant="risk" />
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-3 min-w-[9rem]">
                          <span className="text-[15px] font-semibold text-slate-900 tabular-nums w-9">
                            {formatScore(c.final_risk_score)}
                          </span>
                          <span className="h-1.5 flex-1 max-w-[6rem] rounded-full bg-slate-100 overflow-hidden">
                            <span
                              className={`block h-full rounded-full ${tone.bar}`}
                              style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
                            />
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 text-sm text-slate-700">
                        {c.family_classification && c.family_classification !== 'Unknown' ? (
                          c.family_classification
                        ) : (
                          <span className="text-slate-400">Unclassified</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5 hidden lg:table-cell">
                        <span className={`inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-medium rounded-full px-2.5 py-1 ${
                          c.dynamic_available ? 'bg-indigo-50 text-indigo-700' : 'bg-slate-100 text-slate-600'
                        }`}>
                          {c.dynamic_available ? 'Static + runtime' : 'Static only'}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 hidden 2xl:table-cell">
                        <span
                          className="flex items-center gap-1 font-mono text-xs text-slate-500"
                          onClick={e => e.stopPropagation()}
                        >
                          {c.sha256.slice(0, 12)}…
                          <CopyButton value={c.sha256} />
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-sm text-slate-500 hidden md:table-cell whitespace-nowrap">
                        {fmtDate(c.created_at)}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <ChevronRight
                          className="h-4 w-4 text-slate-300 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all inline"
                          aria-hidden
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-slate-100">
            <span className="text-sm text-slate-500">
              {page * LIMIT + 1}–{Math.min((page + 1) * LIMIT, total)} of {total}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="h-9 px-3 rounded-lg border border-slate-200 bg-white text-sm font-medium text-slate-700 disabled:opacity-40 hover:bg-slate-50"
              >
                Previous
              </button>
              <span className="text-sm text-slate-500 px-1">
                {page + 1} / {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="h-9 px-3 rounded-lg border border-slate-200 bg-white text-sm font-medium text-slate-700 disabled:opacity-40 hover:bg-slate-50"
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
