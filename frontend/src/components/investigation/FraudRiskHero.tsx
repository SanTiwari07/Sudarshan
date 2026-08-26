import { useState } from 'react';
import { BarChart2, ChevronDown, Info } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { getRiskStyle } from '../../theme/colors';
import { TYPOGRAPHY } from '../../theme/typography';
import { extractAppMetadata } from '../../lib/analystCopy';
import { formatScore, bandOverrideReason, verdictHeadline } from '../../lib/verdictCopy';
import HelpTerm from './HelpTerm';
import CopyButton from '../ui/CopyButton';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import RiskInfluenceCard from './RiskInfluenceCard';
import DownloadReportButton from './DownloadReportButton';

function ScoreRing({ score, pct, strokeClass }: { score: number; pct: number; strokeClass: string }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;

  return (
    <div className="relative w-36 h-36 sm:w-40 sm:h-40 shrink-0">
      <svg className="w-full h-full -rotate-90 score-ring-spin" viewBox="0 0 120 120" aria-hidden>
        <circle cx="60" cy="60" r={r} fill="none" stroke="currentColor" strokeWidth="8" className="text-slate-100" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          strokeWidth="8"
          strokeLinecap="round"
          className={`score-ring-progress transition-all duration-1000 ease-out ${strokeClass}`}
          stroke="currentColor"
          strokeDasharray={c}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display text-4xl sm:text-5xl font-semibold tracking-[-0.045em] text-slate-900 tabular-nums leading-none">
          {formatScore(score)}
        </span>
        <span className={`${TYPOGRAPHY.displaySub} mt-1`}>/ 100</span>
      </div>
    </div>
  );
}

/**
 * Case metadata, collapsed.
 *
 * Eight label/value rows used to sit at the top of the page in the same
 * typographic register as the verdict, and half of them read as a dash. None
 * of it answers "is this app dangerous"; all of it matters once you have
 * decided it is. So it lives one click down rather than above the fold.
 */
function CaseDetails({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(false);
  const meta = extractAppMetadata(data);

  const clean = (v: unknown) => {
    const s = typeof v === 'string' ? v.trim() : '';
    return s && s !== '—' && s !== '-' && s !== 'Unknown' ? s : null;
  };

  const rows: Array<{ label: string; value: string; mono?: boolean; copy?: boolean }> = [];
  const push = (label: string, value: string | null, opts: { mono?: boolean; copy?: boolean } = {}) => {
    if (value) rows.push({ label, value, ...opts });
  };

  push('App name', clean(data.app_name));
  push('Package', clean(data.package_name), { mono: true, copy: true });
  push('Version', clean(meta.version) ?? clean((data as any).version_name));
  push('Size', clean(meta.size) ?? clean((data as any).apk_size));
  push('SHA-256', clean(data.sha256), { mono: true, copy: true });
  push('Platform', 'Android (APK)');
  push('Analysis', 'Static · Dynamic · Threat intelligence');

  const createdAt = (data as any).created_at;
  if (createdAt) {
    push(
      'Analysed',
      new Date(createdAt).toLocaleString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
      }),
    );
  }

  if (rows.length === 0) return null;

  const subject = data.package_name || data.sha256 || '';

  return (
    <div className="border-t border-slate-200/70">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-2 px-6 py-3 text-left hover:bg-slate-50/70 transition-colors"
      >
        <span className={`${TYPOGRAPHY.label} flex items-center gap-2`}>
          <Info className="h-3.5 w-3.5 text-slate-400" aria-hidden />
          Case details
          <span className="font-mono text-slate-400">
            {subject.slice(0, 28)}
            {subject.length > 28 ? '…' : ''}
          </span>
        </span>
        <ChevronDown
          className={`h-4 w-4 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`}
          aria-hidden
        />
      </button>
      {open && (
        <dl className="px-6 pb-4 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-0">
          {rows.map((row) => (
            <div
              key={row.label}
              className={`flex items-baseline justify-between gap-3 py-1.5 border-b border-slate-100 ${
                row.label === 'SHA-256' ? 'sm:col-span-2' : ''
              }`}
            >
              <dt className={TYPOGRAPHY.label}>{row.label}</dt>
              <dd className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`${row.mono ? TYPOGRAPHY.codeSm : TYPOGRAPHY.bodySmall} text-right truncate`}
                  title={row.value}
                >
                  {row.value}
                </span>
                {row.copy && (
                  <CopyButton
                    value={row.value}
                    className="h-4 w-4 p-0 shrink-0 text-slate-300 hover:text-slate-600"
                  />
                )}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

export default function FraudRiskHero({ data }: { data: FraudCardData }) {
  const riskStyle = getRiskStyle(data.risk_band);
  const { openLedger } = useInvestigationUI();
  const score = data.final_risk_score;
  const pct = Math.min(100, Math.max(0, score));
  const band = data.risk_band || 'Unknown';
  const overrideReason = bandOverrideReason(data);

  return (
    <div className="bg-white border border-slate-300 rounded-lg shadow-[0_1px_3px_rgba(15,23,42,0.06)] overflow-hidden upload-fade-in">
      <div className="flex flex-col lg:flex-row lg:items-stretch">
        {/* Tier 1 - the answer. Score, verdict, one action, nothing else. */}
        <div className="flex-1 min-w-0 px-6 py-7 flex flex-col justify-between gap-6">
          <div className="flex flex-col sm:flex-row sm:items-center gap-6 sm:gap-8">
            <ScoreRing score={score} pct={pct} strokeClass={riskStyle.text} />

            <div className="min-w-0 space-y-3">
              <div className="flex items-center gap-2.5">
                <span className={`${TYPOGRAPHY.badgePill} ${riskStyle.badge} border-transparent`}>
                  {band}
                </span>
                <span className={TYPOGRAPHY.label}>
                  <HelpTerm term="Risk Score">Fraud Risk Score</HelpTerm>
                </span>
              </div>

              <p className="font-display text-xl sm:text-2xl font-semibold tracking-[-0.022em] text-slate-900 leading-snug break-words">
                {data.app_name || data.package_name || 'Unnamed application'}
              </p>

              <p className={`${TYPOGRAPHY.body} max-w-prose`}>{verdictHeadline(data)}</p>

              {overrideReason && (
                <p
                  className={`${TYPOGRAPHY.bodySmall} text-amber-900 bg-amber-50/70 border-l-2 border-amber-400 pl-3 py-1.5 max-w-prose`}
                >
                  {overrideReason}
                </p>
              )}
            </div>
          </div>

          {/* One primary action. The breakdown is a link, not a rival button. */}
          <div className="flex flex-wrap items-center gap-4">
            <DownloadReportButton
              sha256={data.sha256}
              className={`${TYPOGRAPHY.button} bg-blue-700 hover:bg-blue-800 text-white px-5 py-2.5 shadow-sm`}
            />
            <button
              type="button"
              onClick={() => openLedger('full')}
              className={`${TYPOGRAPHY.linkAction} py-2.5`}
            >
              <BarChart2 className="h-3.5 w-3.5" aria-hidden />
              How this score was calculated
            </button>
          </div>
        </div>

        {/* Tier 2 - the reasons, ranked by how much they moved the score. */}
        <div className="w-full lg:w-[22rem] xl:w-[24rem] shrink-0 border-t lg:border-t-0 lg:border-l border-slate-200 bg-slate-50/50 px-5 py-6">
          <RiskInfluenceCard data={data} embedded />
        </div>
      </div>

      {/* Tier 3 - reference. */}
      <CaseDetails data={data} />
    </div>
  );
}
