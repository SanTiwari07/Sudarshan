import { useState } from 'react';
import {
  Calendar, Copy, Check, Building2, HardDrive, KeyRound, Smartphone, Cpu, Tag, Fingerprint, Sparkles,
} from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { caseSeverity } from '../../theme/severity';
import { isInconclusive } from '../../lib/decision';
import { formatScore, verdictHeadline } from '../../lib/verdictCopy';
import InfoTip from '../ui/InfoTip';
import DownloadReportButton from '../investigation/DownloadReportButton';

/** One plain sentence per band: what the verdict means for the reader. */
function verdictMeaning(band: string | undefined, inconclusive: boolean): string {
  if (inconclusive) return 'The analysis could not run far enough to give a reliable verdict. Treat this app as unverified.';
  const b = (band || '').toLowerCase();
  if (b.includes('critical')) return 'This app shows confirmed banking-malware behaviour. Block it and treat any device it is on as compromised.';
  if (b.includes('high')) return 'This app shows strong signs of banking malware. It should not be installed or allowed on the network.';
  if (b.includes('suspicious')) return 'Some of this app’s behaviour resembles fraud apps. Review the findings before trusting it.';
  if (b.includes('safe')) return 'No meaningful signs of banking malware were found in this app.';
  return 'Sudarshan has scored this app; see the findings below for the details.';
}

/** First couple of sentences of the AI narrative - enough to orient, not a wall. */
function shortNarrative(text: string | undefined, sentences = 2): string | null {
  if (!text) return null;
  // A narrative that is really a pipeline status message (the LLM call failed
  // and the backend wrote the error in its place) is not a summary. Show
  // nothing rather than an error string dressed up as prose.
  if (/bypass|auth_failed|invalid_argument|providers? failed|api key|quota exceeded/i.test(text)) return null;
  text = text.replace(/^deterministic threat assessment:\s*/i, '');
  const parts = text.replace(/\s+/g, ' ').trim().match(/[^.!?]+[.!?]+/g);
  if (!parts) return text.trim() || null;
  return parts.slice(0, sentences).join(' ').trim();
}

function ScoreRing({ score, colour, inconclusive }: { score: number; colour: string; inconclusive: boolean }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const f = Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className={`relative h-36 w-36 shrink-0 ${inconclusive ? 'text-slate-300' : colour}`}>
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90" aria-hidden>
        <circle cx="60" cy="60" r={r} fill="none" strokeWidth="10" stroke="currentColor" className="text-slate-100" />
        {!inconclusive && (
          <circle
            cx="60" cy="60" r={r} fill="none" strokeWidth="10" strokeLinecap="round" stroke="currentColor"
            strokeDasharray={c} strokeDashoffset={c * (1 - f)}
            className="transition-[stroke-dashoffset] duration-700 ease-out"
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-semibold tracking-[-0.04em] text-slate-900 tabular-nums leading-none">
          {inconclusive ? '–' : formatScore(score)}
        </span>
        <span className="mt-1 text-xs font-medium text-slate-400">out of 100</span>
      </div>
    </div>
  );
}

function Fact({ icon: Icon, label, value, mono = false }: { icon: typeof Tag; label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0 rounded-xl bg-slate-50 px-4 py-3">
      <dt className="flex items-center gap-1.5 text-xs font-medium text-slate-500">
        <Icon className="h-3.5 w-3.5" aria-hidden />
        {label}
      </dt>
      <dd className={`mt-1 truncate text-sm font-semibold text-slate-900 ${mono ? 'font-mono' : ''}`}>{value}</dd>
    </div>
  );
}

export default function CaseHeader({ data }: { data: FraudCardData }) {
  const [copiedSha, setCopiedSha] = useState(false);
  const inconclusive = isInconclusive(data);
  const token = caseSeverity(data.risk_band, inconclusive);
  const score = Number(data.final_risk_score) || 0;

  const targetBank =
    data.vide?.visual_impersonation_institution ||
    data.vide?.corpus_compare?.institution_display ||
    data.intelligence_report?.affected_banking_apps?.[0] ||
    (data as any).target_bank;

  const family = data.family_classification && data.family_classification !== 'Unknown'
    ? data.family_classification
    : null;
  const capabilities = verdictHeadline(data);
  const aiSummary = shortNarrative(
    data.executive_view?.plain_english_narrative || data.intelligence_report?.plain_english_narrative,
  );

  // Only facts the analysis actually produced - a grid of "Unknown" tiles
  // tells the reader nothing and looks broken.
  const facts = [
    { icon: Tag, label: 'Version', value: data.version_name || 'Unknown' },
    { icon: HardDrive, label: 'APK size', value: data.apk_size || 'Unknown' },
    { icon: KeyRound, label: 'Permissions', value: `${data.all_permissions?.length || 0} declared` },
    {
      icon: Calendar,
      label: 'Analysed',
      value: data.created_at
        ? new Date(data.created_at).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
        : 'Unknown',
    },
    { icon: Cpu, label: 'Engine', value: data.analysis_mode ? data.analysis_mode.replace(/\+/g, ' + ') : undefined },
    { icon: Fingerprint, label: 'Malware family', value: family || 'None identified' },
  ].filter((f): f is { icon: typeof Tag; label: string; value: string } => Boolean(f.value));

  const handleCopyHash = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (data.sha256) {
      navigator.clipboard.writeText(data.sha256);
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Identity + score */}
      <div className="flex flex-col-reverse gap-6 md:flex-row md:items-center md:justify-between">
        <div className="flex items-start gap-4 min-w-0">
          <span className={`hidden sm:flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl ${token.bg} ${token.fg}`}>
            <Smartphone className="h-7 w-7" aria-hidden />
          </span>
          <div className="min-w-0">
            <h1 className="text-2xl sm:text-3xl font-semibold tracking-[-0.03em] text-slate-900 break-words">
              {data.app_name && data.app_name !== data.package_name ? data.app_name : data.package_name}
            </h1>
            {data.app_name && data.app_name !== data.package_name && (
              <p className="mt-0.5 font-mono text-sm text-slate-500 break-all">{data.package_name}</p>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-semibold ${token.bg} ${token.fg}`}>
                <span className="h-2 w-2 rounded-full bg-current" aria-hidden />
                {token.label}
              </span>
              {family && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-3 py-1 text-sm font-medium text-slate-700">
                  <Tag className="h-3.5 w-3.5" aria-hidden />
                  {family}
                </span>
              )}
              {targetBank && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 px-3 py-1 text-sm font-medium text-red-700">
                  <Building2 className="h-3.5 w-3.5" aria-hidden />
                  Targets {targetBank}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4 md:flex-col md:items-center md:gap-1 shrink-0">
          <ScoreRing score={score} colour={token.fg} inconclusive={inconclusive} />
          <span className="flex items-center gap-1 text-sm font-medium text-slate-500">
            Risk score
            <InfoTip
              align="right"
              label="the risk score"
              text="A 0-100 fraud risk score from Sudarshan's fixed-rule engine. 0-34 is safe, 35-59 suspicious, 60-79 high risk and 80+ critical. The same app always gets the same score."
            />
          </span>
        </div>
      </div>

      {/* What this means */}
      <div className="rounded-2xl border border-slate-200/80 bg-slate-50/60 p-5 space-y-3">
        <p className="text-base font-semibold text-slate-900 leading-snug">
          {verdictMeaning(data.risk_band, inconclusive)}
        </p>
        {capabilities && <p className="text-sm text-slate-600 leading-relaxed">{capabilities}</p>}
        {aiSummary && (
          <div className="flex gap-3 border-t border-slate-200/80 pt-3">
            <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-blue-50 text-blue-600">
              <Sparkles className="h-3.5 w-3.5" aria-hidden />
            </span>
            <p className="text-sm text-slate-600 leading-relaxed">
              <span className="font-semibold text-slate-800">AI summary. </span>
              {aiSummary}
              <span className="ml-1 inline-flex align-middle">
                <InfoTip
                  label="the AI summary"
                  text="Written by the AI assistant from this case's evidence to help you orient. It explains the result but never changes the score or verdict."
                />
              </span>
            </p>
          </div>
        )}
      </div>

      {/* Basic facts */}
      <div className="flex flex-col gap-3">
        {/* SHA-256 Row */}
        <div className="flex items-center gap-3 min-w-0 rounded-xl bg-slate-50 px-4 py-3">
          <div className="flex items-center gap-1.5 text-xs font-medium text-slate-500 shrink-0">
            <Fingerprint className="h-3.5 w-3.5" aria-hidden />
            SHA-256
          </div>
          <div className="font-mono text-sm text-slate-800 truncate flex-1 min-w-0">{data.sha256}</div>
          <button
            type="button"
            onClick={handleCopyHash}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-white px-2.5 py-1 text-xs font-semibold text-slate-700 ring-1 ring-inset ring-slate-200 hover:bg-slate-100 transition-colors"
            title="Copy full SHA-256"
          >
            {copiedSha ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
            {copiedSha ? 'Copied' : 'Copy'}
          </button>
        </div>

        {/* Dynamic Facts Grid */}
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6">
          {facts.map((f) => (
            <Fact key={f.label} icon={f.icon} label={f.label} value={f.value} />
          ))}
        </dl>
      </div>

      {/* Primary Actions */}
      {data.sha256 && (
        <div className="flex flex-col sm:flex-row justify-start pt-2 gap-3">
          <DownloadReportButton
            sha256={data.sha256}
            label="Download Summary PDF"
            className="inline-flex w-full sm:w-auto items-center justify-center gap-2 rounded-xl bg-blue-600 px-6 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 transition-all active:scale-95"
          />
        </div>
      )}
    </div>
  );
}
