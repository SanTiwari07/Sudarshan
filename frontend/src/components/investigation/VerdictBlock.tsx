import { BarChart2, ShieldCheck, ShieldAlert, SearchX } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { TYPOGRAPHY } from '../../theme/typography';
import { caseSeverity } from '../../theme/severity';
import { getDecision, isInconclusive } from '../../lib/decision';
import {
  formatScore,
  bandOverrideReason,
  verdictHeadline,
  scalePosition,
  BAND_THRESHOLDS,
} from '../../lib/verdictCopy';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import AnimatedNumber from '../motion/AnimatedNumber';
import DownloadReportButton from './DownloadReportButton';
import RiskInfluenceCard from './RiskInfluenceCard';
import CopyButton from '../ui/CopyButton';
import { extractAppMetadata } from '../../lib/analystCopy';
import { assessTrust, type TrustLevel } from '../../lib/trust';

/**
 * The decision, and the three things that qualify it.
 *
 * What changed and why:
 *
 * The page used to open with a score ring. "94" is not a decision - it is an
 * input to one, and it requires the reader to already know the scale, the
 * bands, and which direction is bad. A bank manager given twenty seconds reads
 * a sentence far faster than they interpret a number, so the imperative
 * ("DO NOT INSTALL") is now the largest thing on the page and the score sits
 * beside it as supporting evidence.
 *
 * Confidence was previously only reachable inside a slide-over. It belongs
 * here: a 94 we are unsure about and a 94 we are certain about call for
 * different actions, and hiding that behind a click means most readers never
 * learn which one they are looking at.
 *
 * The app's own name is the page's `h1`. It was a `<p>`, which left every view
 * in the product without a top-level heading.
 */

/**
 * The score, and where it sits on the scale that produced it.
 *
 * Two things were wrong with the ring this replaces.
 *
 * The numeral and the "/ 100" beneath it were centred *as a group*, so the
 * number - the only thing anyone actually reads - sat above the circle's
 * centre and the whole dial looked knocked out of true. They are one baseline
 * row now, which is centred correctly by construction.
 *
 * It also printed `14` where the case header printed `14.1`, which is the
 * exact two-numbers-for-one-score problem `formatScore` exists to prevent.
 *
 * The notches are the engine's own band thresholds, taken from the same list
 * as the sentence beside the dial so the two can never disagree about where
 * Suspicious begins.
 */
function ScoreDial({
  score,
  barClass,
  ringLabel,
}: {
  score: number;
  barClass: string;
  ringLabel: string;
}) {
  const r = 52;
  const sw = 10;
  const c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score));
  const offset = c - (pct / 100) * c;

  const notch = (value: number) => {
    const a = (value / 100) * 2 * Math.PI - Math.PI / 2;
    const inner = r - sw / 2;
    const outer = r + sw / 2;
    return {
      x1: 60 + inner * Math.cos(a),
      y1: 60 + inner * Math.sin(a),
      x2: 60 + outer * Math.cos(a),
      y2: 60 + outer * Math.sin(a),
    };
  };

  return (
    // The accessible name carries the same fact the ring encodes, so the dial
    // is never colour-and-shape only.
    <div
      className="relative h-36 w-36 shrink-0 sm:h-40 sm:w-40"
      role="img"
      aria-label={`Risk score ${formatScore(score)} out of 100. ${ringLabel}.`}
    >
      <svg className="h-full w-full" viewBox="0 0 120 120" aria-hidden>
        <g transform="rotate(-90 60 60)">
          <circle cx="60" cy="60" r={r} fill="none" stroke="currentColor" strokeWidth={sw} className="text-slate-200/90" />
          <circle
            cx="60"
            cy="60"
            r={r}
            fill="none"
            strokeWidth={sw}
            strokeLinecap="round"
            className={`transition-[stroke-dashoffset] duration-700 ease-out ${barClass}`}
            stroke="currentColor"
            strokeDasharray={c}
            strokeDashoffset={offset}
          />
          {/* Drawn last, in the card's own white, so they read as gaps cut
              through whichever of the two arcs is underneath. */}
          {BAND_THRESHOLDS.map((t) => (
            <line key={t.name} {...notch(t.at)} stroke="white" strokeWidth={2.5} />
          ))}
        </g>
      </svg>
      {/* Centred as a single baseline row, not as a stacked group - that is
          what put the numeral above the circle's centre before. */}
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="flex items-baseline">
          <span className="font-sans text-[2.5rem] font-semibold leading-none tracking-[-0.045em] text-slate-900 tabular-nums">
            <AnimatedNumber value={score} decimals={1} />
          </span>
          <span className="ml-0.5 font-sans text-[13px] font-medium leading-none text-slate-400 tabular-nums">
            /100
          </span>
        </div>
      </div>
    </div>
  );
}

/**
 * Confidence as a labelled meter. Never a bare percentage.
 *
 * The label is passed in rather than recomputed: the same three thresholds
 * were written out here and again wherever else confidence was described, so
 * they could drift. `assessTrust` owns them now.
 */
function ConfidenceMeter({ pct, label }: { pct: number; label: string }) {
  const bar =
    label === 'High' ? 'bg-emerald-600' : label === 'Moderate' ? 'bg-amber-500' : 'bg-slate-400';

  return (
    <div className="w-full min-w-[11rem] space-y-1.5 sm:w-56">
      <div className="flex items-baseline justify-between gap-3">
        <span className={TYPOGRAPHY.label}>Analysis confidence</span>
        <span className="font-sans text-[13px] font-semibold text-slate-900">{label}</span>
      </div>
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-slate-200"
        role="img"
        aria-label={`Analysis confidence: ${label}, ${Math.round(pct)} percent`}
      >
        <div className={`h-full rounded-full ${bar}`} style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
      </div>
    </div>
  );
}

/** A fact, or nothing. Placeholders the backend uses for "unknown" are not facts. */
function factValue(v: unknown): string | null {
  const t = typeof v === 'string' ? v.trim() : typeof v === 'number' ? String(v) : '';
  return t && t !== '-' && t !== '—' && t !== 'Unknown' && t !== 'N/A' ? t : null;
}

/**
 * What this application is, in sentences.
 *
 * This band used to restate the caveat already carried by the headline and the
 * excluded-axis line above it - a third telling of "the runtime axis reached no
 * conclusion" on one screen. The reader arriving here has the verdict and wants
 * the artifact: what it asks for, what it ships, what it reaches.
 *
 * Every sentence is built from a field that exists. Nothing is asserted for an
 * absent value, so a sparse case prints fewer lines rather than a paragraph of
 * hedges, and the capability sentence states the negative explicitly when none
 * of the overlay-fraud capabilities are declared - "none of them" is a finding,
 * not a gap.
 */
function describeApk(data: FraudCardData): string[] {
  const meta = extractAppMetadata(data);
  const lines: string[] = [];

  const version = factValue(meta.version) ?? factValue(data.version_name);
  const size = factValue(meta.size) ?? factValue(data.apk_size);
  const sdk = factValue(meta.targetSdk);
  const identity =
    `${data.package_name || data.app_name || 'This package'}` +
    (version ? ` is version ${version}` : ' is the analysed build') +
    (size ? `, ${size} on disk` : '') +
    (sdk ? `, compiled against Android API ${sdk}` : '') +
    '.';
  lines.push(identity);

  const perms = data.all_permissions?.length ?? 0;
  const dangerous = data.dangerous_permissions ?? [];
  if (perms > 0) {
    const named = dangerous
      .map((p) => factValue(p.short) ?? factValue(p.permission))
      .filter(Boolean)
      .slice(0, 3)
      .join(', ');
    lines.push(
      `It requests ${perms} permission${perms === 1 ? '' : 's'}` +
        (dangerous.length > 0
          ? `, ${dangerous.length} of which Android treats as dangerous${named ? ` (${named})` : ''}`
          : ', none of them in Android\'s dangerous set') +
        '.',
    );
  }

  const capabilities = [
    data.has_accessibility_abuse ? 'the accessibility service' : null,
    data.has_sms_read_write ? 'SMS read and write' : null,
    data.has_system_alert_window ? 'drawing over other applications' : null,
  ].filter(Boolean) as string[];
  lines.push(
    capabilities.length > 0
      ? `It claims ${capabilities.join(', ')} — the capabilities overlay banking fraud depends on to read one-time passcodes and cover the screen.`
      : 'It claims none of the accessibility, SMS or screen-overlay capabilities that overlay banking fraud depends on.',
  );

  const activities = data.activities?.length ?? 0;
  const services = data.services?.length ?? 0;
  const receivers = data.receivers?.length ?? 0;
  if (activities + services + receivers > 0) {
    const exported =
      (data.exported_activities?.length ?? 0) +
      (data.exported_services?.length ?? 0) +
      (data.exported_receivers?.length ?? 0);
    lines.push(
      `The package ships ${activities} activities, ${services} services and ${receivers} broadcast receivers` +
        (exported > 0 ? `, ${exported} of them exported to any app on the device` : '') +
        '.',
    );
  }

  const endpoints = data.hardcoded_urls_ips?.length ?? 0;
  const trackers = data.trackers?.length ?? 0;
  if (endpoints > 0 || trackers > 0) {
    const parts = [
      endpoints > 0
        ? `${endpoints} hardcoded URL or IP literal${endpoints === 1 ? '' : 's'} in its code`
        : null,
      trackers > 0 ? `${trackers} third-party tracker${trackers === 1 ? '' : 's'}` : null,
    ].filter(Boolean);
    lines.push(`Static analysis found ${parts.join(' and ')}.`);
  }

  if (data.targets_indian_banks) {
    lines.push('Its strings reference Indian banking applications by package or brand name.');
  }

  const family = factValue(data.family_classification);
  if (family) {
    lines.push(`Threat intelligence files these indicators under the ${family} family.`);
  }

  // Six is the band; past that the facts grid below says it better in less space.
  return lines.slice(0, 6);
}

/** Retained for the confidence meter's wording, which still comes from the run. */
const TRUST_TONE: Record<TrustLevel, { icon: typeof ShieldCheck; ring: string }> = {
  reliable: { icon: ShieldCheck, ring: 'border-emerald-200 bg-emerald-50 text-emerald-700' },
  provisional: { icon: ShieldAlert, ring: 'border-amber-200 bg-amber-50 text-amber-700' },
  unreliable: { icon: SearchX, ring: 'border-slate-300 bg-slate-100 text-slate-700' },
};

function TrustBand({ data }: { data: FraudCardData }) {
  const trust = assessTrust(data);
  const tone = TRUST_TONE[trust.level];
  const Glyph = tone.icon;
  const lines = describeApk(data);

  return (
    <div className="flex flex-col gap-5 border-t border-slate-200 bg-slate-50/70 px-6 py-5 sm:flex-row sm:items-start sm:justify-between sm:gap-10 sm:px-8">
      <div className="flex min-w-0 items-start gap-3.5">
        <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${tone.ring}`}>
          <Glyph className="h-[18px] w-[18px]" aria-hidden />
        </span>
        <div className="min-w-0 max-w-[78ch]">
          <p className={TYPOGRAPHY.label}>About this application</p>
          <ul className="mt-1.5 space-y-1">
            {lines.map((line) => (
              <li key={line} className={`${TYPOGRAPHY.bodySmall} flex gap-2`}>
                <span className="mt-[0.55em] h-1 w-1 shrink-0 rounded-full bg-slate-400" aria-hidden />
                <span>{line}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
      <div className="shrink-0 sm:pt-1">
        <ConfidenceMeter pct={data.confidence ?? 0} label={trust.confidenceLabel} />
      </div>
    </div>
  );
}

/**
 * What this file actually is.
 *
 * This space held a band-override note - "runtime analysis ran but was not
 * conclusive" - which by then was the third statement of the same caveat on one
 * screen, after the verdict headline and the excluded runtime axis.
 *
 * A reader arriving at a verdict needs to know which artifact it applies to:
 * which build, how big, what it can reach, who signed it, and the hash they
 * will paste into their own tooling.
 *
 * Two rules:
 *
 *  - Only facts that exist are rendered. A row of dashes says nothing except
 *    that the platform does not know, which is what the previous metadata panel
 *    did and why it ended up collapsed.
 *  - Nothing here is a pipeline internal. It carried "Analysis
 *    androguard+mobsf", which names the tools that ran rather than telling the
 *    reader anything about the application. Provenance of that kind belongs in
 *    the evidence view, beside the findings each tool produced.
 */
function ApkIdentity({ data }: { data: FraudCardData }) {
  const meta = extractAppMetadata(data);
  const cert = (data.certificate ?? {}) as Record<string, unknown>;

  const clean = factValue;

  /** Pull a readable common name out of an X.509 subject string. */
  const signer = (() => {
    const subject = clean(cert.subject) ?? clean(cert.issuer);
    if (!subject) return null;
    const cn = subject.match(/CN=([^,]+)/i)?.[1]?.trim();
    return cn || (subject.length > 40 ? `${subject.slice(0, 40)}…` : subject);
  })();

  const perms = data.all_permissions?.length ?? 0;
  const dangerous = data.dangerous_permissions?.length ?? 0;
  const components =
    (data.activities?.length ?? 0) +
    (data.services?.length ?? 0) +
    (data.receivers?.length ?? 0);

  const facts: Array<{ label: string; value: string }> = [];
  const push = (label: string, value: string | null) => {
    if (value) facts.push({ label, value });
  };

  // The heading falls back to the package when there is no app name, so
  // repeating it here would print the same string twice, two lines apart.
  if (clean(data.app_name)) push('Package', clean(data.package_name));
  push('Version', clean(meta.version) ?? clean(data.version_name));
  push('Size', clean(meta.size) ?? clean(data.apk_size));
  push('Target SDK', clean(meta.targetSdk));
  push(
    'Permissions',
    perms > 0
      ? `${perms}${dangerous > 0 ? ` · ${dangerous} dangerous` : ''}`
      : null,
  );
  push('Components', components > 0 ? String(components) : null);
  push('Signed by', signer);
  push('Signature', clean(cert.signing_algorithm));
  push('Family', clean(data.family_classification));
  // The band used to be a green pill at the top of the card, where it read as
  // the verdict. It is one classification among the facts below it.
  push('Risk band', clean(data.risk_band));
  if (data.created_at) {
    push(
      'Analysed',
      new Date(data.created_at).toLocaleString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
      }),
    );
  }

  return (
    <div className="pt-1.5 space-y-3">
      {facts.length > 0 && (
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-2">
          {facts.map((f) => (
            <div key={f.label} className="min-w-0">
              <dt className={TYPOGRAPHY.label}>{f.label}</dt>
              <dd
                className={`${TYPOGRAPHY.bodySmall} font-medium text-slate-900 truncate`}
                title={f.value}
              >
                {f.value}
              </dd>
            </div>
          ))}
        </dl>
      )}

      {/* The hash is the identifier an analyst carries to other tooling, so it
          is shown in full and has its own copy control. */}
      <div className="min-w-0 pt-1 border-t border-slate-100">
        <dt className={`${TYPOGRAPHY.label} block mb-0.5`}>SHA-256</dt>
        <dd className="flex items-start gap-1.5 min-w-0">
          <span className={`${TYPOGRAPHY.codeSm} break-all`}>{data.sha256}</span>
          <CopyButton
            value={data.sha256}
            className="h-4 w-4 p-0 shrink-0 mt-0.5 text-slate-400 hover:text-slate-700"
          />
        </dd>
      </div>
    </div>
  );
}

export default function VerdictBlock({ data }: { data: FraudCardData }) {
  const { openLedger } = useInvestigationUI();

  const inconclusive = isInconclusive(data);
  const decision = getDecision(data);
  const token = caseSeverity(data.risk_band, inconclusive);
  const overrideReason = bandOverrideReason(data);

  return (
    <section aria-label="Verdict" className="space-y-4">
      {/*
        The verdict is one card in three regions, divided by hairlines: what to
        do, how much to believe it, and what artifact it applies to.

        Two things this composition fixes.

        The card was coloured by the *band*, so this page opened with a green
        SAFE pill directly above a headline reading "coverage incomplete". A
        reader gets one impression from a hero and green was the wrong one -
        the band describes where the score landed, not whether the case is
        settled. The pill follows the decision now, and the band survives as a
        labelled fact in the identity strip, which is what it is. The coloured
        rail down the left edge went with it: a card that is already headed by
        a decision pill does not need a second, wordless copy of the same
        signal painted beside it.

        The headline was also set in capitals. `theme/typography.ts` reserves
        uppercase for badges and says why: when everything shouts, nothing
        ranks. It is sentence case, and it is still the largest thing here.
      */}
      <div className="overflow-hidden rounded-xl border border-slate-300 bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04),0_10px_28px_-14px_rgba(15,23,42,0.22)]">
        <div className="flex">
          <div className="min-w-0 flex-1">
            {/* ── What to do ─────────────────────────────────────────────── */}
            <div className="flex flex-col-reverse gap-6 px-6 py-7 sm:flex-row sm:items-start sm:gap-10 sm:px-8">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <span className={`${TYPOGRAPHY.badgePill} ${decision.badgeClass} border-transparent`}>
                    {decision.action}
                  </span>
                  <span className={TYPOGRAPHY.label}>
                    {token.label} band · {scalePosition(data.final_risk_score)}
                  </span>
                </div>

                <p className="mt-3 font-sans text-[1.75rem] font-semibold leading-[1.15] tracking-[-0.028em] text-slate-900 sm:text-[2.125rem]">
                  {decision.headline}
                </p>

                <h1 className={`${TYPOGRAPHY.h3} mt-2 break-words text-slate-600`}>
                  {data.app_name || data.package_name || 'Unnamed application'}
                </h1>

                <p className="mt-3 max-w-[64ch] font-sans text-base leading-relaxed text-slate-700">
                  {inconclusive ? decision.rationale : verdictHeadline(data)}
                </p>

                {overrideReason && (
                  <p className={`${TYPOGRAPHY.bodySmall} mt-2 max-w-[64ch] text-slate-600`}>
                    {overrideReason}
                  </p>
                )}
              </div>

              <div className="flex shrink-0 items-center gap-5 sm:flex-col sm:items-center sm:gap-2">
                <ScoreDial
                  score={data.final_risk_score}
                  barClass={token.fg}
                  ringLabel={`${token.label}. ${token.meaning}`}
                />
                <p className={`${TYPOGRAPHY.label} text-center`}>Fraud risk score</p>
              </div>
            </div>

            {/* ── How much to believe it ─────────────────────────────────── */}
            <TrustBand data={data} />

            {/* ── Which artifact it applies to ───────────────────────────── */}
            <div className="border-t border-slate-200 px-6 py-6 sm:px-8">
              <ApkIdentity data={data} />

              <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-3">
                <DownloadReportButton
                  sha256={data.sha256}
                  className={`${TYPOGRAPHY.button} bg-blue-700 px-5 py-2.5 text-white shadow-sm hover:bg-blue-800`}
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
          </div>
        </div>
      </div>

      {/* Why the score is what it is, ranked. Full width, so the axes can be
          read against each other rather than down a narrow column. */}
      <RiskInfluenceCard data={data} />
    </section>
  );
}
