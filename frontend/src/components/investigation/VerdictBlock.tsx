import { BarChart2 } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { TYPOGRAPHY } from '../../theme/typography';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import DownloadReportButton from './DownloadReportButton';
import RiskInfluenceCard from './RiskInfluenceCard';
import CopyButton from '../ui/CopyButton';
import { extractAppMetadata } from '../../lib/analystCopy';

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



/** A fact, or nothing. Placeholders the backend uses for "unknown" are not facts. */
function factValue(v: unknown): string | null {
  const t = typeof v === 'string' ? v.trim() : typeof v === 'number' ? String(v) : '';
  return t && t !== '-' && t !== '-' && t !== 'Unknown' && t !== 'N/A' ? t : null;
}


/** Retained for the confidence meter's wording, which still comes from the run. */


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
    return cn || (subject.length > 40 ? `${subject.slice(0, 40)}�` : subject);
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
      ? `${perms}${dangerous > 0 ? ` � ${dangerous} dangerous` : ''}`
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

  return (
    <section aria-label="Verdict" className="space-y-4">
      {/*
        No verdict statement here any more.
        
        The decision, its headline, the confidence meter and the plain-language
        description of the build were removed at the product owner's direction.
        What survives of that information, and where:
        
          - the score, its band and the confidence level are the hero readings
            at the top of the page;
          - the action the verdict implies is RecommendedAction, directly below
            this section;
          - permissions, family and risk band are facts in the identity band at
            the foot of this section.
        
        What is no longer anywhere on the case page is the sentence explaining
        *why* an inconclusive run is not a clean one, and the five-line plain
        description of the application. Both were unique to this block.
      */}
      {/*
        The three axes, side by side, across the width the verdict used to
        share with them. Each is its own card: they are three separate
        readings that are meant to be compared, and comparison across a row is
        what a column of stacked panels makes hardest.
      */}
      <div>
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <div>
            <p className={TYPOGRAPHY.h2}>What influenced the score</p>
            <p className={`${TYPOGRAPHY.caption} mt-0.5`}>
              Ranked by how much each raised the risk score.
            </p>
          </div>
          <button
            type="button"
            onClick={() => openLedger('full')}
            className={TYPOGRAPHY.linkAction}
          >
            <BarChart2 className="h-3.5 w-3.5" aria-hidden />
            How this score was calculated
          </button>
        </div>
        <RiskInfluenceCard data={data} bare />
      </div>

      {/*
        Which artifact this applies to, and what to do with it - one band, the
        full width of both cards above.

        This was the last region inside the verdict card, which made the left
        column much taller than the right and left the row visibly lopsided.
        It also belongs to neither half: the package identity and the report
        are about the case as a whole, not about the decision or about the
        arithmetic. As its own block underneath, it squares the two columns off
        and reads as the footer of the pair rather than the tail of one of them.
      */}
      <div className="rounded-[var(--card-radius)] border border-slate-200 bg-white p-5 shadow-[var(--card-elevation)] sm:p-6">
        <ApkIdentity data={data} />

        <div className="mt-5 border-t border-slate-200 pt-5">
          <DownloadReportButton
            sha256={data.sha256}
            className={`${TYPOGRAPHY.button} bg-blue-700 px-5 py-2.5 text-white hover:bg-blue-800`}
          />
        </div>
      </div>
    </section>
  );
}

