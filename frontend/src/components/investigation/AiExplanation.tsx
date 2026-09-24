import { Sparkles, Info } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import {
  buildOverallAssessmentParagraphs,
  buildCustomerAndBankingImpact,
  narrativeSource,
} from '../../lib/executiveIntelligence';
import { buildWhatThisMeans } from '../../lib/analystCopy';
import { getDecision } from '../../lib/decision';
import { TYPOGRAPHY } from '../../theme/typography';

/**
 * The AI explanation layer.
 *
 * Two inversions from what this replaced.
 *
 * 1. Provenance was backwards. The old card was branded AI - Sparkles icon,
 *    "EXECUTIVE ASSESSMENT" heading - but three of its four sections were
 *    deterministic template strings built in executiveIntelligence.ts, while
 *    the actual Gemini output was folded in unattributed and its own
 *    `confidence` and `analysis_note` were discarded. A reader could not tell
 *    which sentences a model wrote. Now the AI badge appears only when a model
 *    genuinely produced the text, and says so when it did not.
 *
 * 2. Authority was implied. The deterministic risk engine owns the verdict;
 *    the model explains it. That relationship is stated on the card rather than
 *    left to be inferred, because "AI says this is malware" and "here is an
 *    explanation of why the engine scored this" are different claims and only
 *    one of them is true.
 *
 * Structure is fixed at four short blocks - what we found, what it means, why
 * it matters, what to do - rather than a paragraph dump. The old card ran three
 * full-width paragraphs at the top of a 1920px container.
 */

const SOURCE_META = {
  ai: {
    badge: 'AI explanation',
    icon: Sparkles,
    iconClass: 'text-blue-700 bg-blue-50',
    note: 'Generated from SUDARSHAN evidence. The verdict itself is produced by the deterministic risk engine.',
  },
  stored: {
    badge: 'Stored explanation',
    icon: Sparkles,
    iconClass: 'text-slate-600 bg-slate-100',
    note: 'Recorded when this case was first analysed. The verdict is produced by the deterministic risk engine.',
  },
  derived: {
    badge: 'Explanation unavailable',
    icon: Info,
    iconClass: 'text-slate-600 bg-slate-100',
    note: 'No AI narrative could be generated for this case. The summary below is derived directly from the engine\'s own findings, and the verdict is unaffected.',
  },
} as const;

/** One labelled block. Capped by design, not by chance. */
function Block({ label, children }: { label: string; children: React.ReactNode }) {
  if (!children) return null;
  return (
    <div className="space-y-1">
      <h3 className={TYPOGRAPHY.label}>{label}</h3>
      <p className={`${TYPOGRAPHY.body} max-w-[64ch]`}>{children}</p>
    </div>
  );
}

export default function AiExplanation({ data }: { data: FraudCardData }) {
  const source = narrativeSource(data);
  const meta = SOURCE_META[source];
  const Icon = meta.icon;

  const paragraphs = buildOverallAssessmentParagraphs(data);
  const decision = getDecision(data);
  const intel = data.intelligence_report;

  /*
   * Each block has its own source rather than a slice of one narrative.
   *
   * Mapping the four blocks positionally onto paragraphs[0..2] looked tidy but
   * silently emptied two of them: `splitIntoParagraphs` returns a single
   * element for a narrative of three sentences or fewer, which is the common
   * case, so "What it means" and "Why it matters" simply vanished. Every block
   * now falls back to a deterministic derivation that always exists.
   */
  const whatWeFound = paragraphs[0];
  const whatItMeans = paragraphs[1] || buildWhatThisMeans(data);
  const whyItMatters =
    intel?.banking_impact_assessment?.trim() ||
    intel?.fraud_objective?.trim() ||
    paragraphs[2] ||
    buildCustomerAndBankingImpact(data).bankingImpact;

  if (!whatWeFound) return null;

  return (
    <section
      aria-label="Explanation"
      className="rounded-lg border border-slate-200 bg-white overflow-hidden"
    >
      <header className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-slate-200">
        <div className="flex items-center gap-2.5">
          <span className={`p-1.5 rounded-lg shrink-0 ${meta.iconClass}`}>
            <Icon className="h-4 w-4" aria-hidden />
          </span>
          <h2 className={TYPOGRAPHY.h3}>{meta.badge}</h2>
        </div>
        {source === 'ai' && intel?.confidence && (
          <span className={TYPOGRAPHY.label}>Model confidence: {intel.confidence}</span>
        )}
      </header>

      {/*
        Two columns from `lg` up.
        
        Each block caps its measure at 68 characters, which is right for
        reading and wrong for a full-width card: four stacked blocks left the
        right half of the card empty down its whole height. Pairing them fills
        the card without lengthening the line.
      */}
      <div className="px-5 py-5 grid grid-cols-1 lg:grid-cols-2 gap-x-10 gap-y-5">
        <Block label="What we found">{whatWeFound}</Block>
        <Block label="What it means">{whatItMeans}</Block>
        <Block label="Why it matters">{whyItMatters}</Block>
        <Block label="What to do">{decision.rationale}</Block>

        {intel?.analysis_note && (
          <p className={`${TYPOGRAPHY.caption} lg:col-span-2`}>{intel.analysis_note}</p>
        )}
      </div>

      {/*
        The authority statement. Structural, not optional: it is the difference
        between an explanation of a verdict and a verdict of its own.
      */}
      <footer className="px-5 py-3 border-t border-slate-200 bg-slate-50/70">
        <p className={`${TYPOGRAPHY.caption} flex items-start gap-2 max-w-[80ch]`}>
          <Info className="h-3.5 w-3.5 shrink-0 mt-px text-slate-400" aria-hidden />
          {meta.note}
        </p>
      </footer>
    </section>
  );
}
