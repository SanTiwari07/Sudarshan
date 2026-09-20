import { Link } from 'react-router-dom';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import { useCaseLinks } from '../hooks/useCaseLinks';
import type { CaseRoutes } from '../lib/caseRoutes';
import { TYPOGRAPHY } from '../theme/typography';
import { assessTrust } from '../lib/trust';
import { confidenceTone } from '../theme/riskTone';
import CoreFindingsList from '../components/investigation/CoreFindingsList';
import VerdictBlock from '../components/investigation/VerdictBlock';
import ScoreGauge from '../components/investigation/ScoreGauge';
import AttackStory from '../components/investigation/AttackStory';
import InView from '../components/motion/InView';
import AnalysisTabs, { type AnalysisTab } from '../components/investigation/AnalysisTabs';
import CaseSummaryStrip from '../components/investigation/CaseSummaryStrip';
import AiExplanation from '../components/investigation/AiExplanation';
import BankingImpact from '../components/investigation/BankingImpact';
import RecommendedAction from '../components/investigation/RecommendedAction';
import ExecutiveVisualEvidenceSection from '../components/investigation/ExecutiveVisualEvidenceSection';
import VisualImpersonationExecutiveCard from '../components/investigation/VisualImpersonationExecutiveCard';
import InvestigationConclusionCard from '../components/investigation/InvestigationConclusionCard';
import { useRuntimeScreenshots } from '../hooks/useRuntimeScreenshots';
import {
  ShieldCheck,
  ShieldAlert,
  ChevronRight,
} from 'lucide-react';

type Signal = {
  key: string;
  icon: React.ElementType;
  tone: 'positive' | 'caution' | 'neutral';
  title: string;
  detail: string;
  to: string;
  cta: string;
};

/**
 * Case signals.
 *
 * These were four full-width banners stacked one under another - runtime
 * limitation, sandbox resilience, visual impersonation, threat intel - each
 * shouting at exactly the same volume as the verdict above them. They are all
 * the same kind of thing: a one-line status with a link to the page that
 * proves it. So they render as one row of tiles, and the page gets its
 * hierarchy back.
 */
function buildSignals(data: FraudCardData, links: CaseRoutes): Signal[] {
  const signals: Signal[] = [];
  const frs = data.frs_breakdown;

  /*
   * A stage of the analysis that did not produce a result is not a case signal.
   *
   * "Runtime limited - runtime inconclusive, no runtime evidence raised the
   * score" was the fourth place on this page saying the same thing, after the
   * verdict headline, the band-override note and the Runtime behaviour axis
   * directly above it, which states the same fact and links to the same place.
   * Only a runtime run that actually produced scored evidence is a signal.
   */
  if (frs?.dynamic_ran && frs.dynamic_conclusive) {
    signals.push({
      key: 'runtime',
      icon: ShieldCheck,
      tone: 'positive',
      title: 'Runtime confirmed',
      detail: 'Behaviour was observed and scored in the sandbox.',
      to: links.evidence,
      cta: 'Inspect live analysis',
    });
  }

  const actions = data.dynamic_analysis?.resilience_actions;
  if (data.dynamic_available && actions && actions.length > 0) {
    signals.push({
      key: 'resilience',
      icon: ShieldAlert,
      tone: 'neutral',
      title: `${actions.length} evasion ${actions.length === 1 ? 'case' : 'cases'} defeated`,
      detail: actions.map((a) => a.title).join(' · '),
      to: links.evidence,
      cta: 'View resilience controls',
    });
  }

  return signals;
}

const SIGNAL_ICON: Record<Signal['tone'], string> = {
  positive: 'text-emerald-600',
  caution: 'text-amber-600',
  neutral: 'text-slate-500',
};

function CaseSignalsRow({ data }: { data: FraudCardData }) {
  const links = useCaseLinks();
  const signals = buildSignals(data, links);
  if (signals.length === 0) return null;

  return (
    <section aria-label="Case signals">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {signals.map((signal) => {
          const Icon = signal.icon;
          return (
            <Link
              key={signal.key}
              to={signal.to}
              className="group flex flex-col gap-1.5 bg-white border border-slate-200 rounded-lg px-3.5 py-3 hover:border-slate-300 hover:shadow-[0_1px_3px_rgba(15,23,42,0.06)] transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              <span className="flex items-center gap-2">
                <Icon className={`h-3.5 w-3.5 shrink-0 ${SIGNAL_ICON[signal.tone]}`} aria-hidden />
                <span className={TYPOGRAPHY.h3}>{signal.title}</span>
              </span>
              <span className={`${TYPOGRAPHY.bodySmall} line-clamp-2`}>{signal.detail}</span>
              <span className={`${TYPOGRAPHY.linkAction} mt-auto pt-1`}>
                {signal.cta}
                <ChevronRight
                  className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5"
                  aria-hidden
                />
              </span>
            </Link>
          );
        })}
      </div>
    </section>
  );
}

/*
 * Tier 1 - the numbers a reader must have inside two seconds.
 *
 * Four, full width, above everything, on no card at all. Separated by hairline
 * rules rather than boxed, because a border around a hero number makes it a
 * component; without one it is simply the top of the page.
 *
 * Uppercase survives here and in table column headers, and nowhere else. The
 * type rules reserve caps for badges, and the reason given is that when every
 * label shouts nothing ranks - which was true when card titles, section
 * titles, buttons and labels were all uppercase at once. Used for exactly one
 * tier it does the opposite job: it marks these four as a different kind of
 * thing from every other label on the page.
 *
 * The score is here and no longer inside the verdict card. It was drawn three
 * times on one screen - case bar ring, hero dial, and this - and a hierarchy
 * with the same number at three sizes has no hierarchy in it.
 */
type HeroReading = {
  label: string;
  value: string;
  valueClass?: string;
  context: string;
  segments: { pct: number; fill: string }[];
};

/** One supporting reading: label, value, its track, and what the track shows. */
function Reading({ reading, className = '' }: { reading: HeroReading; className?: string }) {
  return (
    <div className={`min-w-0 ${className}`}>
      <p className="font-sans text-[12px] font-medium uppercase tracking-[0.12em] text-slate-500">
        {reading.label}
      </p>
      <p
        className={`mt-3 font-sans text-[1.75rem] font-medium leading-none tracking-[-0.035em] tabular-nums ${
          reading.valueClass ?? 'text-slate-900'
        }`}
      >
        <span className="block truncate pb-1 -mb-1">{reading.value}</span>
      </p>
      {reading.segments.length > 0 && (
        /* A 2px gap between fills, so neighbouring segments never read as one
           continuous bar. */
        <div className="mt-3 flex h-1 w-full gap-0.5 overflow-hidden rounded-full bg-slate-100">
          {reading.segments.map((seg, i) => (
            <div
              key={i}
              className={`h-full rounded-full ${seg.fill}`}
              style={{ width: `${Math.max(0, Math.min(100, seg.pct))}%` }}
            />
          ))}
        </div>
      )}
      <p className="mt-2.5 font-sans text-[13px] leading-tight tracking-[0.01em] text-slate-500">
        {reading.context}
      </p>
    </div>
  );
}

function HeroMetrics({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: ReturnType<typeof useAnalysis>['investigationBundle'];
}) {
  const trust = assessTrust(data);
  const records = bundle?.counts.evidenceRecords ?? 0;

  const staticFindings = bundle?.counts.staticFindings ?? 0;
  const runtimeBehaviours = bundle?.counts.runtimeBehaviors ?? 0;

  /*
   * Each reading gets a track, and every track is a ratio the data actually
   * states. Confidence is a percentage the run reports; permissions are a
   * count within a count; evidence records are two named sources against the
   * whole. Nothing here is a trend, because a case has no history to trend
   * against - a sparkline on any of these would be a line I drew, not a line
   * the pipeline measured.
   */
  /*
   * The score sits between its two supporting readings.
   *
   * Centre is the strongest slot on a symmetrical row, and the score is what
   * the page is for; how much of the pipeline reported sits to its left and
   * the number of records behind it to its right, so the eye lands on the
   * verdict first and finds its qualifiers either side without moving far.
   *
   * Their values are set one step below the score. They were larger than it,
   * which put the loudest number on the row on the reading that supports the
   * answer rather than on the answer.
   */
  const confidence = {
      label: 'Analysis confidence',
      value: trust.confidenceLabel,
      // The value is the state, so it wears the state's tone - in the darker
      // step that clears 4.5:1, since amber-500 as text is only 2.15:1.
      valueClass: confidenceTone(trust.confidenceLabel).text,
      context: 'How much of the pipeline reported',
      segments: [
        {
          pct: Math.max(0, Math.min(100, data.confidence ?? 0)),
          fill: confidenceTone(trust.confidenceLabel).bar,
        },
      ],
  };

  const evidence = {
      label: 'Evidence records',
      value: String(records),
      valueClass: undefined as string | undefined,
      context:
        records > 0
          ? `${staticFindings} static · ${runtimeBehaviours} runtime`
          : 'Nothing recorded',
      segments:
        records > 0
          ? [
              { pct: (staticFindings / records) * 100, fill: 'bg-slate-700' },
              { pct: (runtimeBehaviours / records) * 100, fill: 'bg-slate-400' },
            ]
          : [],
  };

  return (
    /*
      The gauge leads, the remaining readings sit beside it.
      
      The score was a number in this strip and a second drawing underneath it,
      which is the duplication the tier rules exist to stop. The arc is now the
      only place it is stated, and it earns the leftmost slot because position
      beats size: top-left is the highest-priority place on the page.
    */
    <section
      aria-label="Case at a glance"
      className="grid grid-cols-1 items-center gap-y-8 border-b border-slate-200 pb-8 lg:grid-cols-3 lg:gap-y-0 lg:divide-x lg:divide-slate-200"
    >
      <Reading reading={confidence} className="lg:pr-10" />

      <div className="flex justify-center lg:px-10">
        <ScoreGauge data={data} />
      </div>

      <Reading reading={evidence} className="lg:pl-10" />
    </section>
  );
}

export default function FraudCard({ data }: { data: FraudCardData | null }) {
  const { investigationBundle } = useAnalysis();
  const { entries: screenshotEntries } = useRuntimeScreenshots(data?.sha256);

  if (!data) return null;

  const stripCounts =
    investigationBundle && screenshotEntries.length > 0
      ? { ...investigationBundle.counts, screenshots: screenshotEntries.length }
      : investigationBundle?.counts;

  /*
   * The case in three bands, not eleven stacked sections.
   *
   * Every section here was full-width and always open, so reading a case meant
   * scrolling through the verdict, the narrative, the story, the visual
   * evidence, the findings, the impersonation card, the impact, the action,
   * the conclusion and the index - in that order, every time, whether or not
   * the reader wanted any of them. A analyst checking one number scrolled past
   * eight sections to reach it.
   *
   * The split is by question, not by component:
   *
   *   Band 1  the answer.  Verdict, signals, and the action it implies. Always
   *           on screen, because it is what the page is for.
   *   Band 2  the case for it, tabbed. One panel open at a time, so the depth
   *           is all reachable without any of it costing height by default.
   *
   * Tabs rather than a two-column grid because several of these sections carry
   * their own `md:grid-cols-3` inside them - laid side by side they would each
   * try to fit three columns into half a viewport.
   */
  const caseTabs: AnalysisTab[] = [
    {
      id: 'story',
      label: 'The story',
      anchors: ['attack-story'],
      content: (
        <div className="space-y-8">
          <InView as="section">
            <AiExplanation data={data} />
          </InView>
          <InView as="section">
            <AttackStory data={data} screenshots={screenshotEntries} />
          </InView>
        </div>
      ),
    },
    {
      id: 'findings',
      label: 'Findings',
      count: investigationBundle?.counts.evidenceRecords,
      content: (
        <div className="space-y-8">
          <CoreFindingsList data={data} bundle={investigationBundle} />
          <VisualImpersonationExecutiveCard data={data} />
        </div>
      ),
    },
    {
      id: 'visual',
      label: 'Visual evidence',
      count: screenshotEntries.length || undefined,
      content: <ExecutiveVisualEvidenceSection data={data} />,
    },
    {
      id: 'impact',
      label: 'Impact',
      content: (
        <InView as="section">
          <BankingImpact data={data} />
        </InView>
      ),
    },
    {
      id: 'conclusion',
      label: 'Conclusion',
      content: (
        <div className="space-y-8">
          <InvestigationConclusionCard data={data} bundle={investigationBundle} />
          {stripCounts && (
            <CaseSummaryStrip riskScore={data.final_risk_score} counts={stripCounts} />
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-8">
      {/*
        Band 1 - the decision, with its qualifier attached.

        Coverage used to render as a separate banner here. On a partial run it
        said the same sentence the verdict's own override note says, so the
        reader met the statement twice before reaching the score and a third
        time in the excluded-axis note. It now sits inside VerdictBlock, once,
        with the trigger-condition detail behind "Why?".
      */}
      <HeroMetrics data={data} bundle={investigationBundle} />

      <VerdictBlock data={data} />
      <CaseSignalsRow data={data} />

      {/*
        The single action the verdict implies stays above the tabs. It was the
        ninth section down; a recommendation nobody scrolls to is not a
        recommendation.
      */}
      <InView as="section">
        <RecommendedAction data={data} />
      </InView>

      {/* Band 2 - everything that supports the answer above. */}
      {/*
        Tier 4 - reference. It sits below everything, it is titled at label
        weight rather than as a heading, and it opens closed panels. Nothing
        here should survive the squint test; if it competes with the hero strip
        the page has two first impressions and therefore none.
      */}
      <section aria-label="Supporting detail" className="pt-2">
        <p className="mb-4 font-sans text-[12px] font-medium uppercase tracking-[0.12em] text-slate-400">
          The case for this verdict
        </p>
        <AnalysisTabs tabs={caseTabs} urlParam="detail" />
      </section>
    </div>
  );
}

