import { Link } from 'react-router-dom';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import { useInvestigationUI } from '../context/InvestigationUIContext';
import { useCaseLinks } from '../hooks/useCaseLinks';
import type { CaseRoutes } from '../lib/caseRoutes';
import { TYPOGRAPHY } from '../theme/typography';
import CoreFindingsList from '../components/investigation/CoreFindingsList';
import VerdictBlock from '../components/investigation/VerdictBlock';
import AttackStory from '../components/investigation/AttackStory';
import InView from '../components/motion/InView';
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
 * These were four full-width banners stacked one under another — runtime
 * limitation, sandbox resilience, visual impersonation, threat intel — each
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
              className="group flex flex-col gap-1.5 bg-white border border-slate-200 rounded-md px-3.5 py-3 hover:border-slate-300 hover:shadow-[0_1px_3px_rgba(15,23,42,0.06)] transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
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

export default function FraudCard({ data }: { data: FraudCardData | null }) {
  const { investigationBundle } = useAnalysis();
  const { atLeastAnalyst } = useInvestigationUI();
  const { entries: screenshotEntries } = useRuntimeScreenshots(data?.sha256);

  if (!data) return null;

  const stripCounts =
    investigationBundle && screenshotEntries.length > 0
      ? { ...investigationBundle.counts, screenshots: screenshotEntries.length }
      : investigationBundle?.counts;

  return (
    <div className="space-y-8">
      {/*
        Level 1 - the decision, with its qualifier attached.

        Coverage used to render as a separate banner here. On a partial run it
        said the same sentence the verdict's own override note says, so the
        reader met the statement twice before reaching the score and a third
        time in the excluded-axis note. It now sits inside VerdictBlock, once,
        with the trigger-condition detail behind "Why?".
      */}
      <VerdictBlock data={data} />

      {/* Level 2 - the reasons. Status first, then narrative, then findings. */}
      <CaseSignalsRow data={data} />
      <InView as="section">
        <AiExplanation data={data} />
      </InView>

      {/*
        Level 3 - the story.

        This is the fraud workflow the engine has always produced, promoted out
        of the technical view's third tab where it sat below the certificate
        table. It is the most executive-legible artifact in the system and it
        was the most deeply buried thing in it.
      */}
      <InView as="section">
        <AttackStory data={data} screenshots={screenshotEntries} />
      </InView>

      <ExecutiveVisualEvidenceSection data={data} />
      <CoreFindingsList data={data} bundle={investigationBundle} />
      <VisualImpersonationExecutiveCard data={data} />

      {/* Levels 5 and 6 - who this hurts, then the single action it implies. */}
      <InView as="section">
        <BankingImpact data={data} />
      </InView>
      <InView as="section">
        <RecommendedAction data={data} />
      </InView>

      <InvestigationConclusionCard data={data} bundle={investigationBundle} />

      {/*
        Level 3 - reference. Counts are navigation, not evidence, so they sit
        below the findings they lead into; identity metadata sits below both.

        The evidence index is hidden at Summary depth: a bank manager reading
        for twenty seconds does not need a row of record counts, and its
        presence there was part of what made the page read as a dashboard.
      */}
      {atLeastAnalyst && stripCounts && (
        <CaseSummaryStrip riskScore={data.final_risk_score} counts={stripCounts} />
      )}
    </div>
  );
}
