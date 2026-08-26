import { Link } from 'react-router-dom';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import { useInvestigationUI } from '../context/InvestigationUIContext';
import { dynamicRuntimeLabel } from '../lib/analystCopy';
import { TYPOGRAPHY } from '../theme/typography';
import CoreFindingsList from '../components/investigation/CoreFindingsList';
import VerdictBlock from '../components/investigation/VerdictBlock';
import CoverageNotice from '../components/investigation/CoverageNotice';
import CaseDetails from '../components/investigation/CaseDetails';
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
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Shield,
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
function buildSignals(data: FraudCardData): Signal[] {
  const signals: Signal[] = [];
  const frs = data.frs_breakdown;

  if (frs?.dynamic_ran) {
    signals.push(
      frs.dynamic_conclusive
        ? {
            key: 'runtime',
            icon: ShieldCheck,
            tone: 'positive',
            title: 'Runtime confirmed',
            detail: 'Behaviour was observed and scored in the sandbox.',
            to: '/technical',
            cta: 'Inspect live analysis',
          }
        : {
            key: 'runtime',
            icon: AlertTriangle,
            tone: 'caution',
            title: 'Runtime limited',
            detail: `${dynamicRuntimeLabel(data)}. No runtime evidence raised the score.`,
            to: '/technical',
            cta: 'Inspect live analysis',
          },
    );
  }

  const actions = data.dynamic_analysis?.resilience_actions;
  if (data.dynamic_available && actions && actions.length > 0) {
    signals.push({
      key: 'resilience',
      icon: ShieldAlert,
      tone: 'neutral',
      title: `${actions.length} evasion ${actions.length === 1 ? 'case' : 'cases'} defeated`,
      detail: actions.map((a) => a.title).join(' · '),
      to: '/technical',
      cta: 'View resilience controls',
    });
  }

  const corr = frs?.correlation ?? 0;
  const family = data.family_classification;
  if (corr >= 20 || (family && family !== 'Unknown')) {
    signals.push({
      key: 'intel',
      icon: Shield,
      tone: family && family !== 'Unknown' ? 'caution' : 'neutral',
      title: family && family !== 'Unknown' ? `Matches ${family}` : 'External correlation',
      detail:
        corr >= 20
          ? `Threat-intelligence axis scored ${corr.toFixed(0)}/100.`
          : 'External threat correlation contributed to this case.',
      to: '/threat-intel',
      cta: 'View threat intelligence',
    });
  }

  return signals;
}

const SIGNAL_TONE: Record<Signal['tone'], string> = {
  positive: 'border-l-emerald-500',
  caution: 'border-l-amber-500',
  neutral: 'border-l-slate-300',
};

const SIGNAL_ICON: Record<Signal['tone'], string> = {
  positive: 'text-emerald-600',
  caution: 'text-amber-600',
  neutral: 'text-slate-500',
};

function CaseSignalsRow({ data }: { data: FraudCardData }) {
  const signals = buildSignals(data);
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
              className={`group flex flex-col gap-1.5 bg-white border border-slate-200 border-l-2 ${
                SIGNAL_TONE[signal.tone]
              } rounded-md px-3.5 py-3 hover:border-slate-300 hover:shadow-[0_1px_3px_rgba(15,23,42,0.06)] transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500`}
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
        Level 1 - the decision, and the one qualifier that can invalidate it.
        CoverageNotice sits above the verdict deliberately: when the sandbox
        never exercised the sample, it changes how the score below it reads.
      */}
      <CoverageNotice data={data} />
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
      <CaseDetails data={data} />
    </div>
  );
}
