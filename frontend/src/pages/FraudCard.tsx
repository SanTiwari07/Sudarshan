import { Link } from 'react-router-dom';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import { dynamicRuntimeLabel } from '../lib/analystCopy';
import SocCard from '../components/ui/Card';
import HelpTerm from '../components/investigation/HelpTerm';
import CoreFindingsList from '../components/investigation/CoreFindingsList';
import FraudRiskHero from '../components/investigation/FraudRiskHero';
import CaseSummaryStrip from '../components/investigation/CaseSummaryStrip';
import AiSummaryCard from '../components/investigation/AiSummaryCard';
import ExecutiveVisualEvidenceSection from '../components/investigation/ExecutiveVisualEvidenceSection';
import VisualImpersonationExecutiveCard from '../components/investigation/VisualImpersonationExecutiveCard';
import InvestigationConclusionCard from '../components/investigation/InvestigationConclusionCard';
import { useRuntimeScreenshots } from '../hooks/useRuntimeScreenshots';
import { Activity, AlertTriangle, Shield } from 'lucide-react';

/**
 * INCOMPLETE EXERCISE badge.
 *
 * Sits above every other executive signal because it changes how all of them
 * read: when the sandbox never exercised the sample, a low score is a
 * statement about the run, not about the app.
 */
function IncompleteExerciseBanner({ data }: { data: FraudCardData }) {
  const assertions = data.execution_assertions;
  const incomplete =
    data.verdict === 'INCOMPLETE_EXERCISE' || assertions?.incomplete_exercise;
  if (!incomplete) return null;

  const fired = assertions?.fired_count ?? 0;
  const total = assertions?.total_count ?? 0;

  return (
    <SocCard className="border-amber-300 bg-amber-50/70">
      <div className="px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-400 bg-amber-100 px-2.5 py-1 text-xs font-bold uppercase tracking-wide text-amber-900">
            <AlertTriangle className="h-3.5 w-3.5" />
            Incomplete exercise
          </span>
          {total > 0 && (
            <span className="text-xs font-medium text-amber-900">
              {fired}/{total} fraud trigger conditions reached
            </span>
          )}
        </div>
        <p className="mt-2 text-xs leading-relaxed text-amber-900/90">
          The sandbox ran but never exercised this sample: no trigger condition was
          reached and no threat behaviour was observed.{' '}
          <strong>Absence of evidence is not evidence of absence</strong> — a banking
          trojan waiting on a targeted app, an OTP, an accessibility grant or a
          dormancy timer produces exactly this result. Reported confidence is
          halved and this run does not certify the app as safe.
        </p>
        <Link
          to="/technical"
          className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-blue-800 hover:underline"
        >
          <Activity className="h-3.5 w-3.5" />
          Open resilience controls to re-run with triggers →
        </Link>
      </div>
    </SocCard>
  );
}

function RuntimeLimitationBanner({ data }: { data: FraudCardData }) {
  const frs = data.frs_breakdown;
  if (!frs?.dynamic_ran) return null;
  if (frs.dynamic_conclusive) {
    return (
      <SocCard className="border-emerald-100 bg-emerald-50/40">
        <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-emerald-900">
            <HelpTerm term="Runtime Behaviour Confirmed">Runtime behaviour confirmed</HelpTerm> in the sandbox.
          </p>
          <Link to="/technical" className="text-xs font-semibold text-emerald-800 hover:underline">
            Inspect live analysis →
          </Link>
        </div>
      </SocCard>
    );
  }

  return (
    <SocCard className="border-amber-200/80 bg-amber-50/50">
      <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-amber-950">Runtime limitation</p>
          <p className="text-xs text-amber-900/90 mt-1">
            {dynamicRuntimeLabel(data)}. No runtime evidence was used to increase the final score.
          </p>
        </div>
        <Link
          to="/technical"
          className="inline-flex items-center gap-1 text-xs font-semibold text-blue-800 hover:underline"
        >
          <Activity className="h-3.5 w-3.5" />
          Inspect live analysis →
        </Link>
      </div>
    </SocCard>
  );
}

function ThreatIntelTeaser({ data }: { data: FraudCardData }) {
  const corr = data.frs_breakdown?.correlation ?? 0;
  const family = data.family_classification;
  if (corr < 20 && (!family || family === 'Unknown')) return null;

  return (
    <SocCard>
      <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-start gap-2">
          <Shield className="h-4 w-4 text-blue-600 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-slate-900">Threat intelligence</p>
            <p className="text-xs text-slate-600 mt-0.5">
              {family && family !== 'Unknown'
                ? `Campaign correlation: ${family}.`
                : 'External threat correlation contributed to this case.'}
              {corr >= 20 ? ` Correlation axis score ${corr.toFixed(0)}/100.` : ''}
            </p>
          </div>
        </div>
        <Link to="/threat-intel" className="text-xs font-semibold text-blue-700 hover:underline">
          View threat intelligence →
        </Link>
      </div>
    </SocCard>
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

  return (
    <div className="space-y-6 sm:space-y-8">
      {/* 0. Verdict qualifier - changes how everything below reads. */}
      <IncompleteExerciseBanner data={data} />

      {/* 1. EXECUTIVE RISK ASSESSMENT & SCORE INFLUENCERS */}
      <FraudRiskHero data={data} />

      {/* 2. EVIDENCE & RISK SIGNALS (Independent section below top area) */}
      {stripCounts && (
        <CaseSummaryStrip riskScore={data.final_risk_score} counts={stripCounts} />
      )}

      {/* 3. FULL-WIDTH AI SUMMARY */}
      <AiSummaryCard data={data} />

      {/* 3. Full-Width Visual Evidence Section */}
      <ExecutiveVisualEvidenceSection data={data} />

      <RuntimeLimitationBanner data={data} />

      {/* 3. Technical Findings */}
      <CoreFindingsList data={data} bundle={investigationBundle} />

      {/* 4. Intelligence */}
      <InvestigationConclusionCard data={data} bundle={investigationBundle} />
      <VisualImpersonationExecutiveCard data={data} />
      <ThreatIntelTeaser data={data} />
    </div>
  );
}
