import { Link } from 'react-router-dom';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import { dynamicRuntimeLabel } from '../lib/analystCopy';
import SocCard from '../components/ui/Card';
import HelpTerm from '../components/investigation/HelpTerm';
import CoreFindingsList from '../components/investigation/CoreFindingsList';
import FraudRiskHero from '../components/investigation/FraudRiskHero';
import VisualImpersonationExecutiveCard from '../components/investigation/VisualImpersonationExecutiveCard';
import InvestigationConclusionCard from '../components/investigation/InvestigationConclusionCard';
import StructuredCaseSummary from '../components/investigation/StructuredCaseSummary';
import CaseSummaryStrip from '../components/investigation/CaseSummaryStrip';
import ApplicationInfoCard from '../components/investigation/ApplicationInfoCard';
import { useRuntimeScreenshots } from '../hooks/useRuntimeScreenshots';
import { Activity, Shield } from 'lucide-react';

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
      <FraudRiskHero data={data} />
      <InvestigationConclusionCard data={data} bundle={investigationBundle} />
      <RuntimeLimitationBanner data={data} />
      <VisualImpersonationExecutiveCard data={data} />
      <ThreatIntelTeaser data={data} />
      <StructuredCaseSummary data={data} />
      {investigationBundle && stripCounts && (
        <CaseSummaryStrip riskScore={data.final_risk_score} counts={stripCounts} />
      )}
      <CoreFindingsList data={data} bundle={investigationBundle} />
      <div className="analyst-split-main">
        <div className="analyst-split-side ml-auto max-w-md w-full">
          <ApplicationInfoCard data={data} />
        </div>
      </div>
    </div>
  );
}
