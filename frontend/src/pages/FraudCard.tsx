import { Target } from 'lucide-react';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import HelpTerm from '../components/investigation/HelpTerm';
import CoreFindingsList from '../components/investigation/CoreFindingsList';
import InvestigationTimeline from '../components/investigation/InvestigationTimeline';
import ThreatScenarioTable from '../components/investigation/ThreatScenarioTable';
import FraudRiskHero from '../components/investigation/FraudRiskHero';
import VisualImpersonationExecutiveCard from '../components/investigation/VisualImpersonationExecutiveCard';
import ExecutiveIntelligenceOverview from '../components/investigation/ExecutiveIntelligenceOverview';
import EvidencePipelineTimeline from '../components/investigation/EvidencePipelineTimeline';
import StructuredCaseSummary from '../components/investigation/StructuredCaseSummary';
import CaseSummaryStrip from '../components/investigation/CaseSummaryStrip';
import IntelligencePhaseCards from '../components/investigation/IntelligencePhaseCards';
import ScreenshotGallery from '../components/investigation/ScreenshotGallery';
import ApplicationInfoCard from '../components/investigation/ApplicationInfoCard';
import ScoreEntryCard from '../components/investigation/ScoreEntryCard';
import { useRuntimeScreenshots } from '../hooks/useRuntimeScreenshots';

function MitrePanel({ data }: { data: FraudCardData }) {
  const techniques = data.intelligence_report?.mitre_techniques_used || [];

  return (
    <SocCard>
      <SectionHeader
        icon={<Target className="h-4 w-4" />}
        title="Attack Techniques (MITRE)"
        subtitle={
          <>
            <HelpTerm term="MITRE">Industry attack technique mapping</HelpTerm> — {techniques.length} linked to this
            case.
          </>
        }
      />
      <div className="p-5">
        {techniques.length === 0 ? (
          <div className="text-center py-8 px-4 rounded-xl border border-dashed border-slate-200 bg-slate-50">
            <p className="text-sm text-slate-700">No attack techniques were mapped for this application.</p>
            <p className="text-xs text-slate-500 mt-2">Techniques appear when behaviour matches MITRE ATT&CK Mobile.</p>
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {techniques.map((tech, i) => (
              <div
                key={i}
                className="flex items-center gap-2 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs"
              >
                <Target className="h-4 w-4 text-blue-600 flex-shrink-0" />
                <span className="font-mono font-bold text-slate-800">{tech}</span>
              </div>
            ))}
          </div>
        )}
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
      <VisualImpersonationExecutiveCard data={data} />
      <ExecutiveIntelligenceOverview data={data} bundle={investigationBundle} />
      <EvidencePipelineTimeline data={data} />
      <StructuredCaseSummary data={data} />
      {investigationBundle && stripCounts && (
        <CaseSummaryStrip riskScore={data.final_risk_score} counts={stripCounts} />
      )}
      <ScreenshotGallery data={data} bundle={investigationBundle} />
      {investigationBundle && <IntelligencePhaseCards data={data} bundle={investigationBundle} />}
      <CoreFindingsList data={data} bundle={investigationBundle} />
      <div className="analyst-split-main">
        <div className="analyst-split-primary">
          <MitrePanel data={data} />
          {data.threat_scenario_table && data.threat_scenario_table.length > 0 && (
            <ThreatScenarioTable rows={data.threat_scenario_table} />
          )}
          {investigationBundle && <InvestigationTimeline bundle={investigationBundle} />}
        </div>
        <div className="analyst-split-side">
          <ApplicationInfoCard data={data} />
          <ScoreEntryCard data={data} />
        </div>
      </div>
    </div>
  );
}
