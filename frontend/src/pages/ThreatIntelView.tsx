import { useMemo } from 'react';
import { AlertTriangle, RefreshCw, FileText } from 'lucide-react';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import { useIntelPayload } from '../hooks/useIntelPayload';
import SocCard from '../components/ui/Card';
import IntelPipelineTimeline from '../components/investigation/IntelPipelineTimeline';
import AIIntelligenceOverview from '../components/threatIntel/AIIntelligenceOverview';
import ThreatDnaPanel from '../components/threatIntel/ThreatDnaPanel';
import AttackChainFlow from '../components/threatIntel/AttackChainFlow';
import IntelligenceSourcesPanel from '../components/threatIntel/IntelligenceSourcesPanel';
import OperationalRecommendationCard from '../components/threatIntel/OperationalRecommendationCard';
import ThreatEvidenceExplorer from '../components/threatIntel/ThreatEvidenceExplorer';
import ThreatIocRegistry from '../components/threatIntel/ThreatIocRegistry';
import ThreatIntelExportSuite from '../components/threatIntel/ThreatIntelExportSuite';
import ThreatIntelPageShell from '../components/threatIntel/ThreatIntelPageShell';
import { INTEL } from '../components/threatIntel/intelTokens';
import {
  buildThreatDna,
  buildAttackChain,
  buildConfidenceSources,
  evidenceConfidenceOverall,
  buildAnalystActions,
  collectEvidenceExplorerItems,
} from '../lib/threatIntelModel';

function ThreatIntelSkeleton() {
  return (
    <div className={`animate-pulse ${INTEL.gridGap} grid grid-cols-1`}>
      <div className="h-40 bg-slate-200 rounded-2xl" />
      <div className="h-48 bg-slate-200 rounded-xl" />
      <div className="h-64 bg-slate-200 rounded-xl" />
    </div>
  );
}

export default function ThreatIntelView({ data }: { data: FraudCardData | null }) {
  const { investigationBundle } = useAnalysis();
  const {
    api: intel,
    loading,
    error,
    reload: fetchIntelligence,
  } = useIntelPayload({
    enabled: Boolean(data),
    data,
    fetchPolicy: 'always',
  });

  const derived = useMemo(() => {
    if (!data || !intel) return null;
    const confidenceSources = buildConfidenceSources(data, intel, investigationBundle);
    const overallConf = evidenceConfidenceOverall(confidenceSources);

    return {
      dna: buildThreatDna(data, investigationBundle),
      chain: buildAttackChain(data, investigationBundle),
      overallConf,
      actions: buildAnalystActions(data, intel),
      explorer: collectEvidenceExplorerItems(investigationBundle, data, intel),
    };
  }, [data, intel, investigationBundle]);

  if (!data) return null;

  return (
    <ThreatIntelPageShell>
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">Threat intelligence</h2>
          <p className={INTEL.subtitle}>Banking threat comparison for the active case</p>
        </div>
        <button
          type="button"
          onClick={fetchIntelligence}
          className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold border border-slate-200 rounded-lg bg-white hover:bg-slate-50 text-slate-800 shadow-sm transition-colors"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {loading && !intel ? (
        <ThreatIntelSkeleton />
      ) : error ? (
        <SocCard className="p-10 text-center">
          <AlertTriangle className="h-10 w-10 text-amber-500 mx-auto mb-3" />
          <p className="font-semibold text-slate-800">{error}</p>
          <button
            type="button"
            onClick={fetchIntelligence}
            className="mt-4 px-4 py-2 text-xs font-semibold text-white bg-blue-700 rounded-lg hover:bg-blue-800"
          >
            Retry
          </button>
        </SocCard>
      ) : intel && derived ? (
        <div className={INTEL.sectionGap}>
          <AIIntelligenceOverview
            data={data}
            intel={intel}
            bundle={investigationBundle}
            evidenceConfidence={derived.overallConf}
            actions={derived.actions}
          />

          <ThreatDnaPanel traits={derived.dna} />

          <AttackChainFlow stages={derived.chain} data={data} />

          <IntelligenceSourcesPanel intel={intel} data={data} bundle={investigationBundle} />

          <OperationalRecommendationCard data={data} intel={intel} actions={derived.actions} />

          {intel.iocs.length > 0 && <ThreatIocRegistry iocs={intel.iocs} />}

          {derived.explorer.length > 0 && <ThreatEvidenceExplorer groups={derived.explorer} />}

          {intel.ai_summary && (
            <SocCard className="p-6 border-slate-200 shadow-sm">
              <div className="flex items-center gap-2 mb-3">
                <FileText className="h-4 w-4 text-slate-600" />
                <h3 className={INTEL.title}>Analysis summary</h3>
              </div>
              <p className={`${INTEL.meta} leading-relaxed`}>{intel.ai_summary}</p>
              <p className={`${INTEL.caption} mt-3`}>
                Grounded in intelligence report and engine facts - not an unverified model verdict.
              </p>
            </SocCard>
          )}

          <div className={`analyst-split-main ${INTEL.gridGap}`}>
            <div className="analyst-split-primary min-h-0">
              <IntelPipelineTimeline timeline={intel.timeline} />
            </div>
            <div className="analyst-split-side min-h-0">
              <ThreatIntelExportSuite sha256={data.sha256} />
            </div>
          </div>
        </div>
      ) : null}
    </ThreatIntelPageShell>
  );
}
