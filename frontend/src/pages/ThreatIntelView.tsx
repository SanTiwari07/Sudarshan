import { useState, useEffect, useMemo } from 'react';
import { AlertTriangle, RefreshCw, FileText } from 'lucide-react';
import type { FraudCardData } from '../App';
import { API_BASE, authHeaders } from '../config';
import { useAnalysis } from '../context/AnalysisContext';
import SocCard from '../components/ui/Card';
import IntelPipelineTimeline from '../components/investigation/IntelPipelineTimeline';
import ThreatIntelHero from '../components/threatIntel/ThreatIntelHero';
import ThreatDnaPanel from '../components/threatIntel/ThreatDnaPanel';
import AttackChainFlow from '../components/threatIntel/AttackChainFlow';
import CampaignAttributionPanel from '../components/threatIntel/CampaignAttributionPanel';
import ClassificationJustification from '../components/threatIntel/ClassificationJustification';
import ThreatInfrastructurePanel from '../components/threatIntel/ThreatInfrastructurePanel';
import MitreAttackCards from '../components/threatIntel/MitreAttackCards';
import BankingEcosystemTable from '../components/threatIntel/BankingEcosystemTable';
import EvidenceConfidenceMeter from '../components/threatIntel/EvidenceConfidenceMeter';
import IocRelationshipGraph from '../components/threatIntel/IocRelationshipGraph';
import ThreatSimilarityPanel from '../components/threatIntel/ThreatSimilarityPanel';
import AnalystRecommendationPanel from '../components/threatIntel/AnalystRecommendationPanel';
import ThreatEvidenceExplorer from '../components/threatIntel/ThreatEvidenceExplorer';
import RiskProjectionPanel from '../components/threatIntel/RiskProjectionPanel';
import AnalysisCoveragePanel from '../components/threatIntel/AnalysisCoveragePanel';
import IntelligenceSourcesPanel from '../components/threatIntel/IntelligenceSourcesPanel';
import HistoricalCasesPanel from '../components/threatIntel/HistoricalCasesPanel';
import ThreatIocRegistry from '../components/threatIntel/ThreatIocRegistry';
import ThreatIntelExportSuite from '../components/threatIntel/ThreatIntelExportSuite';
import ThreatIntelPageShell from '../components/threatIntel/ThreatIntelPageShell';
import { INTEL } from '../components/threatIntel/intelTokens';
import {
  type IntelApiPayload,
  buildThreatDna,
  buildAttackChain,
  buildClassificationEvidence,
  buildInfrastructure,
  buildMitreCards,
  buildBankingRows,
  buildConfidenceSources,
  evidenceConfidenceOverall,
  buildFamilySimilarity,
  buildAnalystActions,
  buildRiskProjection,
  buildAnalysisCoverage,
  collectEvidenceExplorerItems,
  filterIocsByGraphNode,
} from '../lib/threatIntelModel';

function ThreatIntelSkeleton() {
  return (
    <div className={`animate-pulse ${INTEL.gridGap} grid grid-cols-1`}>
      <div className="h-40 bg-slate-200 rounded-xl" />
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        <div className="xl:col-span-7 h-72 bg-slate-200 rounded-xl" />
        <div className="xl:col-span-5 h-72 bg-slate-200 rounded-xl" />
      </div>
    </div>
  );
}

export default function ThreatIntelView({ data }: { data: FraudCardData | null }) {
  const { investigationBundle } = useAnalysis();
  const [intel, setIntel] = useState<IntelApiPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [graphNode, setGraphNode] = useState<string | null>(null);

  const fetchIntelligence = async () => {
    if (!data) return;
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`${API_BASE}/intelligence/${data.sha256}`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        throw new Error(
          res.status === 404 ? 'No intelligence analysis found for this hash.' : `Fetch failed (${res.status})`,
        );
      }
      const json: IntelApiPayload = await res.json();
      setIntel(json);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch threat intelligence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntelligence();
  }, [data?.sha256]);

  const derived = useMemo(() => {
    if (!data || !intel) return null;
    const confidenceSources = buildConfidenceSources(data, intel, investigationBundle);
    const overallConf = evidenceConfidenceOverall(confidenceSources);
    const classEv = buildClassificationEvidence(data, intel);
    const family = intel.malware_family || data.family_classification;

    return {
      dna: buildThreatDna(data, investigationBundle),
      chain: buildAttackChain(data, investigationBundle),
      classEv,
      infra: buildInfrastructure(data, intel),
      mitre: buildMitreCards(data, investigationBundle),
      banking: buildBankingRows(data),
      confidenceSources,
      overallConf,
      similarity: buildFamilySimilarity(data, family),
      actions: buildAnalystActions(data, intel),
      risk: buildRiskProjection(data),
      coverage: buildAnalysisCoverage(data, intel),
      explorer: collectEvidenceExplorerItems(investigationBundle, data, intel),
      filteredIocs: filterIocsByGraphNode(intel.iocs, graphNode, data, intel),
    };
  }, [data, intel, investigationBundle, graphNode]);

  if (!data) return null;

  return (
    <ThreatIntelPageShell>
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">Threat intelligence</h2>
          <p className={INTEL.subtitle}>Evidence-backed profile for active case</p>
        </div>
        <button
          type="button"
          onClick={fetchIntelligence}
          className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold border border-blue-200 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-800 shadow-sm transition-colors"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh intelligence
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
          <ThreatIntelHero data={data} intel={intel} evidenceConfidence={derived.overallConf} />

          <div className={`grid grid-cols-1 xl:grid-cols-12 ${INTEL.gridGap} items-stretch`}>
            <div className="xl:col-span-7 min-h-0">
              <ThreatDnaPanel traits={derived.dna} />
            </div>
            <div className="xl:col-span-5 min-h-0">
              <AttackChainFlow stages={derived.chain} />
            </div>
          </div>

          <div className={`grid grid-cols-1 lg:grid-cols-2 ${INTEL.gridGap} items-stretch`}>
            <CampaignAttributionPanel data={data} intel={intel} />
            <ClassificationJustification
              family={derived.classEv.family}
              matchedRules={derived.classEv.matchedRules}
              ruleRefs={derived.classEv.ruleRefs}
              confidence={derived.classEv.confidence}
              ruleText={intel.family_rule_matched || data.technical_view?.matched_rule || 'No rule text'}
            />
          </div>

          <ThreatInfrastructurePanel infra={derived.infra} />

          <MitreAttackCards cards={derived.mitre} />

          <BankingEcosystemTable rows={derived.banking} />

          <EvidenceConfidenceMeter sources={derived.confidenceSources} overall={derived.overallConf} />

          <section className={`grid grid-cols-1 xl:grid-cols-12 ${INTEL.gridGap}`}>
            <div className="xl:col-span-12">
              <IocRelationshipGraph
                activeNode={graphNode}
                onSelect={(id) => setGraphNode(id === 'all' ? null : id)}
                family={intel.malware_family}
                campaign={intel.campaign}
              />
            </div>
            <div className="xl:col-span-12">
              <ThreatIocRegistry iocs={derived.filteredIocs} />
            </div>
          </section>

          <div className={`grid grid-cols-1 lg:grid-cols-2 ${INTEL.gridGap} items-stretch`}>
            <ThreatSimilarityPanel items={derived.similarity} />
            <AnalystRecommendationPanel actions={derived.actions} />
          </div>

          <RiskProjectionPanel
            current={derived.risk.current}
            projected={derived.risk.projected}
            maximum={derived.risk.maximum}
            explanation={derived.risk.explanation}
          />

          <AnalysisCoveragePanel
            percent={derived.coverage.percent}
            completed={derived.coverage.completed}
            missing={derived.coverage.missing}
          />

          <IntelligenceSourcesPanel intel={intel} data={data} />

          <ThreatEvidenceExplorer groups={derived.explorer} />

          {intel.ai_summary && (
            <SocCard className="p-6 border-slate-200 shadow-sm">
              <div className="flex items-center gap-2 mb-3">
                <FileText className="h-4 w-4 text-slate-600" />
                <h3 className={INTEL.title}>Grounded narrative</h3>
              </div>
              <p className={`${INTEL.meta} leading-relaxed`}>{intel.ai_summary}</p>
              <p className={`${INTEL.caption} mt-3`}>
                Produced from intelligence report or deterministic engine facts — not an unverified model verdict.
              </p>
            </SocCard>
          )}

          <HistoricalCasesPanel data={data} />

          <div className={`grid grid-cols-1 lg:grid-cols-3 ${INTEL.gridGap} items-stretch`}>
            <div className="lg:col-span-2 min-h-0">
              <IntelPipelineTimeline timeline={intel.timeline} />
            </div>
            <ThreatIntelExportSuite sha256={data.sha256} />
          </div>
        </div>
      ) : null}
    </ThreatIntelPageShell>
  );
}
