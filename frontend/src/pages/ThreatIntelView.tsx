import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowRight, RefreshCw } from 'lucide-react';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import { useIntelPayload } from '../hooks/useIntelPayload';
import SocCard from '../components/ui/Card';
import AIIntelligenceOverview from '../components/threatIntel/AIIntelligenceOverview';
import ThreatDnaPanel from '../components/threatIntel/ThreatDnaPanel';
import IntelligenceSourcesPanel from '../components/threatIntel/IntelligenceSourcesPanel';
import OperationalRecommendationCard from '../components/threatIntel/OperationalRecommendationCard';
import ThreatEvidenceExplorer from '../components/threatIntel/ThreatEvidenceExplorer';
import ThreatIocRegistry from '../components/threatIntel/ThreatIocRegistry';
import CampaignAttributionPanel from '../components/threatIntel/CampaignAttributionPanel';
import ThreatSimilarityPanel from '../components/threatIntel/ThreatSimilarityPanel';
import HistoricalCasesPanel from '../components/threatIntel/HistoricalCasesPanel';
import EvidenceConfidenceMeter from '../components/threatIntel/EvidenceConfidenceMeter';
import ThreatIntelPageShell from '../components/threatIntel/ThreatIntelPageShell';
import AnalysisTabs, { type AnalysisTab } from '../components/investigation/AnalysisTabs';
import { INTEL } from '../components/threatIntel/intelTokens';
import { TYPOGRAPHY } from '../theme/typography';
import { caseSectionPath } from '../lib/caseRoutes';
import {
  buildThreatDna,
  buildConfidenceSources,
  evidenceConfidenceOverall,
  buildAnalystActions,
  buildFamilySimilarity,
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

/**
 * The reference half of the threat-intelligence page.
 *
 * Threat DNA, source coverage, the IOC registry and the evidence explorer are
 * all "show me the underlying records" panels. Stacked, they tripled the
 * page's height and buried the recommendation above them; tabbed, they cost
 * one screen and the analyst picks the record type they actually want.
 */
function SupportingIntelligence({
  dna,
  intel,
  data,
  bundle,
  explorer,
  similarity,
  confidenceSources,
  overallConf,
}: {
  dna: ReturnType<typeof buildThreatDna>;
  intel: NonNullable<ReturnType<typeof useIntelPayload>['api']>;
  data: FraudCardData;
  bundle: ReturnType<typeof useAnalysis>['investigationBundle'];
  explorer: ReturnType<typeof collectEvidenceExplorerItems>;
  similarity: ReturnType<typeof buildFamilySimilarity>;
  confidenceSources: ReturnType<typeof buildConfidenceSources>;
  overallConf: number;
}) {
  const tabs: AnalysisTab[] = [];

  if (dna.length > 0) {
    tabs.push({
      id: 'dna',
      label: 'Threat DNA',
      hint: 'what traits does it share?',
      count: dna.length,
      content: <ThreatDnaPanel traits={dna} />,
    });
  }

  tabs.push({
    id: 'sources',
    label: 'Sources',
    hint: 'who corroborated this?',
    content: <IntelligenceSourcesPanel intel={intel} data={data} bundle={bundle} />,
  });

  if (intel.iocs.length > 0) {
    tabs.push({
      id: 'iocs',
      label: 'Indicators',
      hint: 'what should I block?',
      count: intel.iocs.length,
      content: <ThreatIocRegistry iocs={intel.iocs} />,
    });
  }

  /*
   * Attribution: the question this page exists to answer.
   *
   * These four panels were built and then left unreachable - no route, no
   * import, nothing rendering them. They answer "have we seen this before",
   * which is precisely what an intelligence view is for, while the page was
   * instead spending its space re-stating the verdict the case bar already
   * carries.
   */
  tabs.push({
    id: 'attribution',
    label: 'Attribution',
    hint: 'have we seen it before?',
    content: (
      <div className="space-y-4">
        <CampaignAttributionPanel data={data} intel={intel} />
        {similarity.length > 0 && <ThreatSimilarityPanel items={similarity} />}
        <HistoricalCasesPanel data={data} />
      </div>
    ),
  });

  tabs.push({
    id: 'confidence',
    label: 'Confidence',
    hint: 'how much of this is corroborated?',
    content: <EvidenceConfidenceMeter sources={confidenceSources} overall={overallConf} />,
  });

  if (explorer.length > 0) {
    tabs.push({
      id: 'evidence',
      label: 'Evidence',
      hint: 'what is it based on?',
      count: explorer.length,
      content: <ThreatEvidenceExplorer groups={explorer} />,
    });
  }

  if (tabs.length === 0) return null;

  return (
    <section aria-label="Supporting intelligence">
      <h3 className={`${TYPOGRAPHY.h2} mb-3`}>Supporting intelligence</h3>
      <AnalysisTabs tabs={tabs} />
    </section>
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
      confidenceSources,
      similarity: buildFamilySimilarity(data, intel.malware_family || data.family_classification),
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
          <h2 className={TYPOGRAPHY.h2}>Threat intelligence</h2>
          <p className={TYPOGRAPHY.caption}>Banking threat comparison for the active case</p>
        </div>
        <button
          type="button"
          onClick={fetchIntelligence}
          className={`inline-flex items-center justify-center gap-2 ${TYPOGRAPHY.buttonSm} border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 shadow-sm transition-colors`}
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
          <p className={`${TYPOGRAPHY.bodySmall} font-bold text-slate-800`}>{error}</p>
          <button
            type="button"
            onClick={fetchIntelligence}
            className={`mt-4 ${TYPOGRAPHY.button} text-white bg-blue-700 hover:bg-blue-800`}
          >
            Retry
          </button>
        </SocCard>
      ) : intel && derived ? (
        <div className={INTEL.sectionGap}>
          {/* Tier 1 - the assessment. */}
          <AIIntelligenceOverview
            data={data}
            intel={intel}
            bundle={investigationBundle}
            evidenceConfidence={derived.overallConf}
            actions={derived.actions}
          />

          {/*
            Tier 2 - the action this intelligence implies.

            The attack chain used to render here as well, from the same
            fraud_workflow the case summary reconstructs. Two renderers of one
            dataset can only ever agree by luck, so this points at the one that
            leads the case rather than shipping a rival copy.
          */}
          {data.fraud_workflow?.fraud_sequence_detected && (
            <Link
              to={`${caseSectionPath(data.sha256, 'summary')}#attack-story`}
              className={`${TYPOGRAPHY.linkAction} text-sm`}
            >
              View the reconstructed attack chain
              <ArrowRight className="h-3.5 w-3.5" aria-hidden />
            </Link>
          )}

          <OperationalRecommendationCard data={data} intel={intel} actions={derived.actions} />

          {/*
            Tier 3 - four lookup panels that used to stack full-width below the
            recommendation, so the page ended in 2000px of tables nobody scrolled
            to. They answer different questions about the same case, which makes
            them tabs rather than sections.
          */}
          <SupportingIntelligence
            dna={derived.dna}
            intel={intel}
            data={data}
            bundle={investigationBundle}
            explorer={derived.explorer}
            similarity={derived.similarity}
            confidenceSources={derived.confidenceSources}
            overallConf={derived.overallConf}
          />
        </div>
      ) : null}
    </ThreatIntelPageShell>
  );
}
