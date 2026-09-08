import type { FraudCardData } from '../App';
import type { InvestigationBundle } from '../types/investigation';
import {
  dynamicRuntimeLabel,
  riskBandPlainEnglish,
  riskRecommendedAction,
} from './analystCopy';
import { overallAnalysisConfidence } from './findingAnalystView';
import { resolveRuntimeDynamicStatus, runtimeStatusExplanation } from './investigationRuntime';
import { getVideUiState, resolveVideFromData } from './videUi';

export type ConclusionPillar = {
  id: string;
  title: string;
  detail: string;
  evidenceIds: string[];
};

export type InvestigationConclusionModel = {
  verdictLabel: string;
  headline: string;
  pillars: ConclusionPillar[];
  confidenceLabel: string;
  confidenceDetail: string;
  limitations: string[];
  recommendedAction: string;
};

function staticPillars(data: FraudCardData): ConclusionPillar[] {
  const pillars: ConclusionPillar[] = [];
  let n = 0;

  if (data.has_accessibility_abuse || data.has_system_alert_window) {
    const ids: string[] = [];
    if (data.has_accessibility_abuse) ids.push('STAT-A11Y');
    if (data.has_system_alert_window) ids.push('STAT-OVERLAY');
    pillars.push({
      id: `pillar-${++n}`,
      title: 'Credential theft capability',
      detail: 'Accessibility and/or overlay indicators were identified in static analysis.',
      evidenceIds: ids,
    });
  }

  if (data.has_sms_read_write) {
    pillars.push({
      id: `pillar-${++n}`,
      title: 'OTP / SMS interception risk',
      detail: 'SMS read or receive permissions were declared in the manifest.',
      evidenceIds: ['STAT-SMS'],
    });
  }

  if (data.targets_indian_banks) {
    pillars.push({
      id: `pillar-${++n}`,
      title: 'Banking targeting',
      detail: 'The APK contains indicators associated with Indian banking applications.',
      evidenceIds: [],
    });
  }

  if (data.frs_breakdown?.concealed_payload) {
    pillars.push({
      id: `pillar-${++n}`,
      title: 'Concealed payload',
      detail: 'Static analysis identified a concealed or dynamically loaded payload pattern.',
      evidenceIds: [],
    });
  }

  const manifestHigh = (data.manifest_findings || []).filter(
    (f) => f && typeof f === 'object' && /critical|high/i.test(String(f.severity || '')),
  );
  if (manifestHigh.length > 0 && pillars.length < 4) {
    const idx = data.manifest_findings?.indexOf(manifestHigh[0]) ?? 0;
    pillars.push({
      id: `pillar-${++n}`,
      title: String(manifestHigh[0].title || 'High-risk static finding'),
      detail: String(manifestHigh[0].description || 'Flagged during manifest and static inspection.'),
      evidenceIds: [`STAT-MAN-${idx}`],
    });
  }

  return pillars.slice(0, 4);
}

export function buildInvestigationConclusion(
  data: FraudCardData,
  bundle: InvestigationBundle | null,
): InvestigationConclusionModel {
  const band = riskBandPlainEnglish(data.risk_band);
  const verdictLabel = band;
  const appLabel = data.app_name || data.package_name || 'This application';

  const pillars = staticPillars(data);
  const runtimeStatus = resolveRuntimeDynamicStatus(data);

  if (runtimeStatus === 'INCONCLUSIVE' || (data.frs_breakdown?.dynamic_ran && !data.frs_breakdown?.dynamic_conclusive)) {
    pillars.push({
      id: 'pillar-runtime-limit',
      title: 'Runtime confirmation unavailable',
      detail: runtimeStatusExplanation('INCONCLUSIVE'),
      evidenceIds: [],
    });
  } else if (runtimeStatus === 'COMPLETED' && (bundle?.counts.runtimeBehaviors ?? 0) > 0) {
    pillars.push({
      id: 'pillar-runtime-confirmed',
      title: 'Runtime behaviour observed',
      detail: `${bundle?.counts.runtimeBehaviors ?? 0} runtime evidence record(s) were captured in the sandbox.`,
      evidenceIds: [],
    });
  }

  const vide = resolveVideFromData(data);
  const videState = getVideUiState(vide);
  if (videState === 'detected' && vide) {
    const rule = vide.vide_compare?.rule_id;
    pillars.push({
      id: 'pillar-vide',
      title: 'Visual impersonation signal',
      detail: 'VIDE reported a laboratory banking-style UI similarity match.',
      evidenceIds: rule ? [rule] : [],
    });
  }

  const threatScore = data.frs_breakdown?.correlation ?? 0;
  if (threatScore >= 25 || (bundle?.counts.iocMatches ?? 0) > 0) {
    pillars.push({
      id: 'pillar-threat',
      title: 'Threat intelligence correlation',
      detail: 'External threat intelligence contributed evidence to this investigation.',
      evidenceIds: [],
    });
  }

  const records = bundle?.evidenceRecords ?? [];
  const confidencePct =
    records.length > 0 ? overallAnalysisConfidence(records, data) : Math.round(data.confidence ?? 0);

  let confidenceLabel = 'Moderate';
  if (confidencePct >= 75) confidenceLabel = 'High';
  else if (confidencePct < 45) confidenceLabel = 'Limited';

  const limitations: string[] = [];
  if (runtimeStatus === 'INCONCLUSIVE' || (data.frs_breakdown?.dynamic_ran && !data.frs_breakdown?.dynamic_conclusive)) {
    limitations.push('Runtime analysis was inconclusive - absence of runtime proof is not proof of benign behaviour.');
  }
  if (runtimeStatus === 'NOT_STARTED' || runtimeStatus === 'UNAVAILABLE') {
    limitations.push('Sandbox execution did not complete; conclusions rely on static and threat evidence.');
  }
  if (data.family_classification === 'Unknown' && (bundle?.counts.iocMatches ?? 0) === 0) {
    limitations.push('No strong malware-family or IOC correlation was available.');
  }

  const headline =
    data.final_risk_score >= 20
      ? `${appLabel} presents a ${band.toLowerCase()} banking-fraud risk profile based on verified evidence.`
      : `${appLabel} shows limited verified fraud signals at the current evidence depth.`;

  let confidenceDetail = `${dynamicRuntimeLabel(data)}. `;
  if (runtimeStatus === 'INCONCLUSIVE') {
    confidenceDetail +=
      'Static and threat evidence support the classification, but runtime confirmation is unavailable.';
  } else if (runtimeStatus === 'COMPLETED') {
    confidenceDetail += 'Static and runtime evidence align on the current risk band.';
  } else {
    confidenceDetail += 'Assessment leans on static inspection and threat correlation.';
  }

  return {
    verdictLabel,
    headline,
    pillars: pillars.slice(0, 5),
    confidenceLabel,
    confidenceDetail,
    limitations,
    recommendedAction: data.recommended_action?.trim() || riskRecommendedAction(data),
  };
}

export function filterPillarEvidenceIds(
  pillar: ConclusionPillar,
  bundle: InvestigationBundle | null,
): string[] {
  if (!bundle) return [];
  const known = new Set(bundle.evidenceRecords.map((e) => e.id));
  return pillar.evidenceIds.filter((id) => known.has(id));
}
