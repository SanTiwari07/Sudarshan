import type { FraudCardData } from '../App';
import type { InvestigationBundle } from '../types/investigation';
import {
  buildWhatThisMeans,
  dynamicRuntimeLabel,
  riskBandPlainEnglish,
  riskLevelMeaning,
  riskRecommendedAction,
} from './analystCopy';
import { isCriticalSeverity, overallAnalysisConfidence } from './findingAnalystView';

export type OverviewObservation = {
  id: string;
  label: string;
  value: string;
};

export function buildOverallAssessment(
  data: FraudCardData,
  bundle: InvestigationBundle | null,
): string {
  const sentences: string[] = [];
  const appLabel = data.app_name || data.package_name || 'This application';
  const band = riskBandPlainEnglish(data.risk_band);
  const score = data.final_risk_score;

  sentences.push(
    `${appLabel} received a deterministic Fraud Risk Score of ${score.toFixed(0)}/100, classified as ${band} by the risk engine.`,
  );

  const records = bundle?.evidenceRecords ?? [];
  const total = records.length;
  const critical = records.filter((r) => isCriticalSeverity(r.severity)).length;

  if (total > 0) {
    sentences.push(
      `Static analysis, runtime instrumentation, and threat correlation produced ${total} verified evidence record${total === 1 ? '' : 's'}${critical > 0 ? ` (${critical} critical)` : ''}.`,
    );
  } else {
    sentences.push(
      'Evidence records are not yet available in the registry; scores and flags below still reflect completed pipeline stages.',
    );
  }

  const family =
    data.family_classification && data.family_classification !== 'Unknown'
      ? data.family_classification
      : null;
  const runtime = dynamicRuntimeLabel(data);
  const contextParts: string[] = [];
  if (family) contextParts.push(`malware family correlation: ${family}`);
  contextParts.push(`runtime status: ${runtime}`);
  sentences.push(`${contextParts.join('; ')}.`);

  sentences.push(riskLevelMeaning(data));

  return sentences.slice(0, 4).join(' ');
}

export function buildKeyObservations(
  data: FraudCardData,
  bundle: InvestigationBundle | null,
): OverviewObservation[] {
  const records = bundle?.evidenceRecords ?? [];
  const total = records.length;
  const critical = records.filter((r) => isCriticalSeverity(r.severity)).length;
  const confidence = records.length > 0 ? overallAnalysisConfidence(records, data) : null;

  const staticCount = records.filter((r) => r.category === 'static').length;
  const runtimeCount = records.filter((r) => r.category === 'runtime').length;
  const threatCount = records.filter(
    (r) => r.category === 'intel' || r.category === 'scenario',
  ).length;

  const observations: OverviewObservation[] = [
    {
      id: 'total',
      label: 'Total verified findings',
      value: total > 0 ? String(total) : 'Pending registry load',
    },
    {
      id: 'critical',
      label: 'Critical findings',
      value: total > 0 ? String(critical) : '-',
    },
  ];

  if (data.family_classification && data.family_classification !== 'Unknown') {
    observations.push({
      id: 'family',
      label: 'Malware family',
      value: data.family_classification,
    });
  } else {
    observations.push({
      id: 'family',
      label: 'Malware family',
      value: 'No named family match',
    });
  }

  observations.push({
    id: 'runtime',
    label: 'Runtime analysis',
    value: dynamicRuntimeLabel(data),
  });

  const ioc = bundle?.counts.iocMatches ?? 0;
  const familyMatches = bundle?.counts.familyMatches ?? 0;
  const threatLine =
    threatCount > 0 || ioc > 0 || familyMatches > 0
      ? `${threatCount} scenario/intel record${threatCount === 1 ? '' : 's'}; ${ioc} IOC match${ioc === 1 ? '' : 'es'}; ${familyMatches} family signal${familyMatches === 1 ? '' : 's'}`
      : 'No threat intelligence matches indexed';

  observations.push({
    id: 'threat',
    label: 'Threat intelligence',
    value: threatLine,
  });

  if (total > 0) {
    observations.push({
      id: 'sources',
      label: 'Evidence by source',
      value: `${staticCount} static · ${runtimeCount} runtime · ${threatCount} threat`,
    });
  }

  observations.push({
    id: 'confidence',
    label: 'Overall confidence',
    value: confidence != null ? `${confidence}%` : 'Derived after evidence loads',
  });

  return observations;
}

export function buildPotentialFraudImpact(
  data: FraudCardData,
  _bundle: InvestigationBundle | null,
): string {
  return buildWhatThisMeans(data);
}

export function buildRecommendedAnalystActions(
  data: FraudCardData,
  bundle: InvestigationBundle | null,
): string[] {
  const actions: string[] = [];
  const records = bundle?.evidenceRecords ?? [];
  const critical = records.filter((r) => isCriticalSeverity(r.severity)).length;

  if (critical > 0) {
    actions.push(
      `Review ${critical} critical finding${critical === 1 ? '' : 's'} in the findings registry and document disposition.`,
    );
  } else if (records.length > 0) {
    actions.push('Review prioritized findings in the registry, starting with highest severity rows.');
  }

  const hasThreat =
    (bundle?.counts.iocMatches ?? 0) > 0 ||
    (bundle?.counts.familyMatches ?? 0) > 0 ||
    records.some((e) => e.category === 'scenario' || e.category === 'intel') ||
    (data.family_classification && data.family_classification !== 'Unknown');

  if (hasThreat) {
    actions.push('Inspect threat correlation, IOC reputation, and campaign attribution on Threat Intelligence.');
  }

  const frs = data.frs_breakdown;
  if (frs?.dynamic_ran) {
    actions.push(
      'Validate runtime evidence (screenshots, network capture, sandbox telemetry) against static findings.',
    );
  } else {
    actions.push(
      'Runtime sandbox did not complete - rely on static and threat evidence; consider re-running dynamic analysis.',
    );
  }

  const policyAction = data.recommended_action?.trim() || riskRecommendedAction(data);
  if (policyAction && !actions.includes(policyAction)) {
    actions.push(policyAction);
  }

  actions.push('Export JSON or CSV from this page for SOC handoff and investigation records.');

  return actions.slice(0, 5);
}
