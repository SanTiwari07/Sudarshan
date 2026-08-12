import type { FraudCardData } from '../App';
import type { InvestigationBundle } from '../types/investigation';
import { FINDING_EXPLANATIONS } from './findingExplanations';
import {
  computeEvidenceBasis,
  detectedBulletLines,
  evidenceBasisBadge,
  evidenceBasisLabel,
  mapFindingEvidence,
  type EvidenceBasis,
  type MappedEvidenceItem,
} from './findingEvidenceMapper';
import {
  getFindingDefinition,
  SEVERITY_DISPLAY,
  type TechnicalFindingId,
  type TechnicalFindingSeverity,
} from './technicalFindings';

export type TechnicalFindingViewModel = {
  id: TechnicalFindingId;
  title: string;
  subtitle: string;
  severity: TechnicalFindingSeverity;
  severityLabel: string;
  sections: {
    whatItIs: string;
    whyItMatters: string;
    whatDetected: string[];
    evidenceBasis: EvidenceBasis;
    evidenceBasisBadge: string;
    evidenceBasisLabel: string;
    evidenceCount: number;
    whatItProves: string;
    whatItDoesNotProve: string;
    riskImpact: string;
    mitre: string | null;
    analystTakeaway: string;
    runtimeNote: string | null;
  };
  evidence: MappedEvidenceItem[];
  confidencePercent: number | null;
};

function scenarioConfidence(data: FraudCardData, keywords: RegExp): number | null {
  const row = data.threat_scenario_table?.find((r) => keywords.test(`${r.indicator} ${r.threat_scenario}`));
  return row?.confidence ?? null;
}

function mitreForFinding(
  findingId: TechnicalFindingId,
  data: FraudCardData,
  evidence: MappedEvidenceItem[],
): string | null {
  const fromEv = evidence.find((e) => e.evidence?.mitreId)?.evidence;
  if (fromEv?.mitreId) {
    return `${fromEv.mitreId}${fromEv.mitreName ? ` - ${fromEv.mitreName}` : ''}`;
  }
  const hint = FINDING_EXPLANATIONS[findingId].mitreHint;
  const intel = data.intelligence_report?.mitre_techniques_used || [];
  if (hint) {
    const code = hint.split(' ')[0];
    const match = intel.find((t) => t.startsWith(code));
    if (match) return match;
  }
  return hint || null;
}

function provesAndNotProves(
  findingId: TechnicalFindingId,
  basis: EvidenceBasis,
): { proves: string; doesNot: string } {
  const c = FINDING_EXPLANATIONS[findingId];
  switch (basis) {
    case 'dynamic_only':
      return { proves: c.whatItProvesDynamic, doesNot: c.whatItDoesNotProveDynamic };
    case 'static_and_dynamic':
      return { proves: c.whatItProvesBoth, doesNot: c.whatItDoesNotProveStatic };
    case 'static_only':
      return { proves: c.whatItProvesStatic, doesNot: c.whatItDoesNotProveStatic };
    default:
      return {
        proves: 'No verified evidence records are linked to this finding yet.',
        doesNot: c.whatItDoesNotProveStatic,
      };
  }
}

function runtimeNote(data: FraudCardData, basis: EvidenceBasis): string | null {
  const frs = data.frs_breakdown;
  if (basis === 'dynamic_only' || basis === 'static_and_dynamic') return null;
  if (!frs?.dynamic_ran) {
    return 'Runtime confirmation was not available for this finding.';
  }
  if (!frs.dynamic_conclusive) {
    return 'Dynamic analysis did not produce conclusive behavioral evidence for this capability.';
  }
  return 'Detection is based on static evidence.';
}

function aggregateConfidence(evidence: MappedEvidenceItem[], data: FraudCardData, findingId: TechnicalFindingId): number | null {
  if (evidence.length === 0) {
    const map: Partial<Record<TechnicalFindingId, () => number | null>> = {
      accessibility_abuse: () => (data.has_accessibility_abuse ? 95 : null),
      overlay_capability: () => (data.has_system_alert_window ? 90 : null),
      sms_otp_interception: () => (data.has_sms_read_write ? 95 : null),
    };
    return map[findingId]?.() ?? scenarioConfidence(data, /./) ?? null;
  }
  const avg = evidence.reduce((s, e) => s + (e.confidence ?? 85), 0) / evidence.length;
  return Math.round(avg);
}

export function buildTechnicalFindingViewModel(
  findingId: TechnicalFindingId,
  data: FraudCardData,
  bundle: InvestigationBundle | null | undefined,
  rawRuntime: Record<string, unknown>[] = [],
): TechnicalFindingViewModel {
  const def = getFindingDefinition(findingId);
  const edu = FINDING_EXPLANATIONS[findingId];
  const evidence = mapFindingEvidence(findingId, data, bundle, rawRuntime);
  const basis = computeEvidenceBasis(evidence);
  const { proves, doesNot } = provesAndNotProves(findingId, basis);
  const axisLines = def.steiAxis
    ? (data.risk_explanation?.stei_evidence_by_axis?.[def.steiAxis] || []).slice(0, 3)
    : [];

  const riskImpact = [
    SEVERITY_DISPLAY[def.severity] || def.severity,
    edu.riskImpactIntro,
    axisLines.length > 0 ? `Engine signals: ${axisLines.join(' ')}` : '',
  ]
    .filter(Boolean)
    .join(' ');

  return {
    id: findingId,
    title: edu.title,
    subtitle: 'Why Sudarshan flagged this finding',
    severity: def.severity,
    severityLabel: SEVERITY_DISPLAY[def.severity] || 'Risk',
    sections: {
      whatItIs: edu.whatItMeans,
      whyItMatters: edu.whyItMatters,
      whatDetected: detectedBulletLines(evidence),
      evidenceBasis: basis,
      evidenceBasisBadge: evidenceBasisBadge(basis),
      evidenceBasisLabel: evidenceBasisLabel(basis),
      evidenceCount: evidence.length,
      whatItProves: proves,
      whatItDoesNotProve: doesNot,
      riskImpact,
      mitre: mitreForFinding(findingId, data, evidence),
      analystTakeaway: edu.analystTakeaway,
      runtimeNote: runtimeNote(data, basis),
    },
    evidence,
    confidencePercent: aggregateConfidence(evidence, data, findingId),
  };
}
