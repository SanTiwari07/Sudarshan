import { useMemo } from 'react';
import type { FraudCardData } from '../App';
import type {
  InvestigationBundle,
  InvestigationCounts,
  InvestigationEvidence,
} from '../types/investigation';
import { buildLedgerLines } from '../lib/scoreLedger';
import { buildForensicTimeline } from '../lib/timelineMerge';

type RawEvidenceRecord = Record<string, unknown>;

function normalizeRuntimeRecord(raw: RawEvidenceRecord, index: number): InvestigationEvidence {
  const findingId = String(raw.finding_id || raw.id || `EVID-${String(index + 1).padStart(3, '0')}`);
  return {
    id: findingId,
    title: String(raw.description || raw.api || raw.category || 'Runtime behavior'),
    severity: String(raw.severity || 'MEDIUM'),
    confidence: 100,
    category: 'runtime',
    sourceEngine: 'Frida',
    timestampMs: typeof raw.timestamp_ms === 'number' ? raw.timestamp_ms : undefined,
    description: String(raw.description || ''),
    mitreId: raw.mitre_technique_id ? String(raw.mitre_technique_id) : undefined,
    mitreName: raw.mitre_technique_name ? String(raw.mitre_technique_name) : undefined,
    screenshotRef: raw.screenshot_ref ? String(raw.screenshot_ref) : undefined,
    hookNames: raw.api ? [String(raw.api)] : undefined,
  };
}

function buildStaticEvidence(data: FraudCardData): InvestigationEvidence[] {
  const out: InvestigationEvidence[] = [];
  let n = 0;
  data.manifest_findings?.forEach((f, i) => {
    out.push({
      id: `STAT-MAN-${i}`,
      title: f.title,
      severity: f.severity,
      confidence: 90,
      category: 'static',
      sourceEngine: data.analysis_mode?.includes('mobsf') ? 'MobSF' : 'Androguard',
      description: f.description,
      artifactRefs: f.component ? [f.component] : undefined,
    });
  });
  data.code_findings?.forEach((f, i) => {
    out.push({
      id: `STAT-CODE-${i}`,
      title: f.title,
      severity: f.severity,
      confidence: 88,
      category: 'static',
      sourceEngine: 'Static Engine',
      description: f.description,
      artifactRefs: f.files,
    });
  });
  data.threat_scenario_table?.forEach((row, i) => {
    out.push({
      id: `SCEN-${i}`,
      title: row.threat_scenario,
      severity: row.credential_theft_risk === 'Critical' ? 'CRITICAL' : 'HIGH',
      confidence: row.confidence,
      category: 'scenario',
      sourceEngine: 'Threat Scenario Engine',
      description: row.evidence,
    });
    n += 1;
  });
  if (data.has_accessibility_abuse) {
    out.push({
      id: 'STAT-A11Y',
      title: 'Accessibility Abuse',
      severity: 'CRITICAL',
      confidence: 95,
      category: 'static',
      sourceEngine: 'Manifest',
      description: 'BIND_ACCESSIBILITY_SERVICE declared',
    });
  }
  if (data.has_sms_read_write) {
    out.push({
      id: 'STAT-SMS',
      title: 'SMS Interception',
      severity: 'CRITICAL',
      confidence: 95,
      category: 'static',
      sourceEngine: 'Manifest',
      description: 'READ/RECEIVE SMS permissions',
    });
  }
  if (data.has_system_alert_window) {
    out.push({
      id: 'STAT-OVERLAY',
      title: 'Overlay Window',
      severity: 'HIGH',
      confidence: 90,
      category: 'static',
      sourceEngine: 'Manifest',
      description: 'SYSTEM_ALERT_WINDOW capability',
    });
  }
  return out;
}

function computeCounts(
  data: FraudCardData,
  evidenceRecords: InvestigationEvidence[],
): InvestigationCounts {
  const staticFindings =
    (data.manifest_findings?.length || 0) +
    (data.code_findings?.length || 0) +
    (data.threat_scenario_table?.length || 0);
  const runtimeBehaviors = evidenceRecords.filter((e) => e.category === 'runtime').length;
  const mitreTechniques = data.intelligence_report?.mitre_techniques_used?.length || 0;
  const iocMatches = data.threat_correlation?.ioc_reputation?.length || 0;
  const familyMatches = data.family_classification !== 'Unknown' ? 1 : 0;
  const screenshots = data.dynamic_analysis?.screenshots?.length || 0;
  return {
    staticFindings,
    runtimeBehaviors,
    mitreTechniques,
    iocMatches,
    familyMatches,
    screenshots,
    evidenceRecords: evidenceRecords.length,
  };
}

export function buildInvestigationBundle(
  data: FraudCardData | null,
  rawRuntimeEvidence: RawEvidenceRecord[] = [],
): InvestigationBundle | null {
  if (!data) return null;

  const runtime = rawRuntimeEvidence.map(normalizeRuntimeRecord);
  const staticEv = buildStaticEvidence(data);
  const evidenceRecords = [...staticEv, ...runtime];

  const ledgerLines = buildLedgerLines(data);
  const timelineEvents = buildForensicTimeline(data);
  const counts = computeCounts(data, evidenceRecords);

  return {
    evidenceRecords,
    ledgerLines,
    timelineEvents,
    counts,
  };
}

export function useInvestigationModel(
  data: FraudCardData | null,
  rawRuntimeEvidence: RawEvidenceRecord[] = [],
) {
  return useMemo(
    () => buildInvestigationBundle(data, rawRuntimeEvidence),
    [data, rawRuntimeEvidence],
  );
}

export function findEvidenceById(
  bundle: InvestigationBundle | null,
  id: string,
): InvestigationEvidence | undefined {
  if (!bundle) return undefined;
  return bundle.evidenceRecords.find((e) => e.id === id || e.id.toLowerCase() === id.toLowerCase());
}
