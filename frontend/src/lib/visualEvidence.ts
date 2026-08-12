import type { ScreenshotManifestEntry } from './screenshotManifest';

export type VisualEvidencePayload = {
  screenshot_id?: string;
  claim_type?: string;
  investigative_claim?: string;
  claim?: string;
  quality?: string;
  priority?: string;
  correlation_status?: string;
  linked_evidence_ids?: string[];
  linked_finding_keys?: string[];
  workflow_stage_label?: string;
  report_tier?: string;
  timeline_eligible?: boolean;
  png_sha256?: string;
  timestamp_ms?: number;
  capture_trigger?: string;
};

const MEANINGFUL_CORRELATION = new Set(['causal', 'linked', 'temporal']);

export function visualFromEntry(entry: ScreenshotManifestEntry): VisualEvidencePayload | null {
  const ve = entry.visual_evidence;
  if (ve) return ve;
  if (entry.claim_type || entry.investigative_claim) {
    return {
      screenshot_id: entry.screenshot_id,
      claim_type: entry.claim_type,
      investigative_claim: entry.investigative_claim,
      quality: entry.quality,
      priority: entry.priority,
      correlation_status: entry.correlation_status,
      linked_evidence_ids: entry.linked_evidence_ids,
      linked_finding_keys: entry.linked_finding_keys,
      workflow_stage_label: entry.workflow_stage_label,
      report_tier: entry.report_tier,
      timeline_eligible: entry.timeline_eligible,
      capture_trigger: entry.capture_trigger,
      timestamp_ms: entry.timestamp_ms,
    };
  }
  return null;
}

export function isTimelineEligibleVisual(entry: ScreenshotManifestEntry): boolean {
  const ve = visualFromEntry(entry);
  if (!ve) return false;
  if (!ve.timeline_eligible) return false;
  const q = ve.quality || '';
  if (q !== 'A' && q !== 'B') return false;
  const corr = ve.correlation_status || '';
  if (corr === 'unresolved' || corr === 'not_applicable') return false;
  return MEANINGFUL_CORRELATION.has(corr);
}

export function illustratedByFinding(
  findingKey: string,
  entries: ScreenshotManifestEntry[],
): ScreenshotManifestEntry[] {
  return entries.filter((e) => {
    const ve = visualFromEntry(e);
    if (!ve) return false;
    return (ve.linked_finding_keys || []).includes(findingKey);
  });
}

export function illustratedByEvidenceId(
  evidId: string,
  entries: ScreenshotManifestEntry[],
): ScreenshotManifestEntry[] {
  return entries.filter((e) => {
    const ve = visualFromEntry(e);
    if (!ve) return false;
    return (ve.linked_evidence_ids || []).includes(evidId);
  });
}

export function executiveVisualEntries(entries: ScreenshotManifestEntry[]): ScreenshotManifestEntry[] {
  return entries
    .filter((e) => {
      const ve = visualFromEntry(e);
      return ve?.report_tier === 'executive_key' && (ve.quality === 'A' || ve.quality === 'B');
    })
    .slice(0, 2);
}

export function correlationRank(corr?: string): number {
  if (corr === 'causal') return 0;
  if (corr === 'linked') return 1;
  if (corr === 'temporal') return 2;
  return 9;
}
