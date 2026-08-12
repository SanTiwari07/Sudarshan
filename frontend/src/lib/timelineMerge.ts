import type { FraudCardData } from '../App';
import type { ScreenshotManifestEntry } from './screenshotManifest';
import type { TimelineEvent } from '../types/investigation';
import { isTimelineEligibleVisual, visualFromEntry } from './visualEvidence';

function msFromUnknown(ts: unknown): number {
  if (typeof ts === 'number') return ts;
  if (typeof ts === 'string') {
    const n = Date.parse(ts);
    return Number.isNaN(n) ? 0 : n;
  }
  return 0;
}

export function buildForensicTimeline(data: FraudCardData): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  const dyn = data.dynamic_analysis;

  events.push({
    id: 'TL-STATIC-0',
    timestampMs: 0,
    label: 'Static analysis complete',
    source: 'STATIC',
    category: 'analysis',
    evidenceIds: [],
    kind: 'forensic',
  });

  if (data.has_accessibility_abuse) {
    events.push({
      id: 'TL-MAN-A11Y',
      timestampMs: 1,
      label: 'Accessibility service declared (manifest)',
      source: 'MANIFEST',
      category: 'permission',
      evidenceIds: [],
      contributionLabel: 'CT',
      kind: 'forensic',
    });
  }

  const attack = dyn?.attack_timeline || [];
  attack.forEach((row, i) => {
    if (!row || typeof row !== 'object') return;
    const ts = msFromUnknown(row.timestamp ?? row.timestamp_ms ?? row.time);
    const evidenceId = row.data?.evidence_id || row.evidence_id;
    events.push({
      id: `TL-ATK-${i}`,
      timestampMs: ts || i * 1000,
      label: String(row.action || row.event || row.label || 'Runtime event'),
      source: String(row.source || 'FRIDA'),
      category: String(row.category || 'runtime'),
      evidenceIds: evidenceId ? [String(evidenceId)] : [],
      kind: 'forensic',
    });
  });

  const workflow = data.fraud_workflow;
  if (workflow?.stages) {
    workflow.stages.forEach((stage, i) => {
      events.push({
        id: `TL-WF-${i}`,
        timestampMs: stage.start_ms || i * 2000,
        label: stage.label,
        source: 'WORKFLOW',
        category: stage.technique_id,
        evidenceIds: stage.evidence_ids || [],
        kind: 'workflow',
      });
    });
  }

  events.push({
    id: 'TL-SCORE-FINAL',
    timestampMs: Date.now(),
    label: `Risk score: ${data.final_risk_score.toFixed(0)} (${data.risk_band})`,
    source: 'RISK_ENGINE',
    category: 'score',
    evidenceIds: [],
    contributionLabel: `FRS ${data.final_risk_score.toFixed(0)}`,
    kind: 'score',
  });

  return events.sort((a, b) => a.timestampMs - b.timestampMs);
}

export function appendVisualTimelineEvents(
  events: TimelineEvent[],
  screenshotEntries: ScreenshotManifestEntry[] = [],
): TimelineEvent[] {
  const merged = [...events];
  for (const entry of screenshotEntries) {
    if (!isTimelineEligibleVisual(entry)) continue;
    const ve = visualFromEntry(entry);
    if (!ve) continue;
    merged.push({
      id: `TL-VIS-${entry.screenshot_id}`,
      timestampMs: entry.timestamp_ms ?? ve.timestamp_ms ?? 0,
      label: ve.investigative_claim?.slice(0, 120) || entry.screenshot_id,
      source: 'VISUAL',
      category: ve.claim_type || 'visual_evidence',
      evidenceIds: [...(ve.linked_evidence_ids || [])],
      kind: 'forensic',
      screenshotId: entry.screenshot_id,
      visualClaim: ve.investigative_claim,
      correlationStatus: ve.correlation_status,
    });
  }
  return merged.sort((a, b) => a.timestampMs - b.timestampMs);
}

export function formatTimelineOffset(ms: number, baseMs: number): string {
  const deltaSec = Math.max(0, Math.floor((ms - baseMs) / 1000));
  const mm = String(Math.floor(deltaSec / 60)).padStart(2, '0');
  const ss = String(deltaSec % 60).padStart(2, '0');
  return `${mm}:${ss}`;
}
