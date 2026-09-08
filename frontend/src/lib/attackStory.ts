import type { FraudCardData, WorkflowStage } from '../App';
import type { ScreenshotManifestEntry } from './screenshotManifest';

/**
 * The fraud workflow, turned into something a bank manager can read.
 *
 * Everything here already existed. `workflow_reconstructor.py` emits thirteen
 * stage rules with human labels, plain-English descriptions, MITRE IDs,
 * millisecond bounds, evidence IDs, hook names and per-stage confidence, plus a
 * composite sequence label. It is the most executive-legible artifact the
 * platform produces.
 *
 * It rendered in exactly one place: the technical view, third tab, thirteenth
 * panel down, below the certificate table. This module does no new analysis -
 * it re-ranks what the engine already said so the story can lead the page
 * instead of trailing it.
 *
 * Nothing here fabricates. A stage with no screenshot gets no screenshot; a
 * chain the engine did not detect produces no story.
 */

export type AttackStage = {
  index: number;
  /** The engine's human-readable stage name. */
  title: string;
  /** One sentence, non-technical, describing what the app did. */
  plain: string;
  /** The engine's own longer description. */
  detail: string;
  severity: 'CRITICAL' | 'HIGH' | 'SUSPICIOUS';
  techniqueId: string;
  confidence: number;
  startMs: number;
  endMs: number;
  /** Seconds, one decimal, or null when the bounds are degenerate. */
  durationS: number | null;
  evidenceIds: string[];
  evidenceCount: number;
  hookNames: string[];
  /** Screenshot captured during this stage, when one genuinely exists. */
  screenshot: ScreenshotManifestEntry | null;
};

export type AttackStory = {
  /** Display name for the detected chain, e.g. "Full account takeover". */
  sequenceLabel: string;
  chainConfidence: number;
  totalEventsAnalyzed: number;
  stages: AttackStage[];
  techniqueIds: string[];
};

/**
 * Why each stage matters, in one sentence, for a reader who does not know what
 * an accessibility service is.
 *
 * Keyed on the engine's own stage labels, so a label the engine adds later
 * falls back to its own description rather than silently getting the wrong
 * gloss. The engine's descriptions are accurate but written for analysts
 * ("hooks AccessibilityService.onAccessibilityEvent"); these say what it means
 * for a customer's money.
 */
const PLAIN_ENGLISH: Record<string, string> = {
  'Accessibility Service Activation':
    'The app requested control over the device screen, letting it read and act on anything shown.',
  'UI Credential Scraping':
    'The app read the contents of on-screen fields, including what the user typed.',
  'Phishing Overlay Deployment':
    'The app drew its own screen on top of another app, so the user was typing into it rather than the real one.',
  'SMS / OTP Interception':
    'The app read incoming text messages, including one-time passwords, before the user saw them.',
  'SMS Forwarding / Exfiltration':
    'The app forwarded intercepted messages to a number or server outside the device.',
  'Banking App Detection':
    'The app watched for banking applications being opened, so it could act at the right moment.',
  'C2 Network Communication':
    'The app contacted an external server, which is how captured data leaves the device.',
  'Dynamic Code Loading':
    'The app downloaded and ran additional code after installation, so its true behaviour was not in the installed file.',
  'Persistence / Device Admin':
    'The app took administrative control of the device, making it difficult to remove.',
  'Launcher Icon Removal':
    'The app hid its own icon, so the user could not easily find or uninstall it.',
  'Accessibility Enabled by Sandbox':
    'Screen-control permission was granted by the analysis environment to see what the app would do with it.',
  'Overlay Permission Enabled by Sandbox':
    'Draw-over-other-apps permission was granted by the analysis environment to observe the result.',
  'Runtime Permissions Granted by Sandbox':
    'Requested permissions were granted by the analysis environment to allow the app to proceed.',
};

/** Human-readable names for the engine's composite sequence labels. */
const SEQUENCE_LABELS: Record<string, string> = {
  FULL_ACCOUNT_TAKEOVER: 'Full account takeover',
  OTP_THEFT_CHAIN: 'OTP theft chain',
  OVERLAY_PHISHING_CHAIN: 'Overlay phishing',
  DROPPER_CHAIN: 'Dropper chain',
  CREDENTIAL_SCRAPE: 'Credential scraping',
  BEHAVIORAL_ANOMALY: 'Behavioural anomaly',
  NONE: 'No sequence detected',
};

/**
 * Stages that describe the malware acting are graded on confidence. Stages that
 * describe the *sandbox* acting are not accusations at all - they are setup
 * steps - so they never render as critical.
 */
const SANDBOX_STAGES = new Set([
  'Accessibility Enabled by Sandbox',
  'Overlay Permission Enabled by Sandbox',
  'Runtime Permissions Granted by Sandbox',
]);

function severityOfStage(stage: WorkflowStage): AttackStage['severity'] {
  if (SANDBOX_STAGES.has(stage.label)) return 'SUSPICIOUS';
  if (stage.confidence >= 0.8) return 'CRITICAL';
  if (stage.confidence >= 0.6) return 'HIGH';
  return 'SUSPICIOUS';
}

/**
 * Find the screenshot that belongs to a stage.
 *
 * Three strategies, most-trustworthy first. Returns null rather than guessing -
 * an image attached to the wrong step is worse than no image, because the whole
 * point of the story is that each claim is backed by its own evidence.
 */
function screenshotForStage(
  stage: WorkflowStage,
  screenshots: ScreenshotManifestEntry[],
): ScreenshotManifestEntry | null {
  if (screenshots.length === 0) return null;

  // 1. The capture pipeline stamped the stage label on it.
  const byLabel = screenshots.find((s) => s.workflow_stage_label === stage.label);
  if (byLabel) return byLabel;

  // 2. It is linked to one of this stage's evidence records.
  if (stage.evidence_ids?.length) {
    const ids = new Set(stage.evidence_ids);
    const byEvidence = screenshots.find((s) =>
      (s.linked_evidence_ids ?? []).some((id) => ids.has(id)),
    );
    if (byEvidence) return byEvidence;
  }

  // 3. It was captured inside the stage's own time window. Requires a real
  //    window - a zero-width one would match on a coincidence.
  if (stage.end_ms > stage.start_ms) {
    const byTime = screenshots.find(
      (s) =>
        typeof s.timestamp_ms === 'number' &&
        s.timestamp_ms >= stage.start_ms &&
        s.timestamp_ms <= stage.end_ms,
    );
    if (byTime) return byTime;
  }

  return null;
}

export function buildAttackStory(
  data: FraudCardData | null,
  screenshots: ScreenshotManifestEntry[] = [],
): AttackStory | null {
  const wf = data?.fraud_workflow;
  if (!wf) return null;
  if (!wf.fraud_sequence_detected || !wf.stages?.length) return null;

  // A screenshot must not be claimed by two stages: the reader would see the
  // same image proving two different things.
  const claimed = new Set<string>();

  const stages: AttackStage[] = wf.stages.map((stage, index) => {
    const available = screenshots.filter(
      (s) => !claimed.has(s.screenshot_id ?? s.filename),
    );
    const shot = screenshotForStage(stage, available);
    if (shot) claimed.add(shot.screenshot_id ?? shot.filename);

    const span = stage.end_ms - stage.start_ms;

    return {
      index,
      title: stage.label,
      plain: PLAIN_ENGLISH[stage.label] ?? stage.description,
      detail: stage.description,
      severity: severityOfStage(stage),
      techniqueId: stage.technique_id,
      confidence: stage.confidence,
      startMs: stage.start_ms,
      endMs: stage.end_ms,
      durationS: span > 0 ? Number((span / 1000).toFixed(1)) : null,
      evidenceIds: stage.evidence_ids ?? [],
      evidenceCount: (stage.evidence_ids ?? []).length,
      hookNames: stage.hook_names ?? [],
      screenshot: shot,
    };
  });

  return {
    sequenceLabel: SEQUENCE_LABELS[wf.sequence_label] ?? wf.sequence_label,
    chainConfidence: wf.chain_confidence,
    totalEventsAnalyzed: wf.total_events_analyzed,
    stages,
    techniqueIds: Array.from(new Set(stages.map((s) => s.techniqueId))),
  };
}

/**
 * Why there is no story, when there is no story.
 *
 * The distinction this preserves is the whole point: "we analysed 1,284 events
 * and no known chain matched" and "the sandbox never ran" are different facts
 * with different implications, and the previous UI rendered both as a green
 * tick reading "no fraud workflow detected".
 */
export type NoStoryReason = {
  headline: string;
  detail: string;
  /** True when the absence says nothing about the application. */
  uninformative: boolean;
};

export function explainMissingStory(data: FraudCardData | null): NoStoryReason | null {
  if (!data) return null;
  if (buildAttackStory(data)) return null;

  const wf = data.fraud_workflow;

  if (!wf) {
    return {
      headline: 'No attack sequence reconstructed',
      detail:
        'Reconstruction requires runtime analysis, which did not produce data for this case. ' +
        'This is a statement about the analysis, not about the application.',
      uninformative: true,
    };
  }

  if (wf.total_events_analyzed === 0) {
    return {
      headline: 'No attack sequence reconstructed',
      detail:
        'The sandbox observed no runtime events at all, so there was nothing to reconstruct a ' +
        'chain from. Absence of a chain here is not evidence that the application is safe.',
      uninformative: true,
    };
  }

  return {
    headline: 'No attack sequence reconstructed',
    detail:
      `${wf.total_events_analyzed.toLocaleString()} runtime events were analysed and no known ` +
      'fraud chain matched them. Individual findings may still apply - this only means the ' +
      'events did not form a recognised sequence.',
    uninformative: false,
  };
}
