import type { FraudCardData } from '../App';
import type { InvestigationBundle, InvestigationEvidence } from '../types/investigation';
import { axisDisplayName } from './evidenceParser';
import { computeWeightedContribution, getAxesUsed } from './scoreLedger';
import { resolveRuntimeDynamicStatus, runtimeStatusHeadline } from './investigationRuntime';
import { getVideUiState, resolveVideFromData, videConfidenceValue } from './videUi';
import type { MergedThreatIntel } from './intelPayloadMerge';

export type ScoreInfluenceAxis = 'static' | 'dynamic' | 'threat_intel' | 'vide';

const FRS_AXIS_SCOPE: Partial<Record<ScoreInfluenceAxis, string>> = {
  static: 'stei',
  dynamic: 'dynamic',
  threat_intel: 'correlation',
  vide: 'dynamic',
};

export function influenceLabel(score: number, included: boolean): string {
  if (!included) return 'Not included';
  if (score >= 60) return 'Strong influence';
  if (score >= 35) return 'Moderate influence';
  if (score > 0) return 'Limited influence';
  return 'Minimal influence';
}

export type FrsAxisRow = {
  key: string;
  label: string;
  included: boolean;
  reason?: string;
  weightPct: number | null;
};

export function buildFrsAxisTransparency(
  dataOrScope: FraudCardData | ScoreInfluenceAxis,
  data?: FraudCardData,
): FrsAxisRow[] {
  const scope = data !== undefined ? (dataOrScope as ScoreInfluenceAxis) : undefined;
  const caseData = data ?? (dataOrScope as FraudCardData);
  const frs = caseData.frs_breakdown;
  if (!frs) return [];
  const axesUsed = getAxesUsed(caseData);
  const excluded = frs.axes_excluded ?? [];
  const rows: { key: string; label: string }[] = [
    { key: 'stei', label: 'Static (STEI)' },
    { key: 'dynamic', label: 'Runtime (BFCI)' },
    { key: 'correlation', label: 'Threat intelligence' },
    { key: 'banking_impact', label: 'Banking impact' },
  ];
  const built = rows.map(({ key, label }) => {
    const included = !excluded.includes(key);
    let reason: string | undefined;
    if (!included && key === 'dynamic') reason = 'Inconclusive runtime evidence';
    if (!included && key === 'correlation') reason = 'Threat correlation unavailable';
    return {
      key,
      label,
      included,
      reason,
      weightPct: included ? (axesUsed[key] ?? 0) * 100 : null,
    };
  });
  if (!scope) return built;
  const frsKey = FRS_AXIS_SCOPE[scope];
  return frsKey ? built.filter((row) => row.key === frsKey) : built;
}

export type StaticFindingRow = {
  id: string;
  title: string;
  detected: string;
  whyItMatters: string;
  evidence: string;
  evidenceId?: string;
};

export type StaticEngineRow = {
  name: string;
  status: 'available' | 'unavailable';
  bullets: string[];
};

export type StaticInfluenceView = {
  score: number;
  influence: string;
  tagline: string;
  whyScore: string;
  findings: StaticFindingRow[];
  engines: StaticEngineRow[];
  steiAxes: { ct: number; bt: number; pr: number; ob: number; ir: number };
  steiTotal: number;
  frsWeightPct: number | null;
  frsContribution: number | null;
  hasVide: boolean;
  videSummary?: string;
  unavailable: boolean;
};

const CAPABILITY_COPY: Record<string, { why: string; detect: (d: FraudCardData) => string | null }> = {
  accessibility: {
    why: 'Can read UI content and automate actions in other apps - common in banking trojans.',
    detect: (d) => (d.has_accessibility_abuse ? 'BIND_ACCESSIBILITY_SERVICE / accessibility-related manifest signals' : null),
  },
  sms: {
    why: 'May intercept one-time passwords sent by SMS.',
    detect: (d) => (d.has_sms_read_write ? 'READ_SMS / RECEIVE_SMS or equivalent permissions' : null),
  },
  overlay: {
    why: 'Can draw over other apps, enabling fake login screens.',
    detect: (d) => (d.has_system_alert_window ? 'SYSTEM_ALERT_WINDOW capability declared' : null),
  },
  banking: {
    why: 'References or targets known banking / UPI package names.',
    detect: (d) => (d.targets_indian_banks ? 'Banking package references in static analysis' : null),
  },
};

function pushFinding(
  out: StaticFindingRow[],
  row: Omit<StaticFindingRow, 'id'> & { id?: string },
): void {
  out.push({ id: row.id || `finding-${out.length}`, ...row });
}

export function buildStaticInfluenceView(data: FraudCardData): StaticInfluenceView {
  const frs = data.frs_breakdown;
  const score = frs?.stei ?? 0;
  const axesUsed = getAxesUsed(data);
  const included = !frs?.axes_excluded?.includes('stei');
  const findings: StaticFindingRow[] = [];

  for (const [key, meta] of Object.entries(CAPABILITY_COPY)) {
    const det = meta.detect(data);
    if (det) {
      pushFinding(findings, {
        id: `cap-${key}`,
        title: key === 'accessibility' ? 'Accessibility abuse' : key === 'sms' ? 'SMS read/write' : key === 'overlay' ? 'Overlay capability' : 'Banking targeting',
        detected: det,
        whyItMatters: meta.why,
        evidence: det,
        evidenceId: key === 'accessibility' ? 'STAT-A11Y' : key === 'sms' ? 'STAT-SMS' : key === 'overlay' ? 'STAT-OVERLAY' : undefined,
      });
    }
  }

  data.dangerous_permissions?.slice(0, 12).forEach((p, i) => {
    pushFinding(findings, {
      id: `perm-${i}`,
      title: p.short || 'Dangerous permission',
      detected: p.permission,
      whyItMatters: p.description || p.info || 'Elevated permission risk in static inspection.',
      evidence: `${p.permission} - ${p.status}`,
    });
  });

  data.manifest_findings?.forEach((f, i) => {
    if (!f?.title) return;
    pushFinding(findings, {
      id: `man-${i}`,
      title: f.title,
      detected: f.description || f.title,
      whyItMatters: 'Manifest-declared component or permission risk.',
      evidence: f.component ? `${f.component}: ${f.description}` : f.description,
    });
  });

  data.code_findings?.slice(0, 15).forEach((f, i) => {
    if (!f?.title) return;
    pushFinding(findings, {
      id: `code-${i}`,
      title: f.title,
      detected: f.description || f.title,
      whyItMatters: f.cwe ? `Mapped to ${f.cwe}` : 'Suspicious code pattern in decompiled sources.',
      evidence: f.files?.length ? `${f.files.join(', ')}` : f.description,
    });
  });

  data.technical_view?.apis_fired?.slice(0, 8).forEach((api, i) => {
    pushFinding(findings, {
      id: `api-${i}`,
      title: 'Suspicious API signature',
      detected: api,
      whyItMatters: 'API usage associated with fraud or overlay/credential patterns.',
      evidence: api,
    });
  });

  data.hardcoded_urls_ips?.slice(0, 6).forEach((u, i) => {
    pushFinding(findings, {
      id: `url-${i}`,
      title: 'Hardcoded URL / host',
      detected: u,
      whyItMatters: 'Static infrastructure indicator - does not prove live C2 without runtime/network proof.',
      evidence: u,
    });
  });

  const engines: StaticEngineRow[] = [];
  const mobsfOn = data.analysis_mode?.toLowerCase().includes('mobsf') || Boolean(data.mobsf_scan_hash);
  const codeCount = data.code_findings?.length ?? 0;
  const manCount = data.manifest_findings?.length ?? 0;
  engines.push({
    name: 'MobSF',
    status: mobsfOn ? 'available' : 'unavailable',
    bullets: mobsfOn
      ? [
          codeCount ? `${codeCount} code/security findings` : 'MobSF scan contributed to static review',
          data.appsec_score != null ? `AppSec score: ${data.appsec_score}` : '',
        ].filter(Boolean)
      : ['Not available - this source did not contribute to the score.'],
  });
  engines.push({
    name: 'Native APK / Androguard parser',
    status: 'available',
    bullets: [
      manCount ? `${manCount} manifest findings` : 'Manifest and permission extraction',
      `${data.all_permissions?.length ?? 0} permissions reviewed`,
    ],
  });
  const apktool = data.apktool_enrichment as Record<string, unknown> | undefined;
  const jadx = data.jadx_enrichment as Record<string, unknown> | undefined;
  const apktoolHits = (apktool?.banking_strings as string[] | undefined)?.length ?? 0;
  engines.push({
    name: 'APKTool',
    status: apktool ? 'available' : 'unavailable',
    bullets: apktool
      ? [apktoolHits ? `${apktoolHits} banking-related strings` : 'Decoded resources / manifest enrichment'].filter(Boolean)
      : ['Not available - this source did not contribute to the score.'],
  });
  const jadxHits = (jadx?.fraud_class_hits as string[] | undefined)?.length ?? 0;
  engines.push({
    name: 'JADX',
    status: jadx ? 'available' : 'unavailable',
    bullets: jadx
      ? [jadxHits ? `${jadxHits} suspicious class references` : 'Decompiled source review'].filter(Boolean)
      : ['Not available - this source did not contribute to the score.'],
  });

  const steiAxes = frs?.stei_axes ?? { ct: 0, bt: 0, pr: 0, ob: 0, ir: 0 };
  const vide = resolveVideFromData(data);
  const videState = getVideUiState(vide);
  let videSummary: string | undefined;
  if (vide && videState !== 'missing') {
    const conf = videConfidenceValue(vide);
    videSummary =
      videState === 'detected'
        ? `Visual impersonation detected (VIDE). Confidence ${conf != null ? `${(conf * 100).toFixed(1)}%` : '-'}.`
        : 'VIDE ran against laboratory UI baselines; no impersonation rule fired.';
  }

  const findingCount = findings.length;
  const tagline =
    findingCount > 0
      ? `${findingCount} static indicator${findingCount === 1 ? '' : 's'} fed the STEI axis.`
      : 'Limited static indicators were recorded for this sample.';

  return {
    score,
    influence: influenceLabel(score, included),
    tagline,
    whyScore:
      data.risk_explanation?.component_evidence?.stei?.[0] ||
      (findingCount > 0
        ? 'The static engine flagged capabilities and permissions associated with fraud malware.'
        : 'Static analysis completed with minimal scored indicators.'),
    findings,
    engines,
    steiAxes,
    steiTotal: score,
    frsWeightPct: included ? (axesUsed.stei ?? 0) * 100 : null,
    frsContribution: included ? computeWeightedContribution('stei', score, axesUsed) : null,
    hasVide: Boolean(vide && videState !== 'missing'),
    videSummary,
    unavailable: !frs,
  };
}

export type RuntimeEventGroup = {
  label: string;
  count: number;
  events: InvestigationEvidence[];
};

const RUNTIME_GROUPS: { label: string; keywords: string[] }[] = [
  { label: 'Accessibility', keywords: ['accessibility', 'a11y', 'accessibilityservice'] },
  { label: 'SMS', keywords: ['sms', 'otp', 'telephony'] },
  { label: 'Overlay', keywords: ['overlay', 'system_alert', 'windowmanager'] },
  { label: 'Banking', keywords: ['bank', 'upi', 'payment', 'credential'] },
  { label: 'Network / C2', keywords: ['http', 'socket', 'network', 'c2', 'url'] },
  { label: 'Persistence', keywords: ['boot', 'receiver', 'alarm', 'persist'] },
  { label: 'Dynamic code loading', keywords: ['dex', 'classloader', 'invoke-dynamic', 'loadclass'] },
];

function bucketRuntimeEvents(events: InvestigationEvidence[]): RuntimeEventGroup[] {
  const groups: RuntimeEventGroup[] = RUNTIME_GROUPS.map((g) => ({ label: g.label, count: 0, events: [] }));
  const other: InvestigationEvidence[] = [];
  for (const ev of events) {
    const hay = `${ev.title} ${ev.description} ${ev.hookNames?.join(' ') || ''}`.toLowerCase();
    const idx = RUNTIME_GROUPS.findIndex((g) => g.keywords.some((k) => hay.includes(k)));
    if (idx >= 0) {
      groups[idx].events.push(ev);
      groups[idx].count += 1;
    } else {
      other.push(ev);
    }
  }
  if (other.length) groups.push({ label: 'Other', count: other.length, events: other });
  return groups.filter((g) => g.count > 0);
}

export type RuntimeInfluenceView = {
  includedInFrs: boolean;
  influence: string;
  tagline: string;
  statusHeadline: string;
  observedScore: number | null;
  frsContribution: number | null;
  telemetry: { label: string; value: string }[];
  eventGroups: RuntimeEventGroup[];
  exclusionReason: string | null;
  conclusiveHints: string[];
  unavailable: boolean;
};

export function buildRuntimeInfluenceView(data: FraudCardData, bundle: InvestigationBundle | null): RuntimeInfluenceView {
  const frs = data.frs_breakdown;
  const dyn =
    (data.dynamic_result && typeof data.dynamic_result === 'object' && !Array.isArray(data.dynamic_result)
      ? data.dynamic_result
      : data.dynamic_analysis) || {};
  const d = dyn as Record<string, unknown>;
  const status = resolveRuntimeDynamicStatus(data);
  const includedInFrs = Boolean(frs?.dynamic_conclusive && !frs.axes_excluded?.includes('dynamic'));
  const bfci =
    typeof d.bfci === 'number' ? d.bfci : typeof frs?.dynamic === 'number' ? frs.dynamic : null;
  const axesUsed = getAxesUsed(data);

  const telemetry: { label: string; value: string }[] = [];
  if (d.engine) telemetry.push({ label: 'Instrumentation', value: String(d.engine) });
  if (d.canary_received != null) telemetry.push({ label: 'Canary', value: d.canary_received ? 'Received' : 'Not received' });
  if (d.dynamic_status) telemetry.push({ label: 'Sandbox status', value: String(d.dynamic_status) });
  const eventCount =
    (d.evidence_record_count as number) ||
    bundle?.counts.runtimeBehaviors ||
    (Array.isArray(d.api_calls) ? d.api_calls.length : 0);
  telemetry.push({ label: 'Events captured', value: String(eventCount) });
  if (Array.isArray(d.hook_errors)) telemetry.push({ label: 'Hook errors', value: String(d.hook_errors.length) });
  const shots = (d.screenshots as string[] | undefined)?.length ?? data.dynamic_analysis?.screenshots?.length ?? 0;
  if (shots) telemetry.push({ label: 'Screenshots', value: String(shots) });
  if (data.fraud_workflow?.stage_count) {
    telemetry.push({ label: 'Workflow stages', value: String(data.fraud_workflow.stage_count) });
  }

  const runtimeEvents = bundle?.evidenceRecords.filter((e) => e.category === 'runtime') ?? [];
  const eventGroups = bucketRuntimeEvents(runtimeEvents);

  let exclusionReason: string | null = null;
  if (frs?.dynamic_ran && !includedInFrs) {
    exclusionReason =
      'Runtime analysis executed, but the run did not produce sufficient conclusive behavioral evidence. The risk engine excluded the dynamic axis and renormalized remaining FRS weights - observed BFCI is not treated as zero proof of benign behavior.';
  }

  const conclusiveHints = [
    'Successful Frida instrumentation with hooks loaded',
    'Sufficient behavioral events in api_calls / network_logs / activities_triggered',
    'BFCI ≥ 20 with observable sample behavior',
    'Evidence records stored for the sandbox run',
  ];

  return {
    includedInFrs,
    influence: includedInFrs ? influenceLabel(bfci ?? 0, true) : 'Not included',
    tagline: includedInFrs
      ? 'Observed sandbox behaviour contributed to the fraud risk score.'
      : 'Runtime execution was inconclusive - axis excluded from final FRS.',
    statusHeadline: runtimeStatusHeadline(status).toUpperCase(),
    observedScore: frs?.dynamic_ran && bfci != null ? bfci : null,
    frsContribution: includedInFrs && bfci != null ? computeWeightedContribution('dynamic', bfci, axesUsed) : null,
    telemetry,
    eventGroups,
    exclusionReason,
    conclusiveHints,
    unavailable: !frs?.dynamic_ran && status === 'NOT_STARTED',
  };
}

export function buildStaticCardSummary(data: FraudCardData): string {
  const v = buildStaticInfluenceView(data);
  return v.findings.length > 0
    ? 'Suspicious capabilities were identified inside the APK.'
    : 'Static analysis completed with limited scored indicators.';
}

export function buildThreatCardSummary(data: FraudCardData): string {
  const corr = data.threat_correlation;
  if (data.frs_breakdown?.axes_excluded?.includes('correlation')) {
    return 'Threat correlation was unavailable for this case.';
  }
  if (corr?.ioc_reputation?.length) {
    return `${corr.ioc_reputation.length} indicator${corr.ioc_reputation.length === 1 ? '' : 's'} correlated with external intelligence.`;
  }
  return 'Threat intelligence patterns contributed evidence to the investigation.';
}

export function steiAxisRows(axes: StaticInfluenceView['steiAxes']): { key: string; label: string; value: number; weight: string }[] {
  const weights: Record<string, string> = { ct: '60%', bt: '20%', pr: '10%', ob: '5%', ir: '5%' };
  return (['ct', 'bt', 'pr', 'ob', 'ir'] as const).map((key) => ({
    key,
    label: axisDisplayName(key),
    value: axes[key],
    weight: weights[key],
  }));
}

export type ThreatInfluenceView = {
  score: number;
  threatScore: number;
  influence: string;
  tagline: string;
  axisIncluded: boolean;
  merged: MergedThreatIntel;
  family: string;
  matchedRule: string;
  familySignals: string[];
};

export function buildThreatInfluenceView(data: FraudCardData, merged: MergedThreatIntel): ThreatInfluenceView {
  const frs = data.frs_breakdown;
  const score = frs?.correlation ?? merged.correlationScore ?? merged.threatScore ?? 0;
  const axisIncluded = merged.axisIncluded;
  const signals: string[] = [];
  if (data.has_accessibility_abuse) signals.push('Accessibility declared');
  if (data.has_sms_read_write) signals.push('SMS read/write');
  if (data.has_system_alert_window) signals.push('SYSTEM_ALERT_WINDOW');
  if (data.targets_indian_banks) signals.push('Banking package targeting');

  return {
    score,
    threatScore: score,
    influence: influenceLabel(score, axisIncluded),
    tagline: buildThreatCardSummary(data),
    axisIncluded,
    merged,
    family: data.family_classification,
    matchedRule: data.technical_view?.matched_rule || '-',
    familySignals: signals,
  };
}
