import type { FraudCardData } from '../App';
import { getVideUiState, resolveVideFromData } from './videUi';

export type TechnicalFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type TechnicalFindingId =
  | 'accessibility_abuse'
  | 'overlay_capability'
  | 'runtime_code_loading'
  | 'obfuscation'
  | 'sms_otp_interception'
  | 'banking_targeting'
  | 'network_c2'
  | 'persistence'
  | 'visual_impersonation';

export type TechnicalFindingDefinition = {
  id: TechnicalFindingId;
  title: string;
  summary: string;
  severity: TechnicalFindingSeverity;
  ledgerScope: 'stei' | 'dynamic';
  steiAxis?: 'ct' | 'bt' | 'pr' | 'ob' | 'ir';
};

const RUNTIME_LOADER_APIS = ['DexClassLoader', 'InMemoryDexClassLoader', 'PathClassLoader'];

export function apisFired(data: FraudCardData): string[] {
  return data.technical_view?.apis_fired || [];
}

export function hasRuntimeCodeLoadingSignal(data: FraudCardData): boolean {
  const apis = apisFired(data);
  if (apis.some((a) => RUNTIME_LOADER_APIS.some((l) => a.includes(l)))) return true;
  const hay = (data.code_findings || [])
    .map((f) => `${f.title} ${f.description}`)
    .join(' ')
    .toLowerCase();
  if (hay.includes('dexclassloader') || hay.includes('pathclassloader') || hay.includes('inmemorydex')) {
    return true;
  }
  const obLines = data.risk_explanation?.stei_evidence_by_axis?.ob || [];
  return obLines.some((l) => /dexclassloader|pathclassloader|dynamic dex/i.test(l));
}

export function hasObfuscationSignal(data: FraudCardData): boolean {
  if (data.has_reflection) return true;
  if ((data.obfuscation_score ?? 0) > 0.25) return true;
  const obLines = data.risk_explanation?.stei_evidence_by_axis?.ob || [];
  if (obLines.some((l) => /entropy|reflection|obfus/i.test(l))) return true;
  return (data.code_findings || []).some((f) => /obfus|entropy|reflection/i.test(`${f.title} ${f.description}`));
}

export function hasNetworkC2Signal(data: FraudCardData): boolean {
  if ((data.hardcoded_urls_ips?.length ?? 0) > 0) return true;
  const ir = data.risk_explanation?.stei_evidence_by_axis?.ir || [];
  if (ir.length > 0) return true;
  const corr = data.threat_correlation;
  if (corr?.suspicious_domains?.length || corr?.malicious_ips?.length) return true;
  return false;
}

export function hasPersistenceSignal(data: FraudCardData): boolean {
  const perms = data.all_permissions || [];
  if (perms.some((p) => p.includes('RECEIVE_BOOT_COMPLETED') || p.includes('BIND_DEVICE_ADMIN'))) {
    return true;
  }
  const manifestHay = (data.manifest_findings || [])
    .map((f) => `${f.title} ${f.description}`)
    .join(' ')
    .toLowerCase();
  if (/boot|device admin|deviceadmin|persistent/i.test(manifestHay)) return true;
  return (data.receivers || []).some((r) => /boot/i.test(r));
}

export function isFindingDetected(id: TechnicalFindingId, data: FraudCardData): boolean {
  switch (id) {
    case 'accessibility_abuse':
      return data.has_accessibility_abuse;
    case 'overlay_capability':
      return data.has_system_alert_window;
    case 'sms_otp_interception':
      return data.has_sms_read_write;
    case 'runtime_code_loading':
      return hasRuntimeCodeLoadingSignal(data);
    case 'obfuscation':
      return hasObfuscationSignal(data);
    case 'banking_targeting':
      return (
        data.targets_indian_banks ||
        (data.intelligence_report?.affected_banking_apps?.length ?? 0) > 0
      );
    case 'network_c2':
      return hasNetworkC2Signal(data);
    case 'persistence':
      return hasPersistenceSignal(data);
    case 'visual_impersonation': {
      const vide = resolveVideFromData(data);
      return getVideUiState(vide) === 'detected';
    }
    default:
      return false;
  }
}

export const TECHNICAL_FINDING_DEFINITIONS: TechnicalFindingDefinition[] = [
  {
    id: 'accessibility_abuse',
    title: 'Accessibility Service Abuse',
    summary:
      "Allows malware to control the phone without the user's knowledge - including reading banking screens and automating taps.",
    severity: 'critical',
    ledgerScope: 'stei',
    steiAxis: 'ct',
  },
  {
    id: 'overlay_capability',
    title: 'Overlay Window Capability',
    summary: 'Can display fake banking login screens over legitimate apps.',
    severity: 'high',
    ledgerScope: 'stei',
    steiAxis: 'ct',
  },
  {
    id: 'runtime_code_loading',
    title: 'Runtime Code Loading',
    summary: 'Downloads or loads hidden code after installation, evading static inspection.',
    severity: 'medium',
    ledgerScope: 'stei',
    steiAxis: 'ob',
  },
  {
    id: 'obfuscation',
    title: 'Obfuscation',
    summary: "Makes the application's code difficult to inspect and reverse-engineer.",
    severity: 'medium',
    ledgerScope: 'stei',
    steiAxis: 'ob',
  },
  {
    id: 'sms_otp_interception',
    title: 'SMS & OTP Interception',
    summary: 'SMS read permissions may allow theft of one-time passwords sent by banks.',
    severity: 'critical',
    ledgerScope: 'stei',
    steiAxis: 'ct',
  },
  {
    id: 'banking_targeting',
    title: 'Banking Targeting',
    summary: 'References or targets known financial applications.',
    severity: 'high',
    ledgerScope: 'stei',
    steiAxis: 'bt',
  },
  {
    id: 'network_c2',
    title: 'Network / C2 Indicators',
    summary: 'Hardcoded or observed network endpoints may indicate command-and-control infrastructure.',
    severity: 'medium',
    ledgerScope: 'stei',
    steiAxis: 'ir',
  },
  {
    id: 'persistence',
    title: 'Persistence Mechanisms',
    summary: 'Boot receivers or device-admin capabilities can keep malware active after reboot.',
    severity: 'medium',
    ledgerScope: 'stei',
    steiAxis: 'pr',
  },
  {
    id: 'visual_impersonation',
    title: 'Visual Impersonation (VIDE)',
    summary: 'Interface similarity to protected banking applications (deterministic VIDE match).',
    severity: 'critical',
    ledgerScope: 'stei',
    steiAxis: 'bt',
  },
];

export function getFindingDefinition(id: TechnicalFindingId): TechnicalFindingDefinition {
  const def = TECHNICAL_FINDING_DEFINITIONS.find((d) => d.id === id);
  if (!def) throw new Error(`Unknown finding: ${id}`);
  return def;
}

export const CORE_FINDING_IDS: TechnicalFindingId[] = [
  'accessibility_abuse',
  'overlay_capability',
  'runtime_code_loading',
  'obfuscation',
  'sms_otp_interception',
];

export const OPTIONAL_FINDING_IDS: TechnicalFindingId[] = [
  'banking_targeting',
  'network_c2',
  'persistence',
  'visual_impersonation',
];

export function visibleFindingDefinitions(data: FraudCardData): TechnicalFindingDefinition[] {
  const core = CORE_FINDING_IDS.map(getFindingDefinition);
  const optional = OPTIONAL_FINDING_IDS.filter((id) => isFindingDetected(id, data)).map(getFindingDefinition);
  return [...core, ...optional];
}

export const SEVERITY_DISPLAY: Record<string, string> = {
  critical: 'Critical Risk',
  high: 'High Risk',
  medium: 'Moderate Risk',
  low: 'Lower Risk',
};
