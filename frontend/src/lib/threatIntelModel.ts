import type { FraudCardData } from '../types/case';
import type { InvestigationBundle } from '../types/investigation';

export type IntelApiPayload = {
  available: boolean;
  mode: 'dynamic' | 'static';
  sha256: string;
  package_name: string;
  app_name: string;
  threat_score: number;
  malware_family: string;
  family_rule_matched: string;
  campaign: string;
  confidence: number;
  risk_band: string;
  sources: string[];
  sources_status: { name: string; status: string; message: string }[];
  virus_total: {
    available: boolean;
    malicious: number;
    total: number;
    ratio: number;
    permalink: string;
    vendors: string[];
    reputation: number;
    suggested_label?: string;
  };
  alienvault: {
    available: boolean;
    pulse_count: number;
    campaign: string;
    pulses: unknown[];
  };
  abuseipdb: { available: boolean; confidence: number; reports: number };
  iocs: {
    type: string;
    value: string;
    severity: string;
    source: string;
    reputation: string;
  }[];
  timeline: { step: string; status: string; timestamp: string; detail: string }[];
  ai_summary: string;
};

/**
 * How a fraud behaviour was established, in descending strength.
 *
 * This replaced a `percent` field whose values were literals chosen per branch
 * (95 / 72 / 55 / 8 for credential theft, 92 / 81 / 60 / 0 for overlay, and so
 * on). The booleans behind them are real, but nothing measures "72% credential
 * theft" - the panel rendered invented precision as a confidence meter. The
 * four states below are exactly what the underlying signals can support.
 */
export type DnaObservation =
  | 'runtime_observed'
  | 'statically_declared'
  | 'inferred'
  | 'not_observed';

export type DnaTrait = {
  label: string;
  observation: DnaObservation;
  evidenceIds: string[];
  rationale: string;
};

const DNA_OBSERVATION_RANK: Record<DnaObservation, number> = {
  runtime_observed: 3,
  statically_declared: 2,
  inferred: 1,
  not_observed: 0,
};

export function dnaObservationRank(observation: DnaObservation): number {
  return DNA_OBSERVATION_RANK[observation];
}

/** True when any signal at all backed the behaviour. */
export function dnaTraitDetected(trait: DnaTrait | undefined): boolean {
  return trait != null && trait.observation !== 'not_observed';
}

export type AttackStage = {
  id: string;
  label: string;
  detected: boolean;
  evidenceIds: string[];
  detail?: string;
};

export type FamilySimilarity = {
  family: string;
  percent: number;
  reasons: string[];
  isAssigned: boolean;
};

export type BankingRow = {
  id: string;
  label: string;
  status: 'detected' | 'possible' | 'unknown' | 'not_targeted';
  evidenceCount: number;
  evidenceHint: string;
};

export type ConfidenceSource = {
  label: string;
  percent: number | null;
  status: 'ok' | 'partial' | 'unavailable';
  detail: string;
};

export type MitreCard = {
  technique: string;
  techniqueId?: string;
  /** Absent when no evidence record backing the technique reported one. */
  confidence?: number;
  evidence: string;
  source: string;
  evidenceIds: string[];
};

export type AnalystAction = {
  label: string;
  evidenceRef: string;
  priority: 'high' | 'medium' | 'low';
};

export type InfrastructureSummary = {
  domains: string[];
  ips: string[];
  urls: string[];
  certificates: string[];
  countries: string[];
  asns: string[];
  hosting: string[];
};

const BANKING_ECOSYSTEM: { id: string; label: string; patterns: string[] }[] = [
  { id: 'boi', label: 'Bank of India', patterns: ['com.boi', 'bankofindia'] },
  { id: 'sbi', label: 'SBI', patterns: ['com.sbi', 'sbi.lotus'] },
  { id: 'icici', label: 'ICICI', patterns: ['com.icici'] },
  { id: 'hdfc', label: 'HDFC', patterns: ['com.hdfc'] },
  { id: 'axis', label: 'Axis', patterns: ['com.axis'] },
  { id: 'kotak', label: 'Kotak', patterns: ['com.kotak'] },
  { id: 'canara', label: 'Canara', patterns: ['com.canara'] },
  { id: 'phonepe', label: 'PhonePe', patterns: ['phonepe', 'com.phonepe'] },
  { id: 'gpay', label: 'Google Pay', patterns: ['com.google.android.apps.nbu', 'gpay'] },
  { id: 'bhim', label: 'BHIM', patterns: ['npci', 'bhim', 'upiapp'] },
  { id: 'paytm', label: 'Paytm', patterns: ['paytm', 'net.one97'] },
  { id: 'amazonpay', label: 'Amazon Pay', patterns: ['amazonpay', 'in.amazon'] },
];

const FAMILY_RULES: { family: string; conditions: { key: string; test: (d: FraudCardData) => boolean; label: string }[] }[] = [
  {
    family: 'Xenomorph',
    conditions: [
      { key: 'a11y', test: (d) => d.has_accessibility_abuse, label: 'Accessibility abuse' },
      { key: 'sms', test: (d) => d.has_sms_read_write, label: 'SMS read/write' },
      { key: 'bank', test: (d) => d.targets_indian_banks, label: 'Banking package match' },
    ],
  },
  {
    family: 'Cerberus',
    conditions: [
      { key: 'overlay', test: (d) => d.has_system_alert_window, label: 'Overlay window' },
      { key: 'sms', test: (d) => d.has_sms_read_write, label: 'SMS read/write' },
      { key: 'bank', test: (d) => d.targets_indian_banks, label: 'Banking package match' },
    ],
  },
  {
    family: 'Anubis',
    conditions: [
      { key: 'a11y', test: (d) => d.has_accessibility_abuse, label: 'Accessibility abuse' },
      { key: 'js', test: (d) => apiFired(d, 'addJavascriptInterface'), label: 'WebView injection API' },
    ],
  },
  {
    family: 'Hydra',
    conditions: [
      { key: 'a11y', test: (d) => d.has_accessibility_abuse, label: 'Accessibility abuse' },
      { key: 'overlay', test: (d) => d.has_system_alert_window, label: 'Overlay window' },
    ],
  },
  {
    family: 'SpyNote',
    conditions: [
      { key: 'a11y', test: (d) => d.has_accessibility_abuse, label: 'Accessibility abuse' },
      { key: 'exec', test: (d) => apiFired(d, 'Runtime.exec'), label: 'Command execution API' },
    ],
  },
  {
    family: 'Joker',
    conditions: [
      { key: 'sms', test: (d) => d.has_sms_read_write, label: 'SMS read/write' },
      { key: 'native', test: (d) => apiFired(d, 'System.loadLibrary'), label: 'Native library load' },
    ],
  },
  {
    family: 'Drinik',
    conditions: [
      { key: 'bank', test: (d) => d.targets_indian_banks, label: 'Banking package match' },
      { key: 'dex', test: (d) => apiFired(d, 'DexClassLoader'), label: 'Dynamic code loading' },
    ],
  },
];

function apiFired(data: FraudCardData, api: string): boolean {
  const apis = data.technical_view?.apis_fired || [];
  return apis.some((a) => a.includes(api));
}

function corpusHaystack(data: FraudCardData): string {
  const parts = [
    data.package_name,
    ...(data.technical_view?.strings_fired || []),
    ...(data.technical_view?.permissions_fired || []),
    ...(data.hardcoded_urls_ips || []),
    ...(data.intelligence_report?.affected_banking_apps || []),
    JSON.stringify(data.code_findings || []),
  ];
  return parts.join(' ').toLowerCase();
}

export function malwareTypeLabel(data: FraudCardData, family: string): string {
  if (family && family !== 'Unknown') {
    return data.targets_indian_banks ? `${family} - Banking Trojan Pattern` : `${family} - Classified Mobile Threat`;
  }
  if (data.targets_indian_banks) return 'Suspected Banking Trojan (family not matched)';
  return 'Unclassified Android Sample';
}

export function campaignStatus(intel: IntelApiPayload): { label: string; tone: 'active' | 'unknown' | 'none' } {
  const c = (intel.campaign || '').trim();
  const attributed =
    c &&
    !/^not attributed$/i.test(c) &&
    c !== 'None' &&
    c !== 'Unknown';
  if (attributed) return { label: 'ACTIVE', tone: 'active' };
  if (intel.alienvault.pulse_count > 0 && !attributed) {
    return { label: 'PULSES - CAMPAIGN NOT IDENTIFIED', tone: 'unknown' };
  }
  return { label: 'NOT ATTRIBUTED', tone: 'none' };
}

export function analysisCoveragePercent(data: FraudCardData, intel: IntelApiPayload): number {
  const steps = [
    true,
    true,
    (data.manifest_findings?.length || 0) + (data.code_findings?.length || 0) > 0,
    (intel.iocs?.length || 0) > 0,
    intel.sources_status.some((s) => s.status === 'active'),
    data.family_classification !== 'Unknown' || intel.malware_family !== 'Unknown',
    data.frs_breakdown != null,
    data.dynamic_available,
    (data.dynamic_analysis?.screenshots?.length || 0) > 0,
    Boolean(data.fraud_workflow?.fraud_sequence_detected),
  ];
  const done = steps.filter(Boolean).length;
  return Math.round((done / steps.length) * 100);
}

export function evidenceConfidenceOverall(sources: ConfidenceSource[]): number {
  const scored = sources.filter((s) => s.percent != null);
  if (!scored.length) return 0;
  const sum = scored.reduce((a, s) => a + (s.percent ?? 0), 0);
  return Math.round(sum / scored.length);
}

export function buildConfidenceSources(
  data: FraudCardData,
  intel: IntelApiPayload,
  bundle: InvestigationBundle | null,
): ConfidenceSource[] {
  // The static engine publishes finding counts, not a confidence figure. The
  // old `hasFindings ? 100 : 50` invented one and fed it into the overall
  // average, so a run with a single manifest finding claimed 100% static
  // confidence. Report the counts, and leave the percentage absent.
  const staticFindingCount =
    (data.manifest_findings?.length || 0) + (data.code_findings?.length || 0);
  const intelActive = intel.sources_status.filter((s) => s.status === 'active').length;
  const intelMax = intel.sources_status.length || 3;
  const intelPct = intelMax ? Math.round((intelActive / intelMax) * 100) : null;
  const iocPct = intel.iocs.length
    ? Math.min(100, Math.round(60 + intel.iocs.filter((i) => i.reputation === 'malicious').length * 5))
    : 0;
  const runtimeCount = bundle?.counts.runtimeBehaviors ?? 0;
  const dynamicPct = data.dynamic_available
    ? Math.min(100, 40 + runtimeCount * 8)
    : null;
  // `|| 85` filled in a confidence for any case that matched a family but
  // carried no confidence of its own - a fabricated figure standing in for a
  // missing one. Absent is the honest value.
  const familyKnown =
    data.family_classification !== 'Unknown' || intel.malware_family !== 'Unknown';
  const reportedConfidence = Math.round(data.confidence || intel.confidence || 0);
  const classPct = familyKnown
    ? reportedConfidence > 0
      ? reportedConfidence
      : null
    : Math.min(40, Math.round(data.confidence || 0));

  return [
    {
      label: 'Static Analysis',
      percent: null,
      status: staticFindingCount > 0 ? 'ok' : 'unavailable',
      detail: `${data.manifest_findings?.length || 0} manifest + ${data.code_findings?.length || 0} code findings`,
    },
    {
      label: 'Threat Intel',
      percent: intelPct,
      status: intelPct == null ? 'unavailable' : intelPct >= 66 ? 'ok' : 'partial',
      detail: intel.sources_status.map((s) => `${s.name}: ${s.status}`).join(' · ') || 'No sources',
    },
    {
      label: 'IOC Correlation',
      percent: intel.iocs.length ? iocPct : null,
      status: intel.iocs.length ? 'ok' : 'unavailable',
      detail: `${intel.iocs.length} correlated indicators`,
    },
    {
      label: 'Dynamic Behaviour',
      percent: dynamicPct,
      status: dynamicPct == null ? 'unavailable' : 'ok',
      detail: dynamicPct == null ? 'Runtime analysis unavailable' : `${runtimeCount} runtime evidence records`,
    },
    {
      label: 'Malware Classification',
      percent: classPct,
      status: classPct == null ? 'unavailable' : classPct >= 70 ? 'ok' : 'partial',
      detail:
        data.family_classification !== 'Unknown'
          ? `Family: ${data.family_classification}`
          : 'Family confidence reduced - no signature match',
    },
  ];
}

export function buildThreatDna(data: FraudCardData, bundle: InvestigationBundle | null): DnaTrait[] {
  const runtimeOverlay = bundle?.evidenceRecords.some((e) =>
    /overlay|alert|window/i.test(e.title + (e.description || '')),
  );
  const runtimeSms = bundle?.evidenceRecords.some((e) => /sms|otp/i.test(e.title + (e.description || '')));
  const upiHit = /upi|npci|paytm|phonepe|bhim/i.test(corpusHaystack(data));
  const credHit =
    data.threat_scenario_table?.some((r) => /credential|login|password/i.test(r.threat_scenario)) ||
    data.code_findings?.some((f) => /credential|login/i.test(f.title + f.description));
  const persistHit = (data.services?.length || 0) > 2 || data.receivers?.length > 3;
  const spywareHit = data.all_permissions?.some((p) => /RECORD_AUDIO|CAMERA|READ_CONTACTS/i.test(p));
  const ransomHit = data.code_findings?.some((f) => /encrypt|ransom|lock/i.test(f.title + f.description));
  const ratHit = apiFired(data, 'Runtime.exec') || apiFired(data, 'ProcessBuilder');

  const traits: DnaTrait[] = [
    {
      label: 'Credential Theft',
      observation: credHit
        ? 'statically_declared'
        : data.has_accessibility_abuse || data.targets_indian_banks
          ? 'inferred'
          : 'not_observed',
      evidenceIds: credHit ? ['SCEN-0'] : data.has_accessibility_abuse ? ['STAT-A11Y'] : [],
      rationale: credHit
        ? 'Threat scenario or code finding references credential capture'
        : data.has_accessibility_abuse
          ? 'Accessibility abuse enables credential harvesting'
          : data.targets_indian_banks
            ? 'Banking targeting without a direct credential-capture finding'
            : 'No direct credential theft evidence',
    },
    {
      label: 'Overlay Attack',
      observation: runtimeOverlay
        ? 'runtime_observed'
        : data.has_system_alert_window
          ? 'statically_declared'
          : 'not_observed',
      evidenceIds: data.has_system_alert_window ? ['STAT-OVERLAY'] : [],
      rationale: runtimeOverlay
        ? 'Overlay behaviour seen in runtime evidence'
        : data.has_system_alert_window
          ? 'SYSTEM_ALERT_WINDOW declared'
          : 'Overlay capability not observed',
    },
    {
      label: 'Accessibility Abuse',
      observation: data.has_accessibility_abuse ? 'statically_declared' : 'not_observed',
      evidenceIds: data.has_accessibility_abuse ? ['STAT-A11Y'] : [],
      rationale: data.has_accessibility_abuse
        ? 'BIND_ACCESSIBILITY_SERVICE / abuse flag'
        : 'Not declared in static analysis',
    },
    {
      label: 'SMS Interception',
      observation: runtimeSms
        ? 'runtime_observed'
        : data.has_sms_read_write
          ? 'statically_declared'
          : 'not_observed',
      evidenceIds: data.has_sms_read_write ? ['STAT-SMS'] : [],
      rationale: runtimeSms
        ? 'SMS or OTP access seen in runtime evidence'
        : data.has_sms_read_write
          ? 'SMS permissions present'
          : 'No SMS permission evidence',
    },
    {
      label: 'UPI / Wallet Fraud',
      observation: upiHit
        ? 'statically_declared'
        : data.targets_indian_banks
          ? 'inferred'
          : 'not_observed',
      evidenceIds: [],
      rationale: upiHit
        ? 'UPI/wallet strings or packages in corpus'
        : data.targets_indian_banks
          ? 'Banking targeting without explicit UPI strings'
          : 'No UPI targeting evidence',
    },
    {
      label: 'Persistence',
      observation: persistHit ? 'statically_declared' : 'not_observed',
      evidenceIds: [],
      rationale: persistHit
        ? `${data.services?.length || 0} services / ${data.receivers?.length || 0} receivers`
        : 'Limited persistence surface in manifest',
    },
    {
      label: 'Spyware Behaviour',
      observation: spywareHit ? 'statically_declared' : 'not_observed',
      evidenceIds: [],
      rationale: spywareHit ? 'Sensitive permissions in manifest' : 'No spyware-class permissions flagged',
    },
    {
      label: 'Ransomware',
      observation: ransomHit ? 'statically_declared' : 'not_observed',
      evidenceIds: [],
      rationale: ransomHit ? 'Encryption/ransom strings in code findings' : 'No ransomware indicators',
    },
    {
      label: 'Remote Access',
      observation: ratHit
        ? 'statically_declared'
        : data.has_reflection
          ? 'inferred'
          : 'not_observed',
      evidenceIds: [],
      rationale: ratHit
        ? 'Runtime.exec / ProcessBuilder APIs fired'
        : data.has_reflection
          ? 'Reflection present, but no direct remote-execution API matched'
          : 'No remote execution APIs matched',
    },
  ];

  return traits.sort(
    (a, b) => dnaObservationRank(b.observation) - dnaObservationRank(a.observation),
  );
}

export function buildAttackChain(data: FraudCardData, bundle: InvestigationBundle | null): AttackStage[] {
  const wf = data.fraud_workflow;
  const wfLabels = new Set((wf?.stages || []).map((s) => s.label.toLowerCase()));
  const hasC2 = data.hardcoded_urls_ips.length > 0 || (data.threat_correlation?.malicious_ips?.length || 0) > 0;
  const hasOverlayRuntime = bundle?.evidenceRecords.some((e) => /overlay/i.test(e.title));

  const stages: AttackStage[] = [
    { id: 'apk', label: 'APK', detected: true, evidenceIds: [], detail: data.sha256.slice(0, 16) + '…' },
    {
      id: 'install',
      label: 'Install',
      detected: true,
      evidenceIds: [],
      detail: data.package_name,
    },
    {
      id: 'a11y',
      label: 'Accessibility',
      detected: data.has_accessibility_abuse || wfLabels.has('accessibility'),
      evidenceIds: data.has_accessibility_abuse ? ['STAT-A11Y'] : [],
    },
    {
      id: 'overlay',
      label: 'Overlay',
      detected: data.has_system_alert_window || hasOverlayRuntime || wfLabels.has('overlay'),
      evidenceIds: data.has_system_alert_window ? ['STAT-OVERLAY'] : [],
    },
    {
      id: 'cred',
      label: 'Credential Capture',
      detected: Boolean(
        data.threat_scenario_table?.some((r) => /credential/i.test(r.threat_scenario)) ||
          data.has_accessibility_abuse,
      ),
      evidenceIds: [],
    },
    {
      id: 'otp',
      label: 'OTP Interception',
      detected: data.has_sms_read_write || wfLabels.has('otp'),
      evidenceIds: data.has_sms_read_write ? ['STAT-SMS'] : [],
    },
    {
      id: 'upi',
      label: 'UPI Fraud',
      detected: data.targets_indian_banks && (data.has_sms_read_write || data.has_accessibility_abuse),
      evidenceIds: [],
    },
    {
      id: 'c2',
      label: 'Command & Control',
      detected: hasC2,
      evidenceIds: [],
      detail: hasC2 ? `${data.hardcoded_urls_ips.length} endpoints` : undefined,
    },
    {
      id: 'transfer',
      label: 'Money Transfer',
      detected: wf?.sequence_label === 'FULL_ACCOUNT_TAKEOVER' || wf?.fraud_sequence_detected === true,
      evidenceIds: [],
    },
  ];
  return stages;
}

export function buildClassificationEvidence(data: FraudCardData, intel: IntelApiPayload): {
  matchedRules: string[];
  ruleRefs: string[];
  family: string;
  confidence: number;
} {
  const matched: string[] = [];
  const refs: string[] = [];
  if (data.has_accessibility_abuse) {
    matched.push('Accessibility Abuse');
    refs.push('STAT-A11Y');
  }
  if (data.has_sms_read_write) {
    matched.push('SMS APIs');
    refs.push('STAT-SMS');
  }
  if (data.has_system_alert_window) {
    matched.push('Overlay');
    refs.push('STAT-OVERLAY');
  }
  if (data.has_reflection) matched.push('Reflection');
  if (data.targets_indian_banks) matched.push('Banking Package Targeting');
  (data.technical_view?.apis_fired || []).forEach((api, i) => {
    matched.push(`API: ${api}`);
    refs.push(`API-${i}`);
  });

  const family = intel.malware_family || data.family_classification;
  const confidence = Math.round(data.confidence || intel.confidence || 0);

  return {
    matchedRules: matched,
    ruleRefs: refs,
    family,
    confidence: family === 'Unknown' ? Math.min(confidence, 45) : confidence,
  };
}

export function buildInfrastructure(
  data: FraudCardData,
  intel: IntelApiPayload,
): InfrastructureSummary {
  const domains = new Set<string>();
  const ips = new Set<string>();
  const urls = new Set<string>();
  const countries = new Set<string>();

  intel.iocs.forEach((ioc) => {
    if (ioc.type === 'Domain') domains.add(ioc.value);
    if (ioc.type === 'IP') ips.add(ioc.value);
    if (ioc.type === 'URL' || ioc.type === 'Firebase URL' || ioc.type === 'Telegram Bot') urls.add(ioc.value);
  });

  data.threat_correlation?.ioc_reputation?.forEach((ioc) => {
    if (ioc.type === 'Domain') domains.add(ioc.indicator);
    if (ioc.type === 'IP') ips.add(ioc.indicator);
    if (ioc.country) countries.add(ioc.country);
  });

  if (data.domains && typeof data.domains === 'object') {
    Object.keys(data.domains).forEach((d) => domains.add(d));
  }

  const cert = data.certificate || {};
  const certLines: string[] = [];
  if (cert.subject) certLines.push(String(cert.subject));
  if (cert.issuer) certLines.push(`Issuer: ${cert.issuer}`);
  if (cert.sha256) certLines.push(`SHA256: ${cert.sha256}`);
  if (cert.fingerprint) certLines.push(`Fingerprint: ${cert.fingerprint}`);

  return {
    domains: [...domains],
    ips: [...ips],
    urls: [...urls],
    certificates: certLines,
    countries: [...countries],
    asns: [],
    hosting: [],
  };
}

export function buildMitreCards(data: FraudCardData, bundle: InvestigationBundle | null): MitreCard[] {
  const techniques = data.intelligence_report?.mitre_techniques_used || [];
  if (techniques.length) {
    return techniques.map((t, i) => {
      const ev = bundle?.evidenceRecords.find((e) => e.mitreId && t.includes(e.mitreId));
      return {
        technique: t,
        techniqueId: ev?.mitreId,
        confidence: ev?.confidence,
        evidence: ev?.description || data.risk_explanation?.evidence_lines?.[i] || 'Mapped from intelligence report',
        source: ev?.sourceEngine || 'Intelligence Report',
        evidenceIds: ev ? [ev.id] : [],
      };
    });
  }

  const fromRuntime = (bundle?.evidenceRecords || []).filter((e) => e.mitreId);
  if (fromRuntime.length) {
    return fromRuntime.map((e) => ({
      technique: e.mitreName || e.title,
      techniqueId: e.mitreId,
      confidence: e.confidence,
      evidence: e.description || e.title,
      source: e.sourceEngine,
      evidenceIds: [e.id],
    }));
  }

  return [];
}

export function buildBankingRows(data: FraudCardData): BankingRow[] {
  const hay = corpusHaystack(data);
  const affected = new Set(
    (data.intelligence_report?.affected_banking_apps || []).map((a) => a.toLowerCase()),
  );

  return BANKING_ECOSYSTEM.map((bank) => {
    const hit = bank.patterns.some((p) => hay.includes(p.toLowerCase()));
    const intelHit = [...affected].some((a) => bank.patterns.some((p) => a.includes(p)));
    let status: BankingRow['status'] = 'not_targeted';
    let evidenceCount = 0;
    let evidenceHint = 'No package/string match in static corpus';

    if (hit || intelHit) {
      status = 'detected';
      evidenceCount = bank.patterns.filter((p) => hay.includes(p.toLowerCase())).length + (intelHit ? 1 : 0);
      evidenceHint = 'Package or string match in analysis corpus';
    } else if (data.targets_indian_banks && !hit) {
      status = 'possible';
      evidenceCount = 1;
      evidenceHint = 'Generic Indian banking targeting flag without explicit package match';
    } else if (!data.targets_indian_banks && !hit) {
      status = 'unknown';
      evidenceHint = 'Insufficient targeting evidence';
    }

    return {
      id: bank.id,
      label: bank.label,
      status,
      evidenceCount,
      evidenceHint,
    };
  });
}

export function buildFamilySimilarity(data: FraudCardData, assignedFamily: string): FamilySimilarity[] {
  return FAMILY_RULES.map((rule) => {
    const reasons: string[] = [];
    let matched = 0;
    rule.conditions.forEach((c) => {
      if (c.test(data)) {
        matched += 1;
        reasons.push(`✓ ${c.label}`);
      } else {
        reasons.push(`✗ ${c.label}`);
      }
    });
    const percent = Math.round((matched / rule.conditions.length) * 100);
    return {
      family: rule.family,
      percent,
      reasons,
      isAssigned: rule.family === assignedFamily,
    };
  })
    .filter((r) => r.percent > 0 || r.isAssigned)
    .sort((a, b) => b.percent - a.percent)
    .slice(0, 8);
}

export function buildAnalystActions(data: FraudCardData, intel: IntelApiPayload): AnalystAction[] {
  const actions: AnalystAction[] = [];
  const infra = buildInfrastructure(data, intel);

  if (infra.domains.length || infra.urls.length) {
    actions.push({
      label: 'Block Domains / URLs',
      evidenceRef: `${infra.domains.length} domains, ${infra.urls.length} URLs in IOC set`,
      priority: 'high',
    });
  }
  if (data.targets_indian_banks) {
    actions.push({
      label: 'Monitor Customer Accounts',
      evidenceRef: 'Indian banking package targeting detected',
      priority: 'high',
    });
  }
  const recs = [
    ...(data.executive_view?.recommended_actions || []),
    ...(data.intelligence_report?.recommended_actions || []),
    ...(data.intelligence_report?.cert_in_recommendations || []),
  ];
  recs.forEach((r) => {
    if (!actions.some((a) => a.label === r)) {
      actions.push({ label: r, evidenceRef: 'Intelligence report recommendation', priority: 'medium' });
    }
  });
  if (!data.dynamic_available) {
    actions.push({
      label: 'Run Dynamic Analysis',
      evidenceRef: 'Runtime analysis unavailable - projection risk may increase',
      priority: 'high',
    });
  }
  actions.push({
    label: 'Export STIX',
    evidenceRef: `Case ${data.sha256.slice(0, 12)}…`,
    priority: 'low',
  });
  if (data.final_risk_score >= 70) {
    actions.push({
      label: 'Escalate to SOC Lead',
      evidenceRef: `FRS ${data.final_risk_score.toFixed(0)} - ${data.risk_band}`,
      priority: 'high',
    });
  }
  if (data.recommended_action && !actions.some((a) => a.label === data.recommended_action)) {
    actions.unshift({
      label: data.recommended_action,
      evidenceRef: 'Risk engine recommended action',
      priority: 'high',
    });
  }

  return actions;
}

export function buildRiskProjection(data: FraudCardData): {
  current: number;
  projected: number;
  maximum: number;
  explanation: string;
} {
  const frs = data.frs_breakdown;
  const current = data.final_risk_score;
  const stei = frs?.stei ?? 0;
  const banking = frs?.banking_impact ?? 0;
  const correlation = frs?.correlation ?? 0;
  const dynamic = frs?.dynamic ?? 0;

  let projected = current;
  let explanation = 'Score reflects completed analysis axes only.';

  if (!data.dynamic_available) {
    const estDynamic = data.has_accessibility_abuse ? 40 : data.has_sms_read_write ? 28 : 12;
    projected = Math.min(100, Math.round(stei * 0.45 + banking + correlation * 0.85 + estDynamic));
    explanation = `Runtime analysis unavailable. Projected score assumes dynamic axis confirms ${
      data.has_accessibility_abuse ? 'accessibility abuse' : 'observed static behaviours'
    } (+${estDynamic} est. dynamic contribution) using STEI ${stei.toFixed(0)}, banking ${banking.toFixed(0)}, correlation ${correlation.toFixed(0)}.`;
  } else if (dynamic > 0) {
    projected = current;
    explanation = `Dynamic analysis conclusive (dynamic axis ${dynamic.toFixed(0)}). Projected aligns with current FRS.`;
  }

  const maximum = Math.min(
    100,
    Math.round(stei + banking + correlation + (data.dynamic_available ? dynamic : 55)),
  );

  return { current, projected, maximum, explanation };
}

export type CoverageItem = { label: string; done: boolean; detail?: string };

export function buildAnalysisCoverage(data: FraudCardData, intel: IntelApiPayload): {
  percent: number;
  completed: CoverageItem[];
  missing: CoverageItem[];
} {
  const completed: CoverageItem[] = [
    { label: 'Static', done: true },
    { label: 'IOC Extraction', done: intel.iocs.length > 0, detail: `${intel.iocs.length} IOCs` },
    {
      label: 'Threat Intel',
      done: intel.sources_status.some((s) => s.status === 'active'),
    },
    { label: 'Risk Engine', done: data.frs_breakdown != null },
    {
      label: 'Classification',
      done: data.family_classification !== 'Unknown' || intel.malware_family !== 'Unknown',
    },
  ];
  const missing: CoverageItem[] = [
    { label: 'Runtime', done: data.dynamic_available, detail: data.dynamic_available ? undefined : 'Runtime analysis unavailable' },
    {
      label: 'Network Behaviour',
      done: Boolean(data.dynamic_analysis?.network_logs?.length),
    },
    {
      label: 'Overlay Hooks',
      done: Boolean(data.fraud_workflow?.stages?.some((s) => /overlay/i.test(s.label))),
    },
  ];

  const all = [...completed, ...missing];
  const percent = Math.round((all.filter((i) => i.done).length / all.length) * 100);

  return {
    percent,
    completed: completed.filter((c) => c.done),
    missing: missing.filter((m) => !m.done),
  };
}

export function collectEvidenceExplorerItems(
  bundle: InvestigationBundle | null,
  data: FraudCardData,
  intel: IntelApiPayload,
): { group: string; items: { id: string; title: string; subtitle: string }[] }[] {
  const groups: { group: string; items: { id: string; title: string; subtitle: string }[] }[] = [];

  if (bundle?.evidenceRecords.length) {
    groups.push({
      group: 'Engine findings',
      items: bundle.evidenceRecords.slice(0, 40).map((e) => ({
        id: e.id,
        title: e.title,
        subtitle: `${e.severity} · ${e.sourceEngine}`,
      })),
    });
  }

  if (intel.virus_total.vendors.length) {
    groups.push({
      group: 'VirusTotal vendors',
      items: intel.virus_total.vendors.slice(0, 20).map((v, i) => ({
        id: `VT-${i}`,
        title: v,
        subtitle: 'VT malicious detection',
      })),
    });
  }

  if (data.technical_view?.matched_rule) {
    groups.push({
      group: 'Matched rules',
      items: [{ id: 'RULE-MATCH', title: data.technical_view.matched_rule, subtitle: 'Technical view' }],
    });
  }

  return groups;
}

export function filterIocsByGraphNode(
  iocs: IntelApiPayload['iocs'],
  nodeId: string | null,
  data: FraudCardData,
  intel: IntelApiPayload,
): IntelApiPayload['iocs'] {
  if (!nodeId || nodeId === 'all') return iocs;
  const map: Record<string, (ioc: (typeof iocs)[0]) => boolean> = {
    apk: (ioc) => ioc.type === 'SHA256',
    package: (ioc) => ioc.type === 'Package',
    cert: (ioc) => ioc.type === 'Certificate',
    domains: (ioc) => ioc.type === 'Domain',
    ips: (ioc) => ioc.type === 'IP',
    urls: (ioc) => ioc.type === 'URL' || ioc.type === 'Firebase URL' || ioc.type === 'Telegram Bot',
    campaign: () => Boolean(intel.campaign && !/not attributed/i.test(intel.campaign)),
    family: () => true,
    mitre: () => (data.intelligence_report?.mitre_techniques_used?.length || 0) > 0,
  };
  const fn = map[nodeId];
  if (!fn) return iocs;
  if (nodeId === 'family') {
    return iocs.filter((i) => i.severity === 'Critical' || i.severity === 'High').slice(0, 20);
  }
  return iocs.filter(fn);
}

export type HistoricalCaseRow = {
  sha256: string;
  similarity: number;
  verdict: string;
  family: string;
  risk: number;
  confidence: number;
  analyst: string;
};

export function scoreCaseSimilarity(
  current: FraudCardData,
  other: {
    family_classification: string | null;
    final_risk_score: number | null;
    risk_band: string | null;
    package_name: string | null;
  },
): number {
  let score = 0;
  if (other.family_classification && other.family_classification === current.family_classification) score += 50;
  if (other.risk_band && other.risk_band === current.risk_band) score += 20;
  if (other.package_name && other.package_name === current.package_name) score += 30;
  const riskDelta = Math.abs((other.final_risk_score ?? 0) - current.final_risk_score);
  if (riskDelta <= 10) score += 15;
  return Math.min(100, score);
}
