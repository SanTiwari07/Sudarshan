import type { FraudCardData } from '../App';
import type { InvestigationBundle, InvestigationEvidence } from '../types/investigation';
import {
  evidencePlainText,
  formatEvidenceSource,
  technicalExplanation,
} from './findingAnalystView';
import type { TechnicalFindingId } from './technicalFindings';
import { apisFired, hasRuntimeCodeLoadingSignal } from './technicalFindings';
import { resolveVideFromData } from './videUi';

export type EvidenceBasis = 'static_only' | 'dynamic_only' | 'static_and_dynamic' | 'none';

export type MappedEvidenceItem = {
  id: string;
  title: string;
  source: string;
  category: 'static' | 'dynamic';
  confidence?: number;
  timestampMs?: number;
  rawDescription?: string;
  interpretation: string;
  evidence?: InvestigationEvidence;
};

type RawRuntime = Record<string, unknown>;

function hay(s: string): string {
  return s.toLowerCase();
}

function matchesKeywords(text: string, keywords: string[]): boolean {
  const h = hay(text);
  return keywords.some((k) => h.includes(k.toLowerCase()));
}

function bundleRecordMatches(
  record: InvestigationEvidence,
  keywords: string[],
  runtimeCategories?: string[],
): boolean {
  const text = `${record.id} ${record.title} ${record.description || ''} ${record.hookNames?.join(' ') || ''}`;
  if (matchesKeywords(text, keywords)) return true;
  if (record.runtimeSubcategory && runtimeCategories?.length) {
    const sub = record.runtimeSubcategory.toLowerCase();
    if (runtimeCategories.some((c) => sub.includes(c.toLowerCase()))) return true;
  }
  return false;
}

function mapRecord(record: InvestigationEvidence): MappedEvidenceItem {
  return {
    id: record.id,
    title: record.title,
    source: formatEvidenceSource(record),
    category: record.category === 'runtime' ? 'dynamic' : 'static',
    confidence: record.confidence,
    timestampMs: record.timestampMs,
    rawDescription: record.description,
    interpretation: technicalExplanation(record),
    evidence: record,
  };
}

function axisLines(data: FraudCardData, axis: string): string[] {
  return data.risk_explanation?.stei_evidence_by_axis?.[axis] || [];
}

function syntheticFromAxis(
  lines: string[],
  filter: (line: string) => boolean,
  prefix: string,
): MappedEvidenceItem[] {
  return lines
    .filter(filter)
    .map((line, i) => ({
      id: `${prefix}-AXIS-${i}`,
      title: line.split(':')[0]?.trim() || 'Risk engine signal',
      source: 'Risk Engine',
      category: 'static' as const,
      rawDescription: line,
      interpretation: line,
    }));
}

function manifestCodeRows(
  data: FraudCardData,
  keywords: string[],
): MappedEvidenceItem[] {
  const out: MappedEvidenceItem[] = [];
  data.manifest_findings?.forEach((f, i) => {
    const text = `${f.title} ${f.description} ${f.component || ''}`;
    if (!matchesKeywords(text, keywords)) return;
    out.push({
      id: `MAN-${i}`,
      title: f.title,
      source: 'Android Manifest',
      category: 'static',
      rawDescription: f.description,
      interpretation: f.description || f.title,
    });
  });
  data.code_findings?.forEach((f, i) => {
    const text = `${f.title} ${f.description} ${(f.files || []).join(' ')}`;
    if (!matchesKeywords(text, keywords)) return;
    out.push({
      id: `CODE-${i}`,
      title: f.title,
      source: 'Static Engine',
      category: 'static',
      rawDescription: f.description,
      interpretation: f.description || f.title,
    });
  });
  return out;
}

function rawRuntimeRows(
  raw: RawRuntime[],
  keywords: string[],
  categories?: string[],
): MappedEvidenceItem[] {
  const out: MappedEvidenceItem[] = [];
  raw.forEach((r, i) => {
    const cat = String(r.category || '').toLowerCase();
    if (categories?.length && !categories.some((c) => cat.includes(c.toLowerCase()))) {
      const text = `${r.description || ''} ${r.api || ''}`;
      if (!matchesKeywords(text, keywords)) return;
    } else if (categories?.length && categories.some((c) => cat.includes(c.toLowerCase()))) {
      // matched category
    } else if (!matchesKeywords(`${r.description || ''} ${r.api || ''} ${cat}`, keywords)) {
      return;
    }
    const id = String(r.finding_id || r.id || `RAW-${i}`);
    out.push({
      id,
      title: String(r.description || r.api || r.category || 'Runtime behavior'),
      source: 'Frida',
      category: 'dynamic',
      confidence: typeof r.confidence === 'number' ? r.confidence : undefined,
      timestampMs: typeof r.timestamp_ms === 'number' ? r.timestamp_ms : undefined,
      rawDescription: String(r.human_description || r.description || ''),
      interpretation: String(r.human_description || r.description || r.api || 'Runtime instrumentation observed this behavior.'),
    });
  });
  return out;
}

function dedupeById(items: MappedEvidenceItem[]): MappedEvidenceItem[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.id}|${item.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function filterBundle(
  bundle: InvestigationBundle | null | undefined,
  keywords: string[],
  runtimeCategories?: string[],
): MappedEvidenceItem[] {
  if (!bundle) return [];
  return bundle.evidenceRecords
    .filter((r) => bundleRecordMatches(r, keywords, runtimeCategories))
    .map(mapRecord);
}

export function computeEvidenceBasis(items: MappedEvidenceItem[]): EvidenceBasis {
  if (items.length === 0) return 'none';
  const hasStatic = items.some((i) => i.category === 'static');
  const hasDynamic = items.some((i) => i.category === 'dynamic');
  if (hasStatic && hasDynamic) return 'static_and_dynamic';
  if (hasDynamic) return 'dynamic_only';
  if (hasStatic) return 'static_only';
  return 'none';
}

export function evidenceBasisLabel(basis: EvidenceBasis): string {
  switch (basis) {
    case 'static_only':
      return 'Capability detected';
    case 'dynamic_only':
      return 'Runtime behavior observed';
    case 'static_and_dynamic':
      return 'Capability detected and runtime behavior observed';
    default:
      return 'No evidence basis';
  }
}

export function evidenceBasisBadge(basis: EvidenceBasis): string {
  switch (basis) {
    case 'static_only':
      return 'STATIC';
    case 'dynamic_only':
      return 'DYNAMIC';
    case 'static_and_dynamic':
      return 'STATIC + DYNAMIC';
    default:
      return 'NONE';
  }
}

const FINDING_KEYWORDS: Record<TechnicalFindingId, string[]> = {
  accessibility_abuse: ['a11y', 'accessibility', 'bind_accessibility', 'stat-a11y'],
  overlay_capability: ['overlay', 'alert window', 'system_alert', 'stat-overlay', 'type_application_overlay'],
  runtime_code_loading: ['dexclassloader', 'pathclassloader', 'inmemorydex', 'dynamic dex', 'classloader'],
  obfuscation: ['obfus', 'entropy', 'reflection', 'forname', 'invoke'],
  sms_otp_interception: ['sms', 'otp', 'receive_sms', 'read_sms', 'stat-sms'],
  banking_targeting: ['bank', 'upi', 'financial', 'hdfc', 'sbi', 'icici', 'vide-f001', 'targeting'],
  network_c2: ['http', 'https', 'socket', 'c2', 'url', 'domain', 'network', 'indicator'],
  persistence: ['boot', 'device admin', 'deviceadmin', 'receiver', 'persistent'],
  visual_impersonation: ['vide', 'visual impersonation', 'impersonation', 'baseline'],
};

const RUNTIME_CATEGORIES: Partial<Record<TechnicalFindingId, string[]>> = {
  accessibility_abuse: ['accessibility'],
  overlay_capability: ['overlay', 'window'],
  sms_otp_interception: ['sms'],
  network_c2: ['network'],
};

export function mapFindingEvidence(
  findingId: TechnicalFindingId,
  data: FraudCardData,
  bundle: InvestigationBundle | null | undefined,
  rawRuntime: RawRuntime[] = [],
): MappedEvidenceItem[] {
  const keywords = FINDING_KEYWORDS[findingId];
  const runtimeCats = RUNTIME_CATEGORIES[findingId];
  let items: MappedEvidenceItem[] = [];

  items.push(...filterBundle(bundle, keywords, runtimeCats));
  items.push(...manifestCodeRows(data, keywords));
  items.push(...rawRuntimeRows(rawRuntime, keywords, runtimeCats));

  if (findingId === 'accessibility_abuse' && data.has_accessibility_abuse) {
    if (!items.some((i) => i.id === 'STAT-A11Y')) {
      items.push({
        id: 'STAT-A11Y',
        title: 'BIND_ACCESSIBILITY_SERVICE declared',
        source: 'Android Manifest',
        category: 'static',
        rawDescription: 'BIND_ACCESSIBILITY_SERVICE declared',
        interpretation: 'The application requests the Android accessibility service capability.',
      });
    }
    items.push(
      ...syntheticFromAxis(axisLines(data, 'ct'), (l) => /accessibility|bind_accessibility/i.test(l), 'A11Y'),
    );
  }

  if (findingId === 'overlay_capability' && data.has_system_alert_window) {
    if (!items.some((i) => i.id === 'STAT-OVERLAY')) {
      items.push({
        id: 'STAT-OVERLAY',
        title: 'SYSTEM_ALERT_WINDOW capability',
        source: 'Android Manifest',
        category: 'static',
        rawDescription: 'SYSTEM_ALERT_WINDOW capability',
        interpretation: 'The application can draw overlay windows above other apps.',
      });
    }
    items.push(
      ...syntheticFromAxis(axisLines(data, 'ct'), (l) => /system_alert|overlay/i.test(l), 'OVR'),
    );
  }

  if (findingId === 'sms_otp_interception' && data.has_sms_read_write) {
    if (!items.some((i) => i.id === 'STAT-SMS')) {
      items.push({
        id: 'STAT-SMS',
        title: 'SMS read/receive permissions',
        source: 'Android Manifest',
        category: 'static',
        rawDescription: 'READ/RECEIVE SMS permissions',
        interpretation: 'The application can access SMS message content.',
      });
    }
    items.push(...syntheticFromAxis(axisLines(data, 'ct'), (l) => /sms/i.test(l), 'SMS'));
  }

  if (findingId === 'runtime_code_loading' && hasRuntimeCodeLoadingSignal(data)) {
    apisFired(data)
      .filter((a) => /DexClassLoader|PathClassLoader|InMemoryDex/i.test(a))
      .forEach((api, i) => {
        items.push({
          id: `API-LOADER-${i}`,
          title: api,
          source: 'Static API scan',
          category: 'static',
            rawDescription: `${api} usage detected`,
          interpretation: `Static analysis identified ${api} - can load bytecode after installation.`,
        });
      });
    items.push(
      ...syntheticFromAxis(axisLines(data, 'ob'), (l) => /dexclassloader|pathclassloader|dynamic dex/i.test(l), 'LOAD'),
    );
  }

  if (findingId === 'obfuscation') {
    if ((data.obfuscation_score ?? 0) > 0) {
      items.push({
        id: 'OB-SCORE',
        title: `String entropy score ${(data.obfuscation_score ?? 0).toFixed(2)}`,
        source: 'Static Engine',
        category: 'static',
        rawDescription: `Obfuscation score ${data.obfuscation_score}`,
        interpretation: 'Elevated string entropy suggests obfuscated or encrypted string pools.',
      });
    }
    if (data.has_reflection) {
      items.push({
        id: 'OB-REFL',
        title: 'Java reflection APIs detected',
        source: 'Static Engine',
        category: 'static',
        rawDescription: 'Class.forName / getDeclaredMethod / invoke patterns',
        interpretation: 'Reflection can hide call targets from static analysis.',
      });
    }
    items.push(
      ...syntheticFromAxis(axisLines(data, 'ob'), (l) => /entropy|reflection|obfus|concealed/i.test(l), 'OB'),
    );
  }

  if (findingId === 'banking_targeting') {
    if (data.targets_indian_banks) {
      items.push({
        id: 'BT-FLAG',
        title: 'Indian banking package targeting',
        source: 'Static Engine',
        category: 'static',
        rawDescription: 'targets_indian_banks flag set',
        interpretation: 'Static analysis matched known Indian banking application identifiers.',
      });
    }
    (data.intelligence_report?.affected_banking_apps || []).forEach((app, i) => {
      items.push({
        id: `BT-APP-${i}`,
        title: app,
        source: 'Threat Intelligence',
        category: 'static',
        rawDescription: app,
        interpretation: 'Intelligence report lists this banking application as affected or targeted.',
      });
    });
    (data.technical_view?.strings_fired || [])
      .filter((s) => /bank|upi|paytm|phonepe/i.test(s))
      .slice(0, 5)
      .forEach((s, i) => {
        items.push({
          id: `BT-STR-${i}`,
          title: s.slice(0, 80),
          source: 'Static strings',
          category: 'static',
            rawDescription: s,
          interpretation: 'Suspicious string reference associated with financial applications.',
        });
      });
    items.push(...syntheticFromAxis(axisLines(data, 'bt'), () => true, 'BT'));
  }

  if (findingId === 'network_c2') {
    (data.hardcoded_urls_ips || []).slice(0, 10).forEach((url, i) => {
      items.push({
        id: `NET-URL-${i}`,
        title: url.slice(0, 100),
        source: 'Static Engine',
        category: 'static',
        rawDescription: url,
        interpretation: 'Hardcoded network indicator embedded in the application.',
      });
    });
    items.push(...syntheticFromAxis(axisLines(data, 'ir'), () => true, 'IR'));
    (data.threat_correlation?.ioc_reputation || []).slice(0, 5).forEach((ioc, i) => {
      items.push({
        id: `IOC-${i}`,
        title: ioc.indicator,
        source: 'Threat Intelligence',
        category: 'static',
        rawDescription: `${ioc.type}: ${ioc.reputation}`,
        interpretation: `IOC reputation: ${ioc.reputation} (${ioc.source}).`,
      });
    });
  }

  if (findingId === 'persistence') {
    (data.all_permissions || [])
      .filter((p) => /BOOT|DEVICE_ADMIN/i.test(p))
      .forEach((p, i) => {
        items.push({
          id: `PRM-${i}`,
          title: p.split('.').pop() || p,
          source: 'Android Manifest',
          category: 'static',
            rawDescription: p,
          interpretation: 'Dangerous permission associated with persistence or elevated control.',
        });
      });
    items.push(...syntheticFromAxis(axisLines(data, 'pr'), (l) => /boot|admin|receiver/i.test(l), 'PR'));
  }

  if (findingId === 'visual_impersonation') {
    const vide = resolveVideFromData(data);
    const compare = vide?.vide_compare;
    if (compare?.detected) {
      items.push({
        id: compare.rule_id || 'VIDE-F001',
        title: `VIDE match: ${compare.institution_display || compare.institution_id || 'banking baseline'}`,
        source: 'VIDE',
        category: 'static',
        confidence: Math.round((compare.confidence ?? vide?.visual_impersonation_confidence ?? 0) * 100),
        rawDescription: (compare.evidence_lines || []).join('; '),
        interpretation:
          (compare.evidence_lines || [])[0] ||
          'Deterministic visual impersonation rule matched laboratory banking UI baseline.',
      });
    }
    (compare?.evidence_lines || []).slice(1).forEach((line, i) => {
      items.push({
        id: `VIDE-EV-${i}`,
        title: line.slice(0, 80),
        source: 'VIDE',
        category: 'static',
        rawDescription: line,
        interpretation: line,
      });
    });
    if (vide?.signer_impersonation?.detected) {
      items.push({
        id: vide.signer_impersonation.rule_id || 'VIDE-SIGNER',
        title: 'Signer impersonation signal',
        source: 'VIDE',
        category: 'static',
        rawDescription: (vide.signer_impersonation.evidence_lines || []).join('; '),
        interpretation: 'Signer certificate similarity to a protected banking application was detected.',
      });
    }
  }

  data.threat_scenario_table?.forEach((row, i) => {
    const text = `${row.indicator} ${row.threat_scenario} ${row.evidence}`;
    if (!matchesKeywords(text, keywords)) return;
    items.push({
      id: `SCEN-${i}`,
      title: row.threat_scenario,
      source: 'Threat Scenario Engine',
      category: 'static',
      confidence: row.confidence,
      rawDescription: row.evidence,
      interpretation: row.evidence,
    });
  });

  return dedupeById(items);
}

export function summarizeEvidenceForDrawer(items: MappedEvidenceItem[]): string {
  if (items.length === 0) {
    return 'No supporting evidence records are currently available.';
  }
  return `${items.length} piece${items.length === 1 ? '' : 's'} of evidence support this finding.`;
}

export function detectedBulletLines(items: MappedEvidenceItem[]): string[] {
  return items.slice(0, 8).map((i) => i.title);
}

export function formatEvidenceCardInterpretation(item: MappedEvidenceItem): string {
  if (item.evidence) {
    const plain = evidencePlainText(item.evidence);
    if (plain && plain !== item.title) return plain;
  }
  return item.interpretation;
}
