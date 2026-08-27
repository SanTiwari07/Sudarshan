import type { FraudCardData } from '../App';
import type { InvestigationBundle } from '../types/investigation';
import type { IntelApiPayload, AnalystAction } from './threatIntelModel';
import { buildThreatDna, campaignStatus, dnaTraitDetected } from './threatIntelModel';
import { riskRecommendedAction } from './analystCopy';

export type QualitativeConfidence = 'High' | 'Moderate' | 'Limited';

export function qualitativeConfidence(overallPercent: number): QualitativeConfidence {
  if (overallPercent >= 70) return 'High';
  if (overallPercent >= 45) return 'Moderate';
  return 'Limited';
}

function assignedFamily(data: FraudCardData, intel: IntelApiPayload): string | null {
  const f = intel.malware_family || data.family_classification;
  if (!f || f === 'Unknown') return null;
  return f;
}

/**
 * The briefing as discrete sentences.
 *
 * The joined string below reads as one 900-character block on screen, which is
 * how the intel page ended up with a wall of prose no analyst finishes. The
 * sentences were always structured - assessment, static, runtime, correlation,
 * method, action, confidence - so the UI now gets them separately and can set
 * them as a lead plus short paragraphs.
 */
export function buildThreatIntelExecutiveSentences(
  data: FraudCardData,
  intel: IntelApiPayload,
  bundle: InvestigationBundle | null,
  overallConf: number,
): string[] {
  const sentences: string[] = [];
  const family = assignedFamily(data, intel);
  const frs = data.frs_breakdown;

  if (data.targets_indian_banks) {
    sentences.push(
      'This application exhibits behavioural characteristics commonly observed in banking malware targeting Android devices, including indicators aimed at Indian financial applications.',
    );
  } else {
    sentences.push(
      'This application exhibits behavioural characteristics that warrant comparison against known Android banking malware and fraud techniques.',
    );
  }

  if (family) {
    const rule = data.technical_view?.matched_rule?.trim();
    sentences.push(
      rule
        ? `Static analysis and classification associated the sample with the ${family} malware family (matched rule: ${rule}).`
        : `Static analysis identified indicators associated with the ${family} malware family.`,
    );
  } else {
    sentences.push(
      'Static analysis surfaced permission and code signals consistent with mobile fraud tooling, without a definitive named family assignment.',
    );
  }

  if (frs?.dynamic_ran && frs.dynamic_conclusive) {
    const parts: string[] = [];
    if (data.has_accessibility_abuse) parts.push('Accessibility Service abuse');
    if (data.has_sms_read_write) parts.push('SMS-related access');
    if (data.has_system_alert_window) parts.push('overlay capability');
    const extra =
      parts.length > 0
        ? `, including ${parts.join(', ')}`
        : '';
    sentences.push(
      `Runtime evidence from the sandbox confirmed suspicious behaviour${extra}, consistent with credential theft and device-control patterns seen in banking trojans.`,
    );
  } else if (frs?.dynamic_ran) {
    sentences.push(
      'Runtime monitoring executed but did not yield conclusive behavioural proof; static inspection and threat correlation carry additional weight in this assessment.',
    );
  } else {
    sentences.push(
      'Runtime monitoring did not complete or was inconclusive for this case; conclusions rely more heavily on static inspection and threat intelligence feeds.',
    );
  }

  const campaign = campaignStatus(intel);
  const threatLinked =
    Boolean(family) ||
    intel.iocs.length > 0 ||
    (bundle?.evidenceRecords.some((e) => e.category === 'scenario' || e.category === 'intel') ?? false);

  if (threatLinked) {
    const campaignNote =
      campaign.tone === 'active'
        ? ` Campaign attribution: ${intel.campaign.trim()}.`
        : family
          ? ` Patterns align with previously documented ${family} banking attack techniques.`
          : ' Observable indicators overlap with documented banking attack techniques.';
    sentences.push(
      `Threat correlation strengthened the assessment by linking verified evidence to external intelligence.${campaignNote}`,
    );
  }

  sentences.push(
    'No single indicator determined this assessment. The conclusion was derived by correlating static evidence, runtime behaviour where available, threat intelligence, and deterministic risk scoring.',
  );

  const deployThreshold = data.final_risk_score >= 20 || data.targets_indian_banks;
  if (deployThreshold) {
    sentences.push(
      'Based on the available evidence, enterprise deployment is not recommended. The application should be quarantined while analysts review associated infrastructure, network communication, and affected customer accounts.',
    );
  } else {
    sentences.push(
      'Based on the available evidence, treat distribution as high risk until analyst review completes and runtime coverage gaps are addressed.',
    );
  }

  const qual = qualitativeConfidence(overallConf);
  const sourceCount = [
    (data.manifest_findings?.length || 0) + (data.code_findings?.length || 0) > 0,
    frs?.dynamic_ran,
    threatLinked,
    Number.isFinite(data.final_risk_score),
  ].filter(Boolean).length;

  sentences.push(
    `Overall confidence in this assessment is ${qual} because ${sourceCount} independent evidence source${sourceCount === 1 ? '' : 's'} support the same conclusion.`,
  );

  return sentences.slice(0, 8);
}

export function buildThreatIntelExecutiveNarrative(
  data: FraudCardData,
  intel: IntelApiPayload,
  bundle: InvestigationBundle | null,
  overallConf: number,
): string {
  return buildThreatIntelExecutiveSentences(data, intel, bundle, overallConf).join(' ');
}

export function buildWhatWasDiscovered(
  data: FraudCardData,
  intel: IntelApiPayload,
): string[] {
  const items: string[] = [];
  const family = assignedFamily(data, intel);
  const dna = buildThreatDna(data, null);

  if (family) items.push(`${family} behavioural similarities`);
  if (data.has_accessibility_abuse) items.push('Accessibility abuse detected');
  const cred = dna.find((t) => t.label === 'Credential Theft');
  if (dnaTraitDetected(cred)) items.push('Credential harvesting behaviour');
  if (data.has_system_alert_window) items.push('Overlay / fake login surface capability');
  if (data.has_sms_read_write) items.push('SMS interception risk');
  if (data.targets_indian_banks) items.push('Banking-target indicators');
  if (intel.iocs.length > 0) items.push('Correlated malicious infrastructure indicators');

  if (items.length === 0) {
    items.push('Elevated static risk signals without a single dominant behaviour class');
  }

  return items.slice(0, 6);
}

export function buildWhySudarshanConcluded(
  data: FraudCardData,
  intel: IntelApiPayload,
  bundle: InvestigationBundle | null,
): string[] {
  const bullets: string[] = [];
  const staticOk =
    (data.manifest_findings?.length || 0) + (data.code_findings?.length || 0) > 0 ||
    (bundle?.counts.staticFindings ?? 0) > 0;
  if (staticOk) {
    bullets.push('Static intelligence matched known fraud indicators in manifest, code, and permissions.');
  }
  const frs = data.frs_breakdown;
  if (frs?.dynamic_ran) {
    bullets.push(
      frs.dynamic_conclusive
        ? 'Runtime analysis validated suspicious behaviour under sandbox monitoring.'
        : 'Runtime analysis ran but left behavioural proof partially inconclusive.',
    );
  }
  if (
    assignedFamily(data, intel) ||
    intel.iocs.length > 0 ||
    bundle?.evidenceRecords.some((e) => e.category === 'scenario' || e.category === 'intel')
  ) {
    bullets.push('Threat correlation linked evidence with historical banking attacks and IOC feeds.');
  }
  bullets.push('Risk Engine combined all verified evidence into a deterministic Fraud Risk Score assessment.');
  return bullets;
}

export function buildRecommendedActionBullets(
  data: FraudCardData,
  intel: IntelApiPayload,
  actions: AnalystAction[],
): string[] {
  const bullets: string[] = [];
  const primary = data.recommended_action?.trim() || riskRecommendedAction(data);

  if (data.final_risk_score >= 20 || data.targets_indian_banks) {
    bullets.push('Quarantine the application');
  }
  if (intel.iocs.length > 0 || data.hardcoded_urls_ips.length > 0) {
    bullets.push('Review associated infrastructure and network indicators');
  }
  if (data.targets_indian_banks) {
    bullets.push('Monitor affected banking accounts for fraud patterns');
  }
  bullets.push('Block enterprise deployment until investigation completes');

  const fromEngine = actions
    .filter((a) => a.priority === 'high')
    .map((a) => a.label)
    .filter((label) => !bullets.some((b) => b.toLowerCase().includes(label.toLowerCase())));

  fromEngine.slice(0, 2).forEach((label) => bullets.push(label));

  if (primary && !bullets.some((b) => b === primary)) {
    bullets.unshift(primary);
  }

  return [...new Set(bullets)].slice(0, 5);
}

export type EvidenceSourceChip = {
  id: string;
  label: string;
  active: boolean;
};

export function buildEvidenceSourceChips(
  data: FraudCardData,
  intel: IntelApiPayload,
  bundle: InvestigationBundle | null,
): EvidenceSourceChip[] {
  const staticActive =
    (data.manifest_findings?.length || 0) + (data.code_findings?.length || 0) > 0 ||
    (bundle?.counts.staticFindings ?? 0) > 0;
  const runtimeActive = Boolean(data.frs_breakdown?.dynamic_ran || data.dynamic_available);
  const intelActive = intel.sources_status.some((s) => s.status === 'active') || intel.sources.length > 0;
  const iocActive = intel.iocs.length > 0;
  const riskActive = Number.isFinite(data.final_risk_score);
  const aiActive = Boolean(intel.ai_summary?.trim());

  return [
    { id: 'static', label: 'Static Analysis', active: staticActive },
    { id: 'runtime', label: 'Runtime Behaviour', active: runtimeActive },
    { id: 'threat', label: 'Threat Intelligence', active: intelActive },
    { id: 'ioc', label: 'IOC Correlation', active: iocActive },
    { id: 'risk', label: 'Deterministic Risk Engine', active: riskActive },
    { id: 'ai', label: 'AI Investigation', active: aiActive },
  ];
}
