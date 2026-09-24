import type { FraudCardData } from '../types/case';
import type { LedgerScope } from '../types/investigation';
import { computeWeightedContribution, getAxesUsed } from './scoreLedger';

export type EvidenceSourceTag = 'Static Analysis' | 'Runtime Analysis' | 'Threat Intelligence';

export type RiskDriver = {
  id: string;
  title: string;
  iconKey: 'shield' | 'layers' | 'code' | 'fingerprint' | 'activity' | 'message' | 'landmark' | 'eye';
  points: number;
  impact: 'High Impact' | 'Medium Impact' | 'Low Impact';
  explanation: string;
  sources: EvidenceSourceTag[];
  scopeTags: Array<'static' | 'runtime' | 'threat' | 'banking'>;
  evidenceId?: string;
};

function impactFromPoints(points: number): RiskDriver['impact'] {
  if (points >= 14) return 'High Impact';
  if (points >= 6) return 'Medium Impact';
  return 'Low Impact';
}

function allocateIntegerPoints(
  total: number,
  weights: Array<{ id: string; weight: number }>,
): Map<string, number> {
  const active = weights.filter((w) => w.weight > 0);
  const result = new Map<string, number>();
  if (active.length === 0 || total <= 0) return result;

  const sum = active.reduce((s, w) => s + w.weight, 0);
  const entries = active.map((w) => {
    const exact = (w.weight / sum) * total;
    const floor = Math.floor(exact);
    return { id: w.id, floor, frac: exact - floor };
  });

  let allocated = entries.reduce((s, e) => s + e.floor, 0);
  const remainder = Math.max(0, Math.round(total) - allocated);
  entries.sort((a, b) => b.frac - a.frac);
  for (let i = 0; i < remainder; i += 1) {
    entries[i % entries.length].floor += 1;
  }
  entries.forEach((e) => result.set(e.id, e.floor));
  return result;
}

type DriverDraft = Omit<RiskDriver, 'points' | 'impact'> & { weight: number };

export function buildRiskDrivers(data: FraudCardData): RiskDriver[] {
  const frs = data.frs_breakdown;
  const steiAxes = frs?.stei_axes || { ct: 0, bt: 0, pr: 0, ob: 0, ir: 0 };
  const axesUsed = getAxesUsed(data);
  const drafts: DriverDraft[] = [];

  if (data.has_accessibility_abuse) {
    const runtime = Boolean(frs?.dynamic_ran && frs.dynamic_conclusive);
    drafts.push({
      id: 'accessibility',
      title: 'Accessibility Abuse',
      iconKey: 'shield',
      weight: Math.max(18, (steiAxes.ct ?? 0) * 0.55 + (runtime ? (frs?.dynamic ?? 0) * 0.25 : 0)),
      explanation:
        'The application requests Accessibility privileges that can control or observe other applications, making credential theft or remote interaction possible.',
      sources: runtime ? ['Static Analysis', 'Runtime Analysis'] : ['Static Analysis'],
      scopeTags: runtime ? ['static', 'runtime'] : ['static'],
      evidenceId: 'STAT-A11Y',
    });
  }

  if (data.has_system_alert_window) {
    drafts.push({
      id: 'overlay',
      title: 'Overlay Capability',
      iconKey: 'layers',
      weight: Math.max(8, (steiAxes.pr ?? 0) * 0.45 + (steiAxes.ct ?? 0) * 0.15),
      explanation:
        'The application can display windows over other apps, allowing fake banking login screens to be presented above legitimate applications.',
      sources: ['Static Analysis'],
      scopeTags: ['static'],
      evidenceId: 'STAT-OVERLAY',
    });
  }

  if (data.has_sms_read_write) {
    drafts.push({
      id: 'sms',
      title: 'SMS & OTP Interception',
      iconKey: 'message',
      weight: Math.max(10, (steiAxes.ct ?? 0) * 0.35),
      explanation:
        'SMS read or receive permissions can allow interception of one-time passwords sent by banks during login or transaction approval.',
      sources: ['Static Analysis'],
      scopeTags: ['static'],
      evidenceId: 'STAT-SMS',
    });
  }

  if (data.obfuscation_score && data.obfuscation_score > 0) {
    drafts.push({
      id: 'obfuscation',
      title: 'Code Obfuscation',
      iconKey: 'code',
      weight: Math.max(5, (steiAxes.ob ?? 0) * 0.5 + data.obfuscation_score * 12),
      explanation:
        'The application intentionally hides its internal implementation using obfuscation techniques commonly seen in malware to evade inspection.',
      sources: ['Static Analysis'],
      scopeTags: ['static'],
      evidenceId: 'STAT-CODE-0',
    });
  }

  if (frs?.concealed_payload) {
    drafts.push({
      id: 'concealed',
      title: 'Concealed Payload',
      iconKey: 'eye',
      weight: Math.max(7, (steiAxes.ob ?? 0) * 0.4 + 6),
      explanation:
        'Static analysis detected hidden or dynamically loaded components designed to conceal malicious functionality from initial review.',
      sources: ['Static Analysis'],
      scopeTags: ['static'],
    });
  }

  const corrWeighted = frs
    ? computeWeightedContribution('correlation', frs.correlation, axesUsed)
    : 0;
  if (corrWeighted > 0.5 || data.family_classification !== 'Unknown') {
    const family = data.family_classification !== 'Unknown' ? data.family_classification : 'known fraud campaigns';
    drafts.push({
      id: 'threat-intel',
      title: 'Threat Intelligence Match',
      iconKey: 'fingerprint',
      weight: Math.max(4, corrWeighted + (data.family_classification !== 'Unknown' ? 6 : 0)),
      explanation: `Behaviour and indicators are consistent with the ${family} banking malware family and correlated threat intelligence.`,
      sources: ['Threat Intelligence'],
      scopeTags: ['threat'],
    });
  }

  if (frs?.dynamic_ran) {
    const runtimeWeight = frs.dynamic_conclusive
      ? Math.max(3, computeWeightedContribution('dynamic', frs.dynamic, axesUsed))
      : Math.max(1, computeWeightedContribution('dynamic', frs.dynamic, axesUsed) * 0.35);
    if (runtimeWeight > 0.2) {
      drafts.push({
        id: 'runtime',
        title: 'Runtime Behaviour',
        iconKey: 'activity',
        weight: runtimeWeight,
        explanation: frs.dynamic_conclusive
          ? 'Suspicious behaviour was confirmed during sandbox execution, increasing confidence in the assessment.'
          : 'Sandbox execution produced partial behavioural signals; runtime evidence is treated cautiously in the final score.',
        sources: ['Runtime Analysis'],
        scopeTags: ['runtime'],
      });
    }
  }

  if (data.targets_indian_banks || (frs?.banking_impact ?? 0) > 15) {
    const bankingWeight = Math.max(
      4,
      computeWeightedContribution('banking_impact', frs?.banking_impact ?? 0, axesUsed),
    );
    drafts.push({
      id: 'banking',
      title: 'Banking Targeting',
      iconKey: 'landmark',
      weight: bankingWeight,
      explanation:
        'Manifest or code references suggest targeting of banking applications used by customers, elevating fraud impact.',
      sources: data.targets_indian_banks ? ['Static Analysis', 'Threat Intelligence'] : ['Static Analysis'],
      scopeTags: ['banking', 'static'],
    });
  }

  if (drafts.length === 0) {
    const fallbackLines = data.risk_explanation?.evidence_lines?.filter(Boolean) || [];
    drafts.push({
      id: 'general',
      title: 'Verified Risk Signals',
      iconKey: 'shield',
      weight: 1,
      explanation:
        fallbackLines[0]?.replace(/^[-•]\s*/, '') ||
        'Multiple verified findings from static and intelligence analysis contributed to the fraud risk score.',
      sources: ['Static Analysis'],
      scopeTags: ['static'],
    });
  }

  const targetScore = Math.round(data.final_risk_score);
  const pointsMap = allocateIntegerPoints(
    targetScore,
    drafts.map((d) => ({ id: d.id, weight: d.weight })),
  );

  const drivers: RiskDriver[] = drafts
    .map((d) => {
      const points = pointsMap.get(d.id) ?? 0;
      return {
        ...d,
        points,
        impact: impactFromPoints(points),
      };
    })
    .filter((d) => d.points > 0)
    .sort((a, b) => b.points - a.points);

  return drivers;
}

export function filterDriversByScope(drivers: RiskDriver[], scope: LedgerScope): RiskDriver[] {
  if (scope === 'full') return drivers;
  if (scope === 'dynamic') return drivers.filter((d) => d.scopeTags.includes('runtime'));
  if (scope === 'correlation') return drivers.filter((d) => d.scopeTags.includes('threat'));
  if (scope === 'banking') return drivers.filter((d) => d.scopeTags.includes('banking'));
  if (scope === 'stei') return drivers.filter((d) => d.scopeTags.includes('static'));
  return drivers.filter((d) => d.scopeTags.includes('static'));
}

export function buildSuspiciousNarrative(data: FraudCardData): string[] {
  const narrative =
    data.intelligence_report?.plain_english_narrative?.trim() ||
    data.executive_view?.plain_english_narrative?.trim() ||
    '';

  if (narrative.length > 100) {
    const parts = narrative.split(/\n\s*\n+/).map((p) => p.trim()).filter(Boolean);
    if (parts.length >= 2) return parts.slice(0, 3);
    const sentences = narrative.match(/[^.!?]+[.!?]+/g) || [narrative];
    if (sentences.length <= 3) return [narrative];
    const chunk = Math.ceil(sentences.length / 3);
    const out: string[] = [];
    for (let i = 0; i < sentences.length; i += chunk) {
      out.push(sentences.slice(i, i + chunk).join(' ').trim());
    }
    return out.slice(0, 3);
  }

  const capabilities: string[] = [];
  if (data.has_accessibility_abuse) capabilities.push('Accessibility Service abuse');
  if (data.has_system_alert_window) capabilities.push('overlay windows');
  if (data.has_sms_read_write) capabilities.push('SMS interception');
  if (data.obfuscation_score && data.obfuscation_score > 0) capabilities.push('code obfuscation');

  const appLabel = data.app_name || data.package_name || 'This application';
  const p1 =
    capabilities.length > 0
      ? `${appLabel} was built with capabilities that are uncommon in legitimate banking software, including ${capabilities.join(', ')}. These features can be abused to observe or control what happens on the device.`
      : `${appLabel} triggered multiple verified fraud indicators during static and intelligence review.`;

  const frs = data.frs_breakdown;
  let p2 = 'Threat intelligence and static evidence were combined to estimate fraud risk.';
  if (frs?.dynamic_ran && frs.dynamic_conclusive) {
    p2 = `Runtime sandbox analysis confirmed suspicious behaviour, strengthening confidence in the assessment.${
      data.family_classification !== 'Unknown' ? ` Indicators align with the ${data.family_classification} malware family.` : ''
    }`;
  } else if (data.family_classification !== 'Unknown') {
    p2 = `Threat intelligence correlates this sample with the ${data.family_classification} family. Runtime coverage was ${
      frs?.dynamic_ran ? 'inconclusive' : 'not available'
    }, so static and intel evidence carry more weight.`;
  } else if (frs?.dynamic_ran && !frs.dynamic_conclusive) {
    p2 =
      'Dynamic analysis ran but did not produce conclusive proof of exploitation; the score still reflects strong static and intelligence signals.';
  }

  const p3 =
    data.final_risk_score >= 20
      ? `Overall, the evidence supports a ${data.risk_band.toLowerCase()} classification. The application should not be trusted for enterprise or customer devices without manual analyst review.`
      : 'Overall risk is lower, but residual signals warrant monitoring if the application is distributed outside controlled channels.';

  return [p1, p2, p3];
}

export function buildWhatThisMeansNarrative(data: FraudCardData): string[] {
  const intel = data.intelligence_report;
  const custom = intel?.banking_impact_assessment?.trim();
  const paragraphs: string[] = [];

  paragraphs.push(
    'This application appears to prioritize device control over normal user functionality. The combination of high-risk capabilities and verified intelligence suggests behaviour that could facilitate credential theft or unauthorized interaction with banking applications.',
  );

  if (custom && custom.length > 40) {
    paragraphs.push(custom);
  } else {
    paragraphs.push(
      `Although no successful banking transaction was observed during analysis, sufficient verified evidence exists to classify the application as ${data.risk_band}. Manual analyst review is recommended before deployment in any enterprise or banking environment.`,
    );
  }

  const rec = data.recommended_action || intel?.recommended_actions?.[0];
  if (rec) {
    paragraphs.push(rec);
  }

  return paragraphs.slice(0, 3);
}
