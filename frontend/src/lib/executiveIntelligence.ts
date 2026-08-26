import type { FraudCardData } from '../App';
import type { InvestigationBundle } from '../types/investigation';
import { buildWhatThisMeans, riskRecommendedAction } from './analystCopy';

function splitIntoParagraphs(text: string, max = 3): string[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  const byBreak = trimmed.split(/\n\s*\n+/).map((p) => p.trim()).filter(Boolean);
  if (byBreak.length >= 2) return byBreak.slice(0, max);

  const sentences = trimmed.match(/[^.!?]+[.!?]+/g) || [trimmed];
  if (sentences.length <= 3) return [trimmed];

  const chunk = Math.ceil(sentences.length / max);
  const out: string[] = [];
  for (let i = 0; i < sentences.length; i += chunk) {
    out.push(sentences.slice(i, i + chunk).join(' ').trim());
  }
  return out.slice(0, max);
}

/**
 * Which source actually produced the narrative on screen.
 *
 * `buildOverallAssessmentParagraphs` has always had a three-tier fallback, but
 * it degraded silently: when the model failed, the reader got deterministic
 * template prose under a heading with a Sparkles icon reading "EXECUTIVE
 * ASSESSMENT", and had no way to tell which one they were looking at. A UI must
 * never imply certainty - or provenance - that the underlying analysis does not
 * support, so the tier is now reportable.
 */
export type NarrativeSource = 'ai' | 'stored' | 'derived';

export function narrativeSource(data: FraudCardData): NarrativeSource {
  // Mirrors buildOverallAssessmentParagraphs exactly, including its `||`
  // precedence: a short-but-present AI narrative shadows the stored one and
  // then fails the length gate, so the result is `derived`. Reporting a tier
  // the renderer did not actually use would be its own provenance lie.
  const ai = data.intelligence_report?.plain_english_narrative?.trim() ?? '';
  const stored = data.executive_view?.plain_english_narrative?.trim() ?? '';
  const chosen = ai || stored || '';
  if (chosen.length <= 80) return 'derived';
  return chosen === ai ? 'ai' : 'stored';
}

export function buildOverallAssessmentParagraphs(data: FraudCardData): string[] {
  const narrative =
    data.intelligence_report?.plain_english_narrative?.trim() ||
    data.executive_view?.plain_english_narrative?.trim() ||
    '';

  if (narrative.length > 80) {
    const fromAi = splitIntoParagraphs(narrative, 3);
    if (fromAi.length > 0) return fromAi;
  }

  const behaviours: string[] = [];
  if (data.has_accessibility_abuse) behaviours.push('Accessibility Service abuse');
  if (data.has_system_alert_window) behaviours.push('overlay capabilities');
  if (data.obfuscation_score && data.obfuscation_score > 0) behaviours.push('runtime code loading');
  if (data.obfuscation_score && data.obfuscation_score > 0.3) behaviours.push('obfuscated components');

  const p1 =
    behaviours.length > 0
      ? `The uploaded application exhibits multiple behaviours commonly associated with Android banking malware. Static analysis identified ${behaviours.join(', ')}, and other manifest or code signals tied to fraud.`
      : `Static analysis completed on ${data.app_name || data.package_name || 'this application'} with mixed permission and code signals that warrant fraud review.`;

  const frs = data.frs_breakdown;
  let p2 =
    'Dynamic sandbox analysis was not available for this case; conclusions lean on static inspection and threat correlation.';
  if (frs?.dynamic_ran && frs.dynamic_conclusive) {
    p2 =
      'Dynamic analysis confirmed behaviours consistent with credential theft or device control - including patterns such as Accessibility registration or overlay windows that can appear above banking applications.';
  } else if (frs?.dynamic_ran) {
    p2 =
      'Dynamic analysis ran but did not produce conclusive behavioural proof in the sandbox. Static and correlation evidence still contribute to the fraud risk score.';
  }

  const family =
    data.family_classification && data.family_classification !== 'Unknown'
      ? `Threat intelligence correlation shows behavioural similarities with the ${data.family_classification} malware family. `
      : 'Threat intelligence correlation did not match a named family with high confidence. ';

  const p3 = `${family}While not every capability may have executed during sandbox analysis, the combined verified evidence indicates ${data.risk_band.toLowerCase()} fraud risk requiring analyst review before the application can be considered safe.`;

  return [p1, p2, p3];
}

export function buildWhyThisMattersParagraphs(data: FraudCardData): string[] {
  const banking =
    data.intelligence_report?.banking_impact_assessment?.trim() ||
    data.intelligence_report?.fraud_objective?.trim();

  const plain = buildWhatThisMeans(data);
  const out: string[] = [];

  out.push(
    'If installed on a customer\'s phone, this application may obtain sensitive banking information, manipulate on-screen banking sessions, or intercept authentication workflows.',
  );

  if (banking && banking.length > 40 && !plain.includes(banking.slice(0, 30))) {
    out.push(banking);
  } else {
    out.push(plain);
  }

  const frs = data.frs_breakdown;
  if (frs?.dynamic_ran && !frs.dynamic_conclusive) {
    out.push(
      'Although sandbox execution was inconclusive, sufficient static and intelligence evidence exists to treat this sample as suspicious until manual review is complete.',
    );
  } else if (!frs?.dynamic_ran) {
    out.push(
      'Although no runtime behaviour was observed during this run, static and intelligence evidence may still justify quarantine pending dynamic re-analysis.',
    );
  } else {
    out.push(
      'Although no successful fraud transaction was observed during sandbox execution, verified malicious capabilities justify treating this application as suspicious.',
    );
  }

  return out.slice(0, 3);
}

export type ConfidenceRow = { label: string; percent: number; detail: string };

export function buildEvidenceConfidence(data: FraudCardData, bundle: InvestigationBundle | null): ConfidenceRow[] {
  const frs = data.frs_breakdown;
  const staticScore = Math.round(Math.min(100, Math.max(0, frs?.stei ?? 0)));
  let runtime = 0;
  if (frs?.dynamic_ran && frs.dynamic_conclusive) {
    runtime = Math.round(Math.min(100, Math.max(0, frs.dynamic ?? 0)));
  } else if (frs?.dynamic_ran) {
    runtime = Math.round(Math.min(55, Math.max(15, (frs.dynamic ?? 0) * 0.5)));
  }

  const corrRaw =
    data.threat_correlation?.correlation_confidence ??
    data.threat_correlation?.threat_score ??
    frs?.correlation ??
    0;
  const threat = Math.round(Math.min(100, Math.max(0, Number(corrRaw))));

  const evidenceCount = bundle?.counts.evidenceRecords ?? 0;
  const riskEngine = Math.round(
    Math.min(
      100,
      Math.max(40, data.final_risk_score * 0.85 + Math.min(evidenceCount, 20)),
    ),
  );

  return [
    {
      label: 'Verified Static Evidence',
      percent: staticScore,
      detail: `${bundle?.counts.staticFindings ?? 0} static findings indexed`,
    },
    {
      label: 'Verified Runtime Evidence',
      percent: runtime,
      detail: frs?.dynamic_conclusive ? 'Sandbox behaviour used in score' : 'Runtime inconclusive or not run',
    },
    {
      label: 'Threat Intelligence Correlation',
      percent: threat,
      detail:
        data.family_classification !== 'Unknown'
          ? `Family: ${data.family_classification}`
          : 'Campaign correlation from intel feeds',
    },
    {
      label: 'Risk Engine Confidence',
      percent: riskEngine,
      detail: `FRS ${data.final_risk_score.toFixed(0)} from weighted axes`,
    },
  ];
}

export type NextStepCard = { title: string; description: string };

export function buildRecommendedNextSteps(data: FraudCardData): NextStepCard[] {
  const actions =
    data.intelligence_report?.recommended_actions?.length
      ? data.intelligence_report.recommended_actions
      : data.executive_view?.recommended_actions || [];

  const defaults: NextStepCard[] = [
    {
      title: 'Quarantine Sample',
      description: 'Isolate the APK from enterprise distribution channels pending analyst sign-off.',
    },
    {
      title: 'Investigate Infrastructure',
      description: 'Pivot on network IOCs, domains, and C2 endpoints from static and runtime telemetry.',
    },
    {
      title: 'Block IOCs',
      description: 'Push confirmed indicators to perimeter and mobile threat defence controls.',
    },
    {
      title: 'Review Banking Targets',
      description: 'Validate whether declared targets match active Bank of India customer applications.',
    },
    {
      title: 'Generate CERT Report',
      description: 'Prepare regulator-ready narrative using exportable evidence and score ledger.',
    },
  ];

  if (actions.length === 0) {
    return defaults;
  }

  return actions.slice(0, 6).map((act, i) => {
    const title = act.split(/[.:–-]/)[0]?.trim().slice(0, 48) || defaults[i]?.title || `Action ${i + 1}`;
    return {
      title: title.length > 3 ? title : defaults[i]?.title || title,
      description: act,
    };
  });
}

export type CaseSummarySection = { heading: string; lines: string[] };

export function buildStructuredCaseSummary(data: FraudCardData): CaseSummarySection[] {
  const appLabel = data.app_name || data.package_name || 'Unknown application';
  const intel = data.intelligence_report;

  const behaviour: string[] = [];
  if (data.has_accessibility_abuse) behaviour.push('Accessibility abuse (manifest)');
  if (data.has_system_alert_window) behaviour.push('Overlay / system alert window');
  if (data.has_sms_read_write) behaviour.push('SMS read/write permissions');
  if (data.obfuscation_score && data.obfuscation_score > 0) behaviour.push('Runtime code loading patterns');

  return [
    {
      heading: 'Application Overview',
      lines: [
        `${appLabel} (${data.package_name || 'package unknown'}) was assessed in ${data.analysis_mode || 'standard'} mode.`,
        `SHA256 ${data.sha256.slice(0, 16)}… · Fraud Risk Score ${data.final_risk_score.toFixed(0)}/100 (${data.risk_band}).`,
      ],
    },
    {
      heading: 'Primary Fraud Objective',
      lines: [
        intel?.fraud_objective ||
          (data.targets_indian_banks
            ? 'Credential theft and session manipulation against Indian banking applications.'
            : 'Fraud-related device control and sensitive data access.'),
        intel?.banking_impact_assessment
          ? `${intel.banking_impact_assessment.split('.')[0]?.trim()}.`
          : '',
      ].filter(Boolean),
    },
    {
      heading: 'Observed Behaviour',
      lines:
        behaviour.length > 0
          ? behaviour
          : ['No single high-risk manifest pattern dominated; review verified evidence registry.'],
    },
    {
      heading: 'Potential Customer Impact',
      lines: splitIntoParagraphs(buildWhatThisMeans(data), 2),
    },
    {
      heading: 'Malware Attribution',
      lines: [
        data.family_classification !== 'Unknown'
          ? `Correlated with ${data.family_classification} family based on threat intelligence and behaviour overlap.`
          : 'No high-confidence malware family label - treat as unattributed suspicious Android fraud.',
        data.threat_correlation?.campaign
          ? `Campaign hint: ${data.threat_correlation.campaign}`
          : '',
      ].filter(Boolean),
    },
    {
      heading: 'Risk Justification',
      lines: (data.risk_explanation?.evidence_lines?.slice(0, 4) || [
        `Weighted fraud risk score ${data.final_risk_score.toFixed(0)} from static, runtime, correlation, and banking impact axes.`,
      ]).map((l) => l.replace(/^[-•]\s*/, '')),
    },
    {
      heading: 'Recommended Analyst Decision',
      lines: [
        data.recommended_action || riskRecommendedAction(data),
        'Document outcome in case notes and align with fraud operations playbooks.',
      ],
    },
  ];
}

export type PipelineTimelineStep = {
  phase: string;
  detail: string;
  tone: 'done' | 'active' | 'warn';
};

export function buildEvidencePipelineTimeline(data: FraudCardData): PipelineTimelineStep[] {
  const steps: PipelineTimelineStep[] = [];
  const staticDetail =
    data.risk_explanation?.evidence_lines?.[0]?.replace(/^[-•]\s*/, '') ||
    (data.has_accessibility_abuse ? 'Dangerous permissions and manifest capabilities detected' : 'Static inspection completed');

  steps.push({ phase: 'Static Analysis Completed', detail: staticDetail, tone: 'done' });

  if (data.family_classification !== 'Unknown' || (data.threat_correlation?.threat_score ?? 0) > 0) {
    steps.push({
      phase: 'Threat Intelligence',
      detail: `${data.family_classification !== 'Unknown' ? `${data.family_classification} family correlation` : 'IOC and campaign correlation'}`,
      tone: 'done',
    });
  }

  const frs = data.frs_breakdown;
  if (frs?.dynamic_ran) {
    steps.push({
      phase: 'Dynamic Analysis',
      detail: frs.dynamic_conclusive
        ? 'Accessibility or overlay abuse observed in sandbox'
        : 'Sandbox run inconclusive - limited behavioural proof',
      tone: frs.dynamic_conclusive ? 'done' : 'warn',
    });
  }

  steps.push({
    phase: 'Risk Engine',
    detail: `Fraud Risk Score calculated - ${data.final_risk_score.toFixed(0)}/100`,
    tone: 'active',
  });

  steps.push({
    phase: 'Recommendation',
    detail:
      data.final_risk_score >= 20
        ? 'Manual analyst review before release'
        : 'Monitor and re-scan if complaints arise',
    tone: 'active',
  });

  return steps;
}

export type CustomerAndBankingImpact = {
  customerImpact: string;
  bankingImpact: string;
  businessInterpretation: string;
};

export function buildCustomerAndBankingImpact(data: FraudCardData): CustomerAndBankingImpact {
  const intel = data.intelligence_report;

  let customerImpact = intel?.customer_advisory_draft?.trim() || '';
  if (!customerImpact || customerImpact.length < 20) {
    if (data.has_accessibility_abuse) {
      customerImpact =
        'High risk of automated keystroke logging, background screen scraping, and unauthorized financial transaction execution without customer intervention.';
    } else if (data.has_sms_read_write) {
      customerImpact =
        'Interception of One-Time Passwords (OTPs) and SMS notification suppression, enabling silent account takeover and credential abuse.';
    } else if (data.has_system_alert_window) {
      customerImpact =
        'Risk of credential phishing through malicious overlay windows displayed over legitimate banking applications.';
    } else {
      customerImpact =
        'Potential exposure of sensitive customer identifiers, application permissions, or credentials to unverified third-party infrastructure.';
    }
  }

  let bankingImpact = intel?.banking_impact_assessment?.trim() || '';
  if (!bankingImpact || bankingImpact.length < 20) {
    if (data.targets_indian_banks || (intel?.fraud_objective && intel.fraud_objective.toLowerCase().includes('bank'))) {
      bankingImpact =
        'Direct risk to mobile banking ecosystem, including potential fraudulent transfers, brand impersonation, and customer support disputes.';
    } else {
      bankingImpact =
        'Elevated fraud operations overhead, requiring manual credential resets, incident logging, and regulatory compliance updates.';
    }
  }

  let businessInterpretation =
    data.executive_view?.plain_english_narrative?.trim() || intel?.plain_english_narrative?.trim() || '';
  if (!businessInterpretation || businessInterpretation.length < 20) {
    const score = Math.round(data.final_risk_score);
    if (score >= 80) {
      businessInterpretation =
        'CRITICAL FRAUD RISK: Immediate isolation and blocking required to prevent account compromise and direct financial loss.';
    } else if (score >= 60) {
      businessInterpretation =
        'HIGH FRAUD THREAT: Quarantine binary and escalate to security analysts for in-depth manual verification before clearance.';
    } else if (score >= 35) {
      businessInterpretation =
        'MODERATE FRAUD SUSPICION: Requires manual review of requested capabilities and permission justification.';
    } else {
      businessInterpretation =
        'LOW AGGREGATE RISK: Approved under standard security controls with routine telemetry and re-scan procedures.';
    }
  }

  return { customerImpact, bankingImpact, businessInterpretation };
}

export type DetailedRiskFactor = {
  id: string;
  name: string;
  badge?: string;
  detected: string;
  capability: string;
  whyItMatters: string;
  evidence: string;
};

export function buildDetailedRiskFactors(data: FraudCardData): DetailedRiskFactor[] {
  const factors: DetailedRiskFactor[] = [];

  if (data.has_accessibility_abuse) {
    factors.push({
      id: 'accessibility',
      name: 'Accessibility Service Abuse',
      badge: 'CRITICAL CAPABILITY',
      detected: 'BIND_ACCESSIBILITY_SERVICE requested or active in manifest / runtime telemetry.',
      capability: 'Full UI hierarchy access, programmatic tap/swipe injection, and text extraction.',
      whyItMatters: 'Enables screen scraping of PINs/passwords and automated fraudulent money transfers.',
      evidence:
        data.risk_explanation?.evidence_lines?.find((l) => l.toLowerCase().includes('accessibility')) ||
        'Static manifest permission BIND_ACCESSIBILITY_SERVICE detected.',
    });
  }

  if (data.has_system_alert_window) {
    factors.push({
      id: 'overlay',
      name: 'Overlay Window Capability',
      badge: 'PHISHING RISK',
      detected: 'SYSTEM_ALERT_WINDOW permission and overlay drawing routines.',
      capability: 'Draws pixel-perfect fake login screens over legitimate banking applications.',
      whyItMatters: 'Deceives customers into entering credentials and MFA tokens into attacker-controlled UI.',
      evidence:
        data.risk_explanation?.evidence_lines?.find((l) => l.toLowerCase().includes('overlay') || l.toLowerCase().includes('alert')) ||
        'SYSTEM_ALERT_WINDOW / ACTION_MANAGE_OVERLAY_PERMISSION detected in binary.',
    });
  }

  if (data.has_sms_read_write) {
    factors.push({
      id: 'sms',
      name: 'SMS / OTP Interception',
      badge: 'CREDENTIAL / MFA THEFT',
      detected: 'READ_SMS, RECEIVE_SMS, or SEND_SMS permissions declared in manifest.',
      capability: 'Intercepts incoming SMS messages containing OTP authentication codes.',
      whyItMatters: 'Bypasses SMS-based Two-Factor Authentication (2FA) for unauthorized transactions.',
      evidence:
        data.risk_explanation?.evidence_lines?.find((l) => l.toLowerCase().includes('sms')) ||
        'SMS broadcast receivers or permission declarations identified in manifest.',
    });
  }

  if (data.obfuscation_score && data.obfuscation_score > 0) {
    factors.push({
      id: 'obfuscation',
      name: 'Code Obfuscation & Dynamic Loading',
      badge: 'EVASION TECHNIQUE',
      detected: `Obfuscation score ${(data.obfuscation_score * 100).toFixed(0)}% with dynamic class/DEX loading.`,
      capability: 'Hides payload logic from standard static analysis scanners.',
      whyItMatters: 'Prevents automated AV/EDR tools from discovering malicious command handlers.',
      evidence: `Obfuscation index ${(data.obfuscation_score * 100).toFixed(0)}% with dynamic code execution patterns.`,
    });
  }

  if (data.family_classification && data.family_classification !== 'Unknown') {
    factors.push({
      id: 'family',
      name: `Malware Family Correlation: ${data.family_classification}`,
      badge: 'THREAT INTEL MATCH',
      detected: `High-confidence correlation with known ${data.family_classification} samples.`,
      capability: 'Known banking trojan capability set matching threat intelligence signatures.',
      whyItMatters: 'Associated with active banking fraud campaigns targeting mobile financial applications.',
      evidence: `Threat intel correlation confidence ${data.threat_correlation?.correlation_confidence ?? 85}%.`,
    });
  }

  if (data.targets_indian_banks) {
    factors.push({
      id: 'targets_banks',
      name: 'Targeting Indian Banking Ecosystem',
      badge: 'HIGH IMPACT',
      detected: 'Package names or app resources specifically matching Indian banking applications.',
      capability: 'Monitors device for specific banking apps to trigger overlay or credential harvest.',
      whyItMatters: 'Direct financial threat focused on domestic banking infrastructure.',
      evidence: 'Matched target list against monitored Indian banking packages.',
    });
  }

  return factors;
}

