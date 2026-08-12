import type { FraudCardData } from '../App';
import type { InvestigationBundle } from '../types/investigation';
import { getRiskStyle } from '../theme/colors';

export const TERM_HELP: Record<string, string> = {
  'Static Analysis':
    'Inspects the application without running it (code inspection).',
  'Code Inspection': 'Inspects application files without executing the APK.',
  'Dynamic Analysis':
    'Runs the application safely inside an isolated Android sandbox.',
  'Threat Correlation': 'Matches findings against known malware campaigns.',
  IOC: 'Indicators of Compromise such as domains, IPs and hashes.',
  'Threat Infrastructure': 'Known malicious domains, IPs, and file hashes linked to campaigns.',
  MITRE: 'Industry-standard catalogue of attacker techniques (MITRE ATT&CK).',
  Accessibility:
    'Android feature that can read screen content and automate taps - often abused against banking apps.',
  'Accessibility Abuse':
    'Allows malware to control the phone without the user\'s knowledge.',
  'Overlay Attack':
    'Can display fake banking login screens over legitimate apps.',
  'Runtime Code Loading':
    'Downloads or loads hidden code after installation.',
  Obfuscation:
    'Makes the application\'s code difficult to inspect.',
  'SMS Interception':
    'May allow theft of one-time passwords sent by SMS.',
  Overlay:
    'A floating window drawn above other apps, sometimes used to mimic login screens.',
  Runtime: 'Behaviour observed while the app runs in the sandbox.',
  'Malware Family': 'A named group of apps that share similar fraud techniques.',
  Confidence: 'How certain Sudarshan is about this conclusion, based on verified evidence.',
  Evidence: 'Observations tied to analysis engines and scoring.',
  'Verified Evidence': 'Observations that passed Sudarshan verification and feed the risk score.',
  'Risk Score': '0–100 fraud risk rating derived from weighted, verified evidence.',
  Hydra: 'Detected malware family showing similar behaviour in prior banking fraud cases.',
  'Runtime Behaviour Confirmed':
    'Sandbox execution produced conclusive behavioural evidence for scoring.',
  'Threat Intelligence': 'Known malware infrastructure and campaign matches.',
  FRS: 'Fraud Risk Score - the evidence-based overall risk level of the application from 0 to 100.',
  STEI: 'Static Threat Exposure - suspicious capabilities identified inside the APK before execution.',
  BFCI: 'Behavioral Fraud Confidence Index - scores suspicious runtime behaviour when conclusive sandbox evidence exists.',
  'Dynamic Sandbox':
    'An isolated Android environment used to execute the APK safely and observe its behavior.',
  'Runtime Inconclusive':
    'The sandbox ran, but insufficient reliable behavior was captured to use runtime evidence in the final risk score.',
  'Axis Excluded':
    'This evidence source was intentionally excluded because the available data was insufficiently reliable.',
  VIDE: 'Visual Impersonation Detection Engine - checks whether the application interface resembles known banking interfaces.',
  'MITRE ATT&CK': 'A standardized framework used to describe attacker techniques observed in the application.',
};

export function riskBandPlainEnglish(band: string): string {
  const b = (band || '').toLowerCase();
  if (b.includes('critical')) return 'Critical';
  if (b.includes('high')) return 'High Risk';
  if (b.includes('suspicious')) return 'Suspicious';
  if (b.includes('safe') || b.includes('low')) return 'Lower Concern';
  return band || 'Under Review';
}

export function riskRecommendedAction(data: FraudCardData): string {
  const score = data.final_risk_score;
  const band = (data.risk_band || '').toLowerCase();
  if (band.includes('critical') || score >= 75) {
    return 'Block distribution immediately and open a priority fraud investigation.';
  }
  if (band.includes('high') || score >= 50) {
    return 'Treat as high-risk fraud. Escalate and block pending analyst confirmation.';
  }
  if (band.includes('suspicious') || score >= 20) {
    return 'Some malicious behaviour was identified. Manual investigation recommended before customer impact.';
  }
  return 'Limited concerning signals. Monitor and re-scan if the app changes or new complaints arrive.';
}

export function riskLevelMeaning(data: FraudCardData): string {
  const score = data.final_risk_score;
  const band = (data.risk_band || '').toLowerCase();
  if (band.includes('critical') || score >= 75) {
    return 'Strong indicators of banking fraud malware. Customer harm is likely if installed.';
  }
  if (band.includes('high') || score >= 50) {
    return 'Multiple high-risk capabilities align with known fraud patterns.';
  }
  if (band.includes('suspicious') || score >= 20) {
    return 'Some malicious behaviour was identified. Not every capability may have run in the sandbox.';
  }
  return 'Few or no verified malicious behaviours. Residual risk may remain from limited runtime coverage.';
}

export function buildWhatThisMeans(data: FraudCardData): string {
  const parts: string[] = [];
  if (data.has_sms_read_write) {
    parts.push('read one-time passwords (OTPs) from SMS');
  }
  if (data.has_accessibility_abuse) {
    parts.push('interact with banking applications through Accessibility services');
  }
  if (data.has_system_alert_window) {
    parts.push('draw overlay windows above other apps');
  }
  if (data.targets_indian_banks) {
    parts.push('reference Indian banking applications');
  }
  const capability =
    parts.length > 0
      ? `The application may be capable of ${parts.join(', ')}.`
      : 'The application shows signals that warrant review, but no single high-risk permission dominated the assessment.';
  const frs = data.frs_breakdown;
  const runtimeNote =
    frs?.dynamic_ran && frs.dynamic_conclusive
      ? 'Runtime behaviour in the sandbox supports these concerns.'
      : frs?.dynamic_ran && !frs.dynamic_conclusive
        ? 'Runtime monitoring was inconclusive; conclusions lean on code inspection and threat matches.'
        : 'Runtime monitoring did not complete; conclusions lean on code inspection and threat matches.';
  const family =
    data.family_classification && data.family_classification !== 'Unknown'
      ? ` Campaign similarity suggests alignment with the ${data.family_classification} fraud family.`
      : '';
  return `${capability} Although not every capability may have been observed during execution, enough verified evidence exists to classify this application as ${riskBandPlainEnglish(data.risk_band).toLowerCase()}.${family} ${runtimeNote}`;
}

export function buildExecutiveSummaryParagraph(data: FraudCardData): string {
  const behaviours: string[] = [];
  if (data.has_accessibility_abuse) behaviours.push('Accessibility abuse');
  if (data.has_sms_read_write) behaviours.push('SMS permissions');
  if (data.has_system_alert_window) behaviours.push('overlay capability');
  if (data.obfuscation_score && data.obfuscation_score > 0) behaviours.push('runtime code loading patterns');

  const behaviourLine =
    behaviours.length > 0
      ? `Static analysis discovered ${behaviours.join(', ')}.`
      : 'Static analysis completed with mixed permission and code signals.';

  const frs = data.frs_breakdown;
  let dynamicLine = 'Dynamic sandbox execution was not available for this case.';
  if (frs?.dynamic_ran && frs.dynamic_conclusive) {
    dynamicLine =
      'Dynamic execution confirmed suspicious behaviour consistent with credential theft or device control.';
  } else if (frs?.dynamic_ran) {
    dynamicLine =
      'Dynamic execution ran but did not produce conclusive behavioural proof; static and correlation evidence still apply.';
  }

  const appLabel = data.app_name || data.package_name || 'This application';
  const familyLine =
    data.family_classification && data.family_classification !== 'Unknown'
      ? ` Malware family correlation: ${data.family_classification}.`
      : '';

  const action =
    data.final_risk_score >= 20
      ? 'Manual analyst review is recommended before customer impact.'
      : 'Continue monitoring; no immediate customer block is indicated from score alone.';

  return `${appLabel} exhibits multiple behaviours commonly associated with Android banking fraud. ${behaviourLine} ${dynamicLine} Overall Fraud Risk Score is ${data.final_risk_score.toFixed(0)}/100.${familyLine} ${action}`;
}

export function dynamicRuntimeLabel(data: FraudCardData): string {
  const frs = data.frs_breakdown;
  if (!frs?.dynamic_ran) return 'Runtime not executed';
  if (frs.dynamic_conclusive) return 'Runtime Behaviour Confirmed';
  return 'Runtime inconclusive';
}

export function extractAppMetadata(data: FraudCardData): {
  version: string;
  targetSdk: string;
  size: string;
  certSummary: string;
} {
  const cert = data.certificate || {};
  const version =
    String(cert.versionName || cert.version_name || data.apktool_enrichment?.versionName || '-');
  const targetSdk = String(
    cert.targetSdkVersion || cert.target_sdk_version || data.apktool_enrichment?.targetSdkVersion || '-',
  );
  const size = String(cert.file_size || cert.size || '-');
  const subject = cert.subject || cert.certificate_info || cert.issuer;
  const certSummary =
    typeof subject === 'string'
      ? subject
      : subject && typeof subject === 'object'
        ? JSON.stringify(subject).slice(0, 80)
        : cert.signing_algorithm
          ? String(cert.signing_algorithm)
          : 'Available in technical view';
  return { version, targetSdk, size, certSummary };
}

export function countFindingEvidence(
  bundle: InvestigationBundle | null | undefined,
  keywords: string[],
): number {
  if (!bundle) return 0;
  const lower = keywords.map((k) => k.toLowerCase());
  return bundle.evidenceRecords.filter((e) => {
    const hay = `${e.id} ${e.title} ${e.description || ''}`.toLowerCase();
    return lower.some((k) => hay.includes(k));
  }).length;
}

export function securityFindingsTotal(counts: { staticFindings: number; runtimeBehaviors: number }): number {
  return counts.staticFindings + counts.runtimeBehaviors;
}

export function timelineTone(
  ev: { category: string; kind: string; label: string },
  index: number,
  total: number,
): 'completed' | 'active' | 'warning' {
  if (ev.category === 'score' || index === total - 1) return 'active';
  if (ev.label.toLowerCase().includes('inconclusive') || ev.label.toLowerCase().includes('excluded')) {
    return 'warning';
  }
  return 'completed';
}

export function humanizeTimelineLabel(label: string): string {
  const map: Record<string, string> = {
    'Static analysis complete': 'Permissions and manifest reviewed (code inspection)',
  };
  return map[label] || label.replace(/_/g, ' ');
}

export function riskAccentClasses(band: string | null | undefined): string {
  return getRiskStyle(band).text;
}
