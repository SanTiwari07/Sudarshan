import type { FraudCardData } from '../App';

/**
 * The single source of truth for "what should the bank do about this app".
 *
 * There were four of these: the engine's `recommended_action`, Gemini's
 * `intelligence_report.recommended_actions`, `riskRecommendedAction()` in
 * analystCopy, and a `getDecisionAction()` living inside the executive summary
 * card. All four could render on one page, and they did not have to agree.
 *
 * The one inside the card was also wrong. It branched on
 * `band === 'critical' | 'high' | 'medium' | 'low'`, but the risk engine's
 * vocabulary is `Critical | High | Suspicious | Safe`. 'suspicious' matched no
 * branch, so it fell through to a score threshold - and a case the engine had
 * floored `Safe -> Suspicious` precisely because it refused to certify it
 * (evasion detected, or no trigger condition ever reached) came out the far end
 * scoring 8 and rendering:
 *
 *     ALLOW - "Minimal risk detected. No significant fraud indicators ... were
 *     observed."
 *
 * That is the exact sentence the platform's own safety model forbids, produced
 * by a band-name typo. So the decision is derived here, from `verdict` first
 * and `risk_band` second, and the score is never consulted for a band the
 * engine has already named.
 */

export type DecisionAction =
  | 'BLOCK'
  | 'ESCALATE'
  | 'REVIEW'
  | 'ALLOW WITH CAUTION'
  | 'ALLOW'
  | 'INCONCLUSIVE';

export type Decision = {
  action: DecisionAction;
  /** Imperative headline for the reader who reads nothing else. */
  headline: string;
  /** One sentence: why this action, in plain English. */
  rationale: string;
  /** What to watch after acting. */
  monitoring: string;
  /** When this case should be looked at again. */
  rescan: string;
  badgeClass: string;
  containerClass: string;
  /**
   * True when the analysis did not earn the right to a conclusion. The UI must
   * not render any positive-affirmation surface (green, "safe", "no threats
   * found") when this is set.
   */
  inconclusive: boolean;
};

/** Did the engine decline to certify this run, for any reason? */
export function isInconclusive(data: FraudCardData): boolean {
  const frs = data.frs_breakdown;
  return Boolean(
    data.verdict === 'INCOMPLETE_EXERCISE' ||
      data.execution_assertions?.incomplete_exercise ||
      frs?.verdict_floored_for_incomplete_exercise ||
      frs?.verdict_floored_for_evasion ||
      frs?.verdict_floored_for_visibility,
  );
}

/**
 * Did the sandbox run and fail to produce a usable answer?
 *
 * Distinct from `isInconclusive`: this is the softer case where the run was
 * simply not conclusive, with no floor applied. It still disqualifies a clean
 * bill of health, because "we looked and could not tell" is not "we looked and
 * it was fine".
 */
function dynamicWasInconclusive(data: FraudCardData): boolean {
  const frs = data.frs_breakdown;
  return Boolean(frs?.dynamic_ran && !frs?.dynamic_conclusive);
}

/** Normalised risk band, using the engine's four-value vocabulary. */
function normalizedBand(data: FraudCardData): 'critical' | 'high' | 'suspicious' | 'safe' | 'unknown' {
  const b = (data.risk_band ?? '').trim().toLowerCase();
  if (b.includes('critical')) return 'critical';
  if (b.includes('high')) return 'high';
  if (b.includes('suspicious')) return 'suspicious';
  if (b.includes('safe')) return 'safe';
  return 'unknown';
}

const STYLE = {
  block: {
    badgeClass: 'bg-red-600 text-white',
    containerClass: 'border-red-300 bg-red-50/80 text-red-950',
  },
  escalate: {
    badgeClass: 'bg-orange-600 text-white',
    containerClass: 'border-orange-300 bg-orange-50/80 text-orange-950',
  },
  review: {
    badgeClass: 'bg-amber-500 text-slate-950',
    containerClass: 'border-amber-300 bg-amber-50/80 text-amber-950',
  },
  caution: {
    badgeClass: 'bg-blue-600 text-white',
    containerClass: 'border-blue-300 bg-blue-50/80 text-blue-950',
  },
  allow: {
    badgeClass: 'bg-emerald-600 text-white',
    containerClass: 'border-emerald-300 bg-emerald-50/80 text-emerald-950',
  },
  /**
   * Slate, deliberately. An inconclusive result is the absence of a conclusion
   * and must not read as either good news or bad news - green would certify a
   * sample nobody examined, red would accuse one nobody examined.
   */
  inconclusive: {
    badgeClass: 'bg-slate-600 text-white',
    containerClass: 'border-slate-300 bg-slate-50 text-slate-900',
  },
} as const;

export function getDecision(data: FraudCardData): Decision {
  const band = normalizedBand(data);
  const score = Math.round(data.final_risk_score ?? 0);
  const engineAction = (data.recommended_action ?? '').trim();

  // ── 1. The analysis did not earn a conclusion ───────────────────────────
  // Checked before the band, because a floored band is a symptom of this and
  // reading the band first would report the symptom as the finding.
  if (isInconclusive(data)) {
    const a = data.execution_assertions;
    const coverage =
      a && a.total_count > 0 ? ` Only ${a.fired_count} of ${a.total_count} trigger conditions were reached.` : '';
    return {
      action: 'INCONCLUSIVE',
      headline: 'INCONCLUSIVE - DO NOT TREAT AS SAFE',
      rationale:
        'The analysis did not exercise all expected behaviour, so the absence of ' +
        'malicious activity is unexplained rather than exonerating.' +
        coverage,
      monitoring:
        'Do not deploy to banking devices on the strength of this run. Treat the sample as unassessed.',
      rescan: 'Re-run with the suggested triggers before drawing any conclusion.',
      ...STYLE.inconclusive,
      inconclusive: true,
    };
  }

  // ── 2. Named bands ──────────────────────────────────────────────────────
  if (band === 'critical' || (band === 'unknown' && score >= 80)) {
    return {
      action: 'BLOCK',
      headline: 'BLOCK AND ISOLATE',
      rationale:
        engineAction ||
        `Critical risk (${score}/100) with verified dangerous capability. Installing this ` +
          'application exposes customers to account takeover and financial fraud.',
      monitoring:
        'Prevent installation on all managed devices and block the associated network indicators.',
      rescan: 'Re-scan immediately if a modified build is submitted.',
      ...STYLE.block,
      inconclusive: false,
    };
  }

  if (band === 'high' || (band === 'unknown' && score >= 60)) {
    return {
      action: 'ESCALATE',
      headline: 'ESCALATE TO SOC AND QUARANTINE',
      rationale:
        engineAction ||
        `High risk (${score}/100) with multiple active threat indicators. Manual analyst ` +
          'review is required before any distribution clearance.',
      monitoring: 'Quarantine the binary and track outbound requests to the associated endpoints.',
      rescan: 'Re-scan when a new build or patch is submitted.',
      ...STYLE.escalate,
      inconclusive: false,
    };
  }

  if (band === 'suspicious' || (band === 'unknown' && score >= 35)) {
    return {
      action: 'REVIEW',
      headline: 'REVIEW BEFORE INSTALLING',
      rationale:
        engineAction ||
        `Potentially harmful behaviour was detected (${score}/100). An analyst should verify ` +
          'the flagged capabilities before this application is cleared.',
      monitoring: 'Track application API usage and inspect background service telemetry.',
      rescan: 'Re-scan on the next version release.',
      ...STYLE.review,
      inconclusive: false,
    };
  }

  // ── 3. Safe, but only as far as the run actually saw ─────────────────────
  // A conclusive-looking low score off an inconclusive sandbox run is still not
  // a clean bill of health, so it never reaches the green branch.
  if (dynamicWasInconclusive(data)) {
    return {
      action: 'ALLOW WITH CAUTION',
      headline: 'NO THREAT OBSERVED - COVERAGE INCOMPLETE',
      rationale:
        `No malicious behaviour was scored (${score}/100), but runtime analysis was ` +
        'not conclusive, so this result describes what was observed rather than what the ' +
        'application can do.',
      monitoring: 'Deploy only under standard security logging and telemetry monitoring.',
      rescan: 'Re-scan with runtime analysis before treating this result as final.',
      ...STYLE.caution,
      inconclusive: false,
    };
  }

  const hasCapability =
    data.has_accessibility_abuse || data.has_sms_read_write || data.has_system_alert_window;

  if (hasCapability || score >= 10) {
    return {
      action: 'ALLOW WITH CAUTION',
      headline: 'MONITOR - APPROVED WITH CAUTION',
      rationale:
        engineAction ||
        `Low aggregate risk (${score}/100), but the application holds capabilities that ` +
          'warrant continued observation.',
      monitoring: 'Approved for deployment under standard security logging.',
      rescan: 'Re-scan on the next version release or if abnormal telemetry is observed.',
      ...STYLE.caution,
      inconclusive: false,
    };
  }

  return {
    action: 'ALLOW',
    headline: 'NO SIGNIFICANT THREAT DETECTED',
    rationale:
      engineAction ||
      `No significant malicious behaviour was identified during the available analysis (${score}/100).`,
    monitoring: 'Maintain routine application security monitoring.',
    rescan: 'Re-scan during scheduled version update cycles.',
    ...STYLE.allow,
    inconclusive: false,
  };
}
