import type { FraudCardData } from '../../App';
import {
  buildOverallAssessmentParagraphs,
  buildCustomerAndBankingImpact,
  buildDetailedRiskFactors,
} from '../../lib/executiveIntelligence';
import { riskRecommendedAction } from '../../lib/analystCopy';
import { TYPOGRAPHY } from '../../theme/typography';
import { Sparkles, AlertTriangle, FileText, Info, ShieldCheck } from 'lucide-react';

export type DecisionAction = 'BLOCK' | 'ESCALATE' | 'REVIEW' | 'ALLOW WITH CAUTION' | 'ALLOW';

export function getDecisionAction(data: FraudCardData): {
  action: DecisionAction;
  badgeClass: string;
  containerClass: string;
  explanation: string;
} {
  const score = Math.round(data.final_risk_score);
  const band = (data.risk_band ?? '').toLowerCase();
  const explanation = data.recommended_action || riskRecommendedAction(data);

  if (band === 'critical' || score >= 80) {
    return {
      action: 'BLOCK',
      badgeClass: 'bg-red-600 text-white font-bold',
      containerClass: 'border-red-300 bg-red-50/90 text-red-950',
      explanation,
    };
  }
  if (band === 'high' || score >= 60) {
    return {
      action: 'ESCALATE',
      badgeClass: 'bg-orange-600 text-white font-bold',
      containerClass: 'border-orange-300 bg-orange-50/90 text-orange-950',
      explanation,
    };
  }
  if (band === 'medium' || score >= 35) {
    return {
      action: 'REVIEW',
      badgeClass: 'bg-amber-500 text-slate-950 font-bold',
      containerClass: 'border-amber-300 bg-amber-50/90 text-amber-950',
      explanation,
    };
  }
  if (band === 'low' || score >= 10) {
    return {
      action: 'ALLOW WITH CAUTION',
      badgeClass: 'bg-blue-600 text-white font-bold',
      containerClass: 'border-blue-300 bg-blue-50/90 text-blue-950',
      explanation,
    };
  }
  return {
    action: 'ALLOW',
    badgeClass: 'bg-emerald-600 text-white font-bold',
    containerClass: 'border-emerald-300 bg-emerald-50/90 text-emerald-950',
    explanation,
  };
}

export default function AiSummaryCard({ data }: { data: FraudCardData }) {
  const assessmentParagraphs = buildOverallAssessmentParagraphs(data);
  const impact = buildCustomerAndBankingImpact(data);
  const riskFactors = buildDetailedRiskFactors(data);
  const decision = getDecisionAction(data);

  const score = Math.round(data.final_risk_score);
  const band = (data.risk_band ?? '').toLowerCase();

  const capsBrief: string[] = [];
  if (data.has_accessibility_abuse) capsBrief.push('accessibility service usage');
  if (data.has_sms_read_write) capsBrief.push('SMS/OTP access');
  if (data.has_system_alert_window) capsBrief.push('overlay window capability');
  const briefText = capsBrief.length > 0 ? capsBrief.join(' and ') : 'observed capability flags';

  let recExplanation = '';
  let recDetails = { action: '', why: '', monitoring: '', rescan: '' };

  if (band === 'critical' || score >= 80) {
    recExplanation = `BLOCK IMMEDIATELY — Critical overall risk score (${score}/100) with verified dangerous capabilities. Deploying this application exposes customers to account takeover and financial fraud. Prevent installation, isolate affected endpoints, and submit IOCs to security teams. Re-scan immediately if a modified APK build is submitted.`;
    recDetails = {
      action: 'BLOCK IMMEDIATELY',
      why: `Critical risk score (${score}/100) and verified threat capabilities (${briefText}) pose an active danger to user accounts.`,
      monitoring: 'Prevent device deployment, block associated network indicators, and log access attempts.',
      rescan: 'Re-scan immediately upon receipt of any updated or remediated binary package.',
    };
  } else if (band === 'high' || score >= 60) {
    recExplanation = `ESCALATE TO SOC — High fraud risk score (${score}/100) with multiple active risk signals. Quarantining the application and assigning a security analyst for manual review is required prior to any distribution clearance. Maintain close endpoint monitoring and re-scan immediately upon receiving updated binaries.`;
    recDetails = {
      action: 'ESCALATE TO SOC & QUARANTINE',
      why: `High risk score (${score}/100) with multiple threat indicators warrants manual analyst evaluation.`,
      monitoring: 'Quarantine application binary and track outgoing network requests to associated endpoints.',
      rescan: 'Re-scan immediately when new build versions or patches are submitted.',
    };
  } else if (band === 'medium' || score >= 35) {
    recExplanation = `REVIEW REQUIRED — Moderate risk score (${score}/100) featuring specific suspicious capabilities (${briefText}). Pending analyst verification of accessibility and permission usage before clearing. Recommended to monitor API endpoint activity and re-scan on next version release.`;
    recDetails = {
      action: 'FLAG FOR MANUAL SECURITY REVIEW',
      why: `Moderate risk score (${score}/100) with specific capability flags requires human validation of business intent.`,
      monitoring: 'Track application API usage and inspect background service telemetry.',
      rescan: 'Re-scan on the next application version release.',
    };
  } else if (band === 'low' || score >= 10) {
    recExplanation = `MONITOR — Low current aggregate risk (${score}/100), but specific capabilities (${briefText}) require continued observation. Approved for deployment under standard monitoring controls. Re-scan on the next application version release or if new runtime behavior is observed.`;
    recDetails = {
      action: 'MONITOR (APPROVED WITH CAUTION)',
      why: `Low aggregate risk score (${score}/100), but specific technical capabilities (${briefText}) necessitate continued observation.`,
      monitoring: 'Approved for deployment under standard security logging and telemetry monitoring.',
      rescan: 'Re-scan on the next application version release or if abnormal runtime telemetry is detected.',
    };
  } else {
    recExplanation = `ALLOW — Minimal risk detected (${score}/100). No significant fraud indicators or threat intelligence matches were observed. Approved for routine deployment under standard security policy. Re-scan periodically during routine version updates.`;
    recDetails = {
      action: 'ALLOW FOR DEPLOYMENT',
      why: `Minimal risk detected (${score}/100) with clean threat intelligence and no malicious capabilities.`,
      monitoring: 'Maintain standard routine application performance and security monitoring.',
      rescan: 'Re-scan during routine scheduled version update cycles.',
    };
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6 shadow-xs space-y-5 sm:space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <div className="flex items-center gap-3">
          <span className="p-2.5 rounded-lg bg-blue-100 text-blue-700 shrink-0">
            <Sparkles className="h-5 w-5 sm:h-6 sm:w-6" />
          </span>
          <div>
            <h3 className={TYPOGRAPHY.cardTitle}>
              EXECUTIVE ASSESSMENT & FRAUD SUMMARY
            </h3>
            <p className={`${TYPOGRAPHY.caption} mt-0.5`}>
              Decision-useful security intelligence for banking leadership and fraud analysts
            </p>
          </div>
        </div>
      </div>

      {/* Grid of Sections */}
      <div className="space-y-5 sm:space-y-6">
        {/* 1. OVERALL ASSESSMENT */}
        <div>
          <p className={`${TYPOGRAPHY.sectionTitle} mb-2`}>
            <FileText className="h-4 w-4 text-blue-600" />
            1. OVERALL ASSESSMENT
          </p>
          <div className="rounded-lg border border-slate-200/90 bg-white p-4 space-y-3">
            {assessmentParagraphs.map((para, idx) => (
              <p key={idx} className={TYPOGRAPHY.body}>
                {para}
              </p>
            ))}
          </div>
        </div>

        {/* 2. CUSTOMER & BANKING IMPACT */}
        <div>
          <p className={`${TYPOGRAPHY.sectionTitle} mb-2`}>
            <AlertTriangle className="h-4 w-4 text-amber-600" />
            2. CUSTOMER & BANKING IMPACT
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Customer Impact Card */}
            <div className="rounded-lg border border-slate-200/90 bg-white p-3.5 space-y-1.5 flex flex-col justify-between">
              <div>
                <span className={`${TYPOGRAPHY.label} text-amber-800 block mb-1`}>
                  Customer Impact
                </span>
                <p className={TYPOGRAPHY.bodySmall}>
                  {impact.customerImpact}
                </p>
              </div>
            </div>

            {/* Banking Impact Card */}
            <div className="rounded-lg border border-slate-200/90 bg-white p-3.5 space-y-1.5 flex flex-col justify-between">
              <div>
                <span className={`${TYPOGRAPHY.label} text-blue-800 block mb-1`}>
                  Banking Impact
                </span>
                <p className={TYPOGRAPHY.bodySmall}>
                  {impact.bankingImpact}
                </p>
              </div>
            </div>

            {/* Business Interpretation Card */}
            <div className="rounded-lg border border-blue-200/80 bg-blue-50/60 p-3.5 space-y-1.5 flex flex-col justify-between">
              <div>
                <span className={`${TYPOGRAPHY.label} text-blue-900 block mb-1`}>
                  Business Interpretation
                </span>
                <p className={`${TYPOGRAPHY.bodySmall} font-semibold text-slate-900`}>
                  {impact.businessInterpretation}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* 3. WHY THIS SCORE? (KEY RISK FACTORS) */}
        <div>
          <p className={`${TYPOGRAPHY.sectionTitle} mb-2`}>
            <Info className="h-4 w-4 text-indigo-600" />
            3. WHY THIS SCORE? (KEY RISK FACTORS)
          </p>

          {riskFactors.length > 0 ? (
            <div className="space-y-3">
              {riskFactors.map((factor) => (
                <div
                  key={factor.id}
                  className="rounded-lg border border-slate-200/90 bg-white p-3.5 space-y-2 hover:border-slate-300 transition-colors"
                >
                  {/* Header & Badge */}
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/80 pb-2">
                    <span className={`${TYPOGRAPHY.h3} flex items-center gap-1.5`}>
                      <span className="h-2 w-2 rounded-full bg-blue-600" />
                      {factor.name}
                    </span>
                    {factor.badge && (
                      <span className={`${TYPOGRAPHY.badge} bg-slate-200/80 text-slate-800 border-slate-300`}>
                        {factor.badge}
                      </span>
                    )}
                  </div>

                  {/* 4-part breakdown */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-0.5">
                    <div className="bg-white/80 p-2.5 rounded border border-slate-200/60">
                      <strong className={`${TYPOGRAPHY.label} block mb-0.5`}>
                        What was detected
                      </strong>
                      <span className={`${TYPOGRAPHY.bodySmall} block`}>{factor.detected}</span>
                    </div>

                    <div className="bg-white/80 p-2.5 rounded border border-slate-200/60">
                      <strong className={`${TYPOGRAPHY.label} block mb-0.5`}>
                        Capability Enabled
                      </strong>
                      <span className={`${TYPOGRAPHY.bodySmall} block`}>{factor.capability}</span>
                    </div>

                    <div className="bg-white/80 p-2.5 rounded border border-slate-200/60">
                      <strong className={`${TYPOGRAPHY.label} block mb-0.5`}>
                        Why it matters
                      </strong>
                      <span className={`${TYPOGRAPHY.bodySmall} block`}>{factor.whyItMatters}</span>
                    </div>

                    <div className="bg-blue-50/50 p-2.5 rounded border border-blue-200/60">
                      <strong className={`${TYPOGRAPHY.label} text-blue-700 block mb-0.5`}>
                        Supporting Evidence
                      </strong>
                      <span className={`${TYPOGRAPHY.bodySmall} font-medium text-slate-800 block`}>{factor.evidence}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className={`${TYPOGRAPHY.body} bg-white p-4 rounded-lg border border-slate-200/80`}>
              This score reflects multi-axis evaluation across static manifest indicators, behavioral code analysis, and global threat intelligence correlation. No individual critical risk triggers were isolated.
            </p>
          )}
        </div>

        {/* 4. RECOMMENDED ACTION */}
        <div className={`rounded-xl border p-4 sm:p-5 ${decision.containerClass}`}>
          <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
            <span className={`${TYPOGRAPHY.sectionTitle} text-slate-900`}>
              <ShieldCheck className="h-4 w-4" />
              RECOMMENDED ACTION
            </span>
            <span className={`${TYPOGRAPHY.badgePill} ${decision.badgeClass}`}>
              {decision.action}
            </span>
          </div>

          <p className={`${TYPOGRAPHY.body} font-bold text-slate-900 mb-3`}>
            {recExplanation}
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-2 border-t border-slate-300/60">
            <div>
              <span className={`${TYPOGRAPHY.label} text-slate-600 block`}>Recommended Action</span>
              <span className={`${TYPOGRAPHY.bodySmall} font-bold text-slate-900`}>{recDetails.action}</span>
            </div>

            <div>
              <span className={`${TYPOGRAPHY.label} text-slate-600 block`}>Rationale</span>
              <span className={`${TYPOGRAPHY.bodySmall} text-slate-800`}>{recDetails.why}</span>
            </div>

            <div>
              <span className={`${TYPOGRAPHY.label} text-slate-600 block`}>Monitoring Required</span>
              <span className={`${TYPOGRAPHY.bodySmall} text-slate-800`}>{recDetails.monitoring}</span>
            </div>

            <div>
              <span className={`${TYPOGRAPHY.label} text-slate-600 block`}>Re-Scan Condition</span>
              <span className={`${TYPOGRAPHY.bodySmall} text-slate-800`}>{recDetails.rescan}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

