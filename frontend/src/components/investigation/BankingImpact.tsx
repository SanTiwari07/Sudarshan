import { Landmark } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { buildCustomerAndBankingImpact } from '../../lib/executiveIntelligence';
import { TYPOGRAPHY } from '../../theme/typography';
import { SEVERITY, caseSeverity } from '../../theme/severity';
import { isInconclusive } from '../../lib/decision';

/**
 * Who is at risk, and what could happen to them.
 *
 * Lifted out of the executive summary card's section 2, where it rendered as
 * three nested cards inside a card inside a 4-section wall. It answers a
 * question of its own - "who does this hurt" - and a bank manager reads it
 * before they read anything technical, so it gets to be a section.
 *
 * The content is unchanged: `buildCustomerAndBankingImpact` already produced
 * customer impact, banking impact and a business interpretation. Only its
 * placement and its weight on the page are different.
 */
export default function BankingImpact({ data }: { data: FraudCardData }) {
  const impact = buildCustomerAndBankingImpact(data);
  if (!impact.customerImpact && !impact.bankingImpact) return null;

  const inconclusive = isInconclusive(data);
  const token = caseSeverity(data.risk_band, inconclusive);

  const targeted = (data.intelligence_report?.affected_banking_apps ?? []).filter(Boolean);

  return (
    <section aria-label="Banking impact" className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className={`${TYPOGRAPHY.h2} flex items-center gap-2`}>
          <Landmark className="h-4 w-4 text-slate-400" aria-hidden />
          Banking impact
        </h2>
        <span className={`${TYPOGRAPHY.badgePill} ${token.badge} border-transparent`}>
          {inconclusive ? SEVERITY.INCOMPLETE.label : token.label}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="rounded-lg border border-slate-200 bg-white p-4 space-y-1.5">
          <h3 className={TYPOGRAPHY.label}>Who is at risk</h3>
          <p className={TYPOGRAPHY.bodySmall}>{impact.customerImpact}</p>
          {targeted.length > 0 && (
            <p className={`${TYPOGRAPHY.caption} pt-1`}>
              Targeted applications: {targeted.slice(0, 4).join(', ')}
              {targeted.length > 4 && ` and ${targeted.length - 4} more`}
            </p>
          )}
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-4 space-y-1.5">
          <h3 className={TYPOGRAPHY.label}>What could happen</h3>
          <p className={TYPOGRAPHY.bodySmall}>{impact.bankingImpact}</p>
        </div>

        <div className="rounded-lg border border-slate-300 bg-slate-50 p-4 space-y-1.5">
          <h3 className={TYPOGRAPHY.label}>What this means for the bank</h3>
          <p className={`${TYPOGRAPHY.bodySmall} font-medium text-slate-900`}>
            {impact.businessInterpretation}
          </p>
        </div>
      </div>
    </section>
  );
}
