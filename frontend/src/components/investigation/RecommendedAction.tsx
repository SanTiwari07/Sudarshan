import { useState } from 'react';
import { ShieldCheck, ChevronDown, Check, Copy } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { getDecision } from '../../lib/decision';
import { TYPOGRAPHY } from '../../theme/typography';

/**
 * What the bank should do.
 *
 * There were four competing answers to this question rendering on one page -
 * the engine's `recommended_action`, Gemini's `recommended_actions`, a
 * `riskRecommendedAction()` helper, and a score-threshold cascade inside the
 * executive summary card - and they did not have to agree. They now all resolve
 * through `lib/decision.ts`, so the page states one action.
 *
 * It also surfaces two fields the backend had been producing and the frontend
 * had been dropping on the floor: `customer_advisory_draft` and
 * `cert_in_recommendations`. Both are ready-to-send text with a real
 * operational and regulatory use, and neither had ever been rendered.
 */

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard denied. The text is on screen and selectable, so the reader
      // still has it - failing loudly here would be worse than failing quietly.
    }
  };

  return (
    <div className="rounded-md border border-slate-200 bg-white">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-2 px-3.5 py-2.5 text-left hover:bg-slate-50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
      >
        <span className={TYPOGRAPHY.h3}>{label}</span>
        <ChevronDown
          className={`h-4 w-4 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`}
          aria-hidden
        />
      </button>
      {open && (
        <div className="px-3.5 pb-3.5 space-y-2.5">
          <p className={`${TYPOGRAPHY.bodySmall} whitespace-pre-line max-w-[68ch]`}>{text}</p>
          <button type="button" onClick={copy} className={TYPOGRAPHY.linkAction}>
            {copied ? (
              <>
                <Check className="h-3.5 w-3.5" aria-hidden />
                Copied
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" aria-hidden />
                Copy text
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}

export default function RecommendedAction({ data }: { data: FraudCardData }) {
  const decision = getDecision(data);
  const intel = data.intelligence_report;

  const advisory = intel?.customer_advisory_draft?.trim();
  const certIn = (intel?.cert_in_recommendations ?? []).filter(Boolean);

  return (
    <section id="recommended-action" aria-label="Recommended action" className="space-y-3 scroll-mt-28">
      <h2 className={`${TYPOGRAPHY.h2} flex items-center gap-2`}>
        <ShieldCheck className="h-4 w-4 text-slate-400" aria-hidden />
        Recommended action
      </h2>

      <div className={`rounded-lg border p-5 space-y-4 ${decision.containerClass}`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="font-sans text-xl font-semibold tracking-[-0.02em] text-slate-900">
            {decision.headline}
          </p>
          <span className={`${TYPOGRAPHY.badgePill} ${decision.badgeClass} border-transparent`}>
            {decision.action}
          </span>
        </div>

        <p className={`${TYPOGRAPHY.body} text-slate-900 max-w-[68ch]`}>{decision.rationale}</p>

        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-3 border-t border-slate-900/10">
          <div className="space-y-0.5">
            <dt className={TYPOGRAPHY.label}>Monitoring</dt>
            <dd className={`${TYPOGRAPHY.bodySmall} text-slate-800`}>{decision.monitoring}</dd>
          </div>
          <div className="space-y-0.5">
            <dt className={TYPOGRAPHY.label}>Re-scan condition</dt>
            <dd className={`${TYPOGRAPHY.bodySmall} text-slate-800`}>{decision.rescan}</dd>
          </div>
        </dl>
      </div>

      {/* Ready-to-send text, collapsed. Present because it exists, not because
          every reader needs it. */}
      {(advisory || certIn.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {advisory && <CopyBlock label="Customer advisory draft" text={advisory} />}
          {certIn.length > 0 && (
            <CopyBlock
              label="CERT-In reporting notes"
              text={certIn.map((r) => `• ${r}`).join('\n')}
            />
          )}
        </div>
      )}
    </section>
  );
}
