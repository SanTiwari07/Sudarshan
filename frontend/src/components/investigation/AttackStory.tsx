import { useMemo, useState } from 'react';
import { ChevronDown, ExternalLink, TriangleAlert, SearchX } from 'lucide-react';
import type { FraudCardData } from '../../App';
import type { ScreenshotManifestEntry } from '../../lib/screenshotManifest';
import { buildAttackStory, explainMissingStory, type AttackStage } from '../../lib/attackStory';
import { SEVERITY } from '../../theme/severity';
import { TYPOGRAPHY } from '../../theme/typography';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { screenshotUrl } from '../../lib/screenshots';

/**
 * How the attack works.
 *
 * The signature view of the product, and the thing that separates it from a
 * dashboard: a causal chain where every step is a plain sentence and every
 * sentence has its own evidence one click away.
 *
 * Vertical rather than horizontal, deliberately. A horizontal flow breaks at
 * 375px and forces the sentence - which is the part carrying the meaning - to
 * truncate. The rail is severity-toned so the shape of the attack is legible
 * before any of the words are read.
 *
 * The technical layer is present but subordinate: MITRE IDs and hook names sit
 * inside a per-stage disclosure, so an executive sees five sentences and an
 * engineer is two clicks from `WindowManager.addView`.
 */

function StageRow({
  stage,
  isLast,
  sha256,
}: {
  stage: AttackStage;
  isLast: boolean;
  sha256: string;
}) {
  const { openEvidence, atLeastAnalyst, isForensic } = useInvestigationUI();
  // Forensic readers came for the instrumentation; making them expand five
  // disclosures to reach it is a tax on the person who needs it most. Everyone
  // else gets the sentence and a way in.
  const [open, setOpen] = useState(isForensic);
  const token = SEVERITY[stage.severity];

  return (
    <li className="relative flex gap-4">
      {/* Rail: numbered node plus the connector to the next stage. */}
      <div className="flex flex-col items-center shrink-0">
        <span
          className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-semibold text-white tabular-nums ${token.bar}`}
          aria-hidden
        >
          {stage.index + 1}
        </span>
        {!isLast && <span className="w-px flex-1 bg-slate-200 my-1.5" aria-hidden />}
      </div>

      <div className={`min-w-0 flex-1 ${isLast ? 'pb-0' : 'pb-6'}`}>
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h3 className={TYPOGRAPHY.h3}>{stage.title}</h3>
          <span className={`${TYPOGRAPHY.badge} ${token.fg} ${token.bg} ${token.border}`}>
            {token.label}
          </span>
        </div>

        {/* The sentence. This is the part an executive reads. */}
        <p className={`${TYPOGRAPHY.body} mt-1 max-w-[62ch]`}>{stage.plain}</p>

        {stage.screenshot && (
          <figure className="mt-3">
            <img
              src={screenshotUrl(sha256, stage.screenshot.filename)}
              alt={
                stage.screenshot.investigative_claim ||
                stage.screenshot.label ||
                `Screen captured during ${stage.title}`
              }
              loading="lazy"
              className="max-h-56 w-auto rounded-md border border-slate-200 bg-slate-50"
            />
            <figcaption className={`${TYPOGRAPHY.caption} mt-1.5`}>
              {stage.screenshot.investigative_claim ||
                stage.screenshot.label ||
                'Captured during this stage'}
            </figcaption>
          </figure>
        )}

        <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5">
          {stage.evidenceCount > 0 && (
            <span className={TYPOGRAPHY.label}>
              {stage.evidenceCount} evidence {stage.evidenceCount === 1 ? 'event' : 'events'}
            </span>
          )}
          {atLeastAnalyst && (
            <span className={`${TYPOGRAPHY.label} font-mono`}>{stage.techniqueId}</span>
          )}
          {stage.durationS !== null && (
            <span className={TYPOGRAPHY.label}>{stage.durationS}s</span>
          )}
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className={TYPOGRAPHY.linkAction}
          >
            Technical detail
            <ChevronDown
              className={`h-3.5 w-3.5 transition-transform ${open ? 'rotate-180' : ''}`}
              aria-hidden
            />
          </button>
        </div>

        {/* Everything below here is the analyst/engineer layer. */}
        {open && (
          <div className="mt-3 rounded-md border border-slate-200 bg-slate-50/70 p-3.5 space-y-3">
            <p className={TYPOGRAPHY.bodySmall}>{stage.detail}</p>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
              <a
                href={`https://attack.mitre.org/techniques/${stage.techniqueId.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className={TYPOGRAPHY.linkAction}
              >
                MITRE {stage.techniqueId}
                <ExternalLink className="h-3 w-3" aria-hidden />
              </a>
              <span className={TYPOGRAPHY.label}>
                {Math.round(stage.confidence * 100)}% stage confidence
              </span>
            </div>

            {stage.hookNames.length > 0 && (
              <div className="space-y-1.5">
                <p className={TYPOGRAPHY.label}>Instrumentation that fired</p>
                <div className="flex flex-wrap gap-1.5">
                  {stage.hookNames.map((h) => (
                    <code
                      key={h}
                      className="px-1.5 py-0.5 rounded border border-slate-200 bg-white font-mono text-[13px] text-slate-700"
                    >
                      {h}
                    </code>
                  ))}
                </div>
              </div>
            )}

            {stage.evidenceIds.length > 0 && (
              <div className="space-y-1.5">
                <p className={TYPOGRAPHY.label}>Evidence records</p>
                <div className="flex flex-wrap gap-1.5">
                  {stage.evidenceIds.map((id) => (
                    <button
                      key={id}
                      type="button"
                      onClick={() => openEvidence(id)}
                      className="font-mono text-[12px] px-2 py-0.5 rounded border border-blue-100 bg-blue-50 text-blue-700 hover:bg-blue-100 transition-colors"
                    >
                      {id}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

/**
 * The empty state.
 *
 * Slate when the absence tells us nothing, amber when we looked and found no
 * chain. Never green: "we could not reconstruct an attack" is the expected
 * output for a dormant or evasive sample, and a green tick tells the reader the
 * opposite of what the data supports.
 */
function NoStory({ data }: { data: FraudCardData }) {
  const reason = explainMissingStory(data);
  if (!reason) return null;

  const token = reason.uninformative ? SEVERITY.INCOMPLETE : SEVERITY.SUSPICIOUS;
  const Icon = reason.uninformative ? SearchX : TriangleAlert;

  return (
    <section id="attack-story" aria-label="How the attack works" className="space-y-3 scroll-mt-28">
      <h2 className={TYPOGRAPHY.h2}>How the attack works</h2>
      <div
        className={`flex items-start gap-2.5 rounded-lg border ${token.border} ${token.bg} px-4 py-3.5`}
      >
        <Icon className={`h-4 w-4 shrink-0 mt-0.5 ${token.fg}`} aria-hidden />
        <div className="min-w-0">
          <p className={TYPOGRAPHY.h3}>{reason.headline}</p>
          <p className={`${TYPOGRAPHY.bodySmall} mt-1 max-w-[68ch]`}>{reason.detail}</p>
        </div>
      </div>
    </section>
  );
}

export default function AttackStory({
  data,
  screenshots = [],
}: {
  data: FraudCardData;
  screenshots?: ScreenshotManifestEntry[];
}) {
  const story = useMemo(() => buildAttackStory(data, screenshots), [data, screenshots]);

  if (!story) return <NoStory data={data} />;

  return (
    <section id="attack-story" aria-label="How the attack works" className="space-y-4 scroll-mt-28">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className={TYPOGRAPHY.h2}>How the attack works</h2>
        <p className={TYPOGRAPHY.label}>
          {story.sequenceLabel} &middot; {Math.round(story.chainConfidence * 100)}% chain confidence
        </p>
      </div>

      <p className={`${TYPOGRAPHY.bodySmall} max-w-[68ch]`}>
        Reconstructed deterministically from{' '}
        {story.totalEventsAnalyzed.toLocaleString()} runtime events. Stages are ordered by causal
        precedence, not by timestamp alone.
      </p>

      <ol className="mt-1">
        {story.stages.map((stage, i) => (
          <StageRow
            key={`${stage.title}-${i}`}
            stage={stage}
            isLast={i === story.stages.length - 1}
            sha256={data.sha256}
          />
        ))}
      </ol>
    </section>
  );
}
