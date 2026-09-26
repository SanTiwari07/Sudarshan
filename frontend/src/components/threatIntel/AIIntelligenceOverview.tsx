import type { ReactNode } from 'react';
import type { FraudCardData } from '../../types/case';
import type { InvestigationBundle } from '../../types/investigation';
import type { AnalystAction, IntelApiPayload } from '../../lib/threatIntelModel';
import {
  buildEvidenceSourceChips,
  buildRecommendedActionBullets,
  buildThreatIntelExecutiveSentences,
  buildWhatWasDiscovered,
  buildWhySudarshanConcluded,
  qualitativeConfidence,
} from '../../lib/threatIntelOverview';
import { SearchX, BadgeCheck, BrainCircuit, ClipboardCheck, ShieldAlert, Sparkles } from 'lucide-react';
import { isInconclusive } from '../../lib/decision';
import SocCard from '../ui/Card';
import { Card, Chip, ProgressBar } from '../ui/primitives';
import { TYPOGRAPHY } from '../../theme/typography';
import InfoTip from '../ui/InfoTip';

function Bullet({ children }: { children: ReactNode }) {
  return (
    <li className="flex gap-2.5">
      <span className="mt-[0.5em] h-1.5 w-1.5 shrink-0 rounded-full bg-blue-600/60" aria-hidden />
      <span className={TYPOGRAPHY.bodySmall}>{children}</span>
    </li>
  );
}

/**
 * A briefing column.
 *
 * These were three bordered, shadowed, hover-lifting cards nested inside an
 * already-bordered card, which puts two frames around every sentence. They are
 * columns of one panel and now read as columns: shared surface, hairline
 * between them, and a literal " - " glyph per line replaced by a real marker.
 */
function InsightColumn({
  icon,
  title,
  items,
  info,
  tone = 'bg-blue-50 text-blue-600',
}: {
  icon: ReactNode;
  title: string;
  items: string[];
  info: string;
  tone?: string;
}) {
  return (
    <Card>
      <div className="mb-4 flex items-center gap-2.5">
        <span className={`flex h-8 w-8 items-center justify-center rounded-lg ${tone}`}>{icon}</span>
        <h3 className="text-[15px] font-semibold text-slate-900">{title}</h3>
        <InfoTip text={info} label={title} />
      </div>
      <ul className="space-y-2">
        {items.map((item) => (
          <Bullet key={item}>{item}</Bullet>
        ))}
      </ul>
    </Card>
  );
}

/*
 * One fact, one card.
 *
 * These were cells divided by hairlines inside a single grey box, so four
 * separate facts - a confidence score, a family name, a runtime verdict and a
 * provenance list - read as one table the eye had to segment before it could
 * use any of them. Given their own surface and a gap between them, each is
 * legible on its own, and the row reflows to however many the case produced
 * rather than holding a fixed four columns.
 */
function SnapshotRow({ label, info, children, className = '' }: { label: string; info: string; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl bg-slate-50 px-4 py-3.5 min-w-0 ${className}`}>
      <dt className="flex items-center gap-1 text-xs font-medium text-slate-500">
        {label}
        <InfoTip text={info} label={label} />
      </dt>
      <dd className="mt-1.5">{children}</dd>
    </div>
  );
}

export default function AIIntelligenceOverview({
  data,
  intel,
  bundle,
  evidenceConfidence,
  actions,
}: {
  data: FraudCardData;
  intel: IntelApiPayload;
  bundle: InvestigationBundle | null;
  evidenceConfidence: number;
  actions: AnalystAction[];
}) {
  const inconclusive = isInconclusive(data);
  const narrative = buildThreatIntelExecutiveSentences(data, intel, bundle, evidenceConfidence).join(' ');
  const discovered = buildWhatWasDiscovered(data, intel);
  const why = buildWhySudarshanConcluded(data, intel, bundle);
  const recommended = buildRecommendedActionBullets(data, intel, actions);
  const chips = buildEvidenceSourceChips(data, intel, bundle).filter((c) => c.active);
  const confLabel = qualitativeConfidence(evidenceConfidence);
  const confPercent = Math.max(0, Math.min(100, Math.round(evidenceConfidence)));
  const frs = data.frs_breakdown;
  const family =
    intel.malware_family && intel.malware_family !== 'Unknown'
      ? intel.malware_family
      : data.family_classification !== 'Unknown'
        ? data.family_classification
        : null;
  const runtimeLabel = frs?.dynamic_conclusive
    ? 'Included in score'
    : frs?.dynamic_ran
      ? 'Inconclusive - excluded'
      : 'Not run';

  return (
    <SocCard rank="primary">
      <header className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3 px-5 pt-5 sm:px-6">
        <div className="flex min-w-0 items-start gap-3">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-blue-600">
            <Sparkles className="h-4 w-4" aria-hidden />
          </span>
          <div className="min-w-0">
            <h2 id="ai-intel-overview-title" className="flex items-center gap-1.5 text-lg font-semibold tracking-[-0.015em] text-slate-900">
              Intelligence overview
              <InfoTip
                label="the intelligence overview"
                text="A briefing on how this app compares to known Android banking threats. The text is written by the AI assistant from verified evidence; it explains the result but never changes the score."
              />
            </h2>
            <p className="mt-0.5 text-sm text-slate-500">How this app compares with known banking threats.</p>
          </div>
        </div>

        {/*
          This badge was unconditional - every case, however inconclusive its
          run, was crowned "Evidence verified" in green. It now reports what
          the analysis actually earned.
        */}
        {inconclusive ? (
          <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-slate-300 bg-white px-3 py-1 text-xs font-semibold text-slate-700">
            <SearchX className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Coverage incomplete
          </span>
        ) : (
          <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-800">
            <BadgeCheck className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Evidence verified
          </span>
        )}
      </header>

      {/*
        Prose beside a snapshot rail left most of a wide console blank: the
        assessment is capped at a readable measure, the rail held ninety
        pixels of tiles, and the rest of the card was white. The snapshot is a
        band across the full width instead - which is how it already read -
        and the briefing runs beneath it as one block of prose. The evidence
        sources join the band; they were a separate footer strip, a third
        place to look for one line of provenance.
      */}
      <section aria-labelledby="ai-intel-overview-title" className="px-5 py-5 sm:px-6">
        <dl
          className={`grid grid-cols-1 gap-3 sm:grid-cols-2 items-start ${
            family ? 'xl:grid-cols-[1fr_1fr_1fr_2fr]' : 'xl:grid-cols-[1fr_1fr_2fr]'
          }`}
        >
          <SnapshotRow
            label="Evidence confidence"
            info="How strongly the collected evidence supports the conclusion, based on how many independent sources agree. It is not the risk score."
          >
            <div className="flex items-baseline gap-1.5">
              <span className="font-sans text-2xl font-semibold leading-none tracking-[-0.03em] text-slate-900 tabular-nums">
                {confPercent}%
              </span>
              <span className={TYPOGRAPHY.caption}>{confLabel}</span>
            </div>
            <ProgressBar
              className="mt-3"
              percent={confPercent}
              label={`Evidence confidence ${confPercent} percent`}
            />
          </SnapshotRow>
          {family && (
            <SnapshotRow label="Malware family" info="The known malware family this app most closely matches, if any. A named family means its code or behaviour lines up with previously seen samples.">
              <span className="text-base font-semibold leading-snug text-slate-900 break-all">{family}</span>
            </SnapshotRow>
          )}
          <SnapshotRow label="Runtime behaviour" info="Whether behaviour seen while the app actually ran in the sandbox was used. 'Not run' means the verdict relies on static and threat-intelligence evidence only.">
            <span className="text-base font-semibold leading-snug text-slate-900">{runtimeLabel}</span>
          </SnapshotRow>
          <SnapshotRow label="Evidence sources" info="Which parts of the pipeline contributed evidence to this briefing.">
            {chips.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {chips.map((chip) => (
                  <Chip key={chip.id} checked>
                    {chip.label}
                  </Chip>
                ))}
              </div>
            ) : (
              <span className={TYPOGRAPHY.caption}>None recorded</span>
            )}
          </SnapshotRow>
        </dl>

        {/*
          One paragraph, not a lead plus balanced columns. The briefing was
          split across two or three newspaper columns to fill the card, but a
          reader has no reason to expect the assessment to continue in a
          second column - it read as three separate findings rather than one
          continuous one. It is a single block of prose again, set a step up
          from body copy because it is the conclusion of the page.
        */}
      </section>

      {/*
        The assessment and its three answers, side by side.

        The briefing ran the full width, and the three answer cards sat in a
        row beneath it - so reading the conclusion and checking what it was
        based on were two separate screens, and the card was roughly twice as
        tall as it needed to be. On a wide console the prose takes a reading
        measure on the left and the three answers stack in a rail on the right,
        which puts the whole assessment in one view.

        It collapses to the old order below xl: at narrower widths a 72ch
        measure plus a rail does not fit, and prose squeezed into half a tablet
        is worse than a taller card.
      */}
      <div className="space-y-4 border-t border-slate-100 p-5 sm:p-6">
        <div className="flex gap-4 rounded-2xl bg-blue-50/50 p-5 ring-1 ring-inset ring-blue-100">
          <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-white text-blue-600 ring-1 ring-blue-100">
            <Sparkles className="h-4 w-4" aria-hidden />
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-slate-900">Assessment</p>
            <p className="mt-1.5 text-[15px] leading-[1.75] text-slate-700 [text-wrap:pretty]">
              {narrative}
            </p>
          </div>
        </div>

        {/*
          Three answers, three cards. Hairline-divided columns inside one
          surface made "what was discovered", "why Sudarshan concluded this"
          and "recommended analyst action" look like three paragraphs of one
          text rather than three separate answers.
        */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3 items-stretch">
          <InsightColumn
            icon={<ShieldAlert className="h-4 w-4" aria-hidden />}
            title="What was discovered"
            items={discovered}
            tone="bg-red-50 text-red-600"
            info="The concrete fraud capabilities and indicators found in this app." 
          />
          <InsightColumn
            icon={<BrainCircuit className="h-4 w-4" aria-hidden />}
            title="Why Sudarshan concluded this"
            items={why}
            tone="bg-violet-50 text-violet-600"
            info="The chain of reasoning from evidence to verdict, so you can check how the conclusion was reached." 
          />
          <InsightColumn
            icon={<ClipboardCheck className="h-4 w-4" aria-hidden />}
            title="Recommended analyst action"
            items={recommended}
            tone="bg-emerald-50 text-emerald-600"
            info="What to do next with this app, based on its risk and the evidence found." 
          />
        </div>
      </div>

    </SocCard>
  );
}
