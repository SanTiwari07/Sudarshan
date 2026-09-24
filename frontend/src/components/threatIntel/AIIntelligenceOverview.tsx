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
import { INTEL } from './intelTokens';

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
function InsightColumn({ icon, title, items }: { icon: ReactNode; title: string; items: string[] }) {
  return (
    <Card>
      <div className="mb-3.5 flex items-center gap-2.5">
        <span className="flex h-7 w-7 items-center justify-center rounded-md border border-slate-200 bg-white text-blue-700">
          {icon}
        </span>
        <h3 className={TYPOGRAPHY.h3}>{title}</h3>
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
function SnapshotRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Card>
      <dt className={INTEL.eyebrow}>{label}</dt>
      <dd className="mt-2">{children}</dd>
    </Card>
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
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3 border-b border-slate-200 bg-slate-50/70 px-5 py-4 sm:px-6">
        <div className="flex min-w-0 items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-blue-100 bg-blue-50 text-blue-700">
            <Sparkles className="h-4 w-4" aria-hidden />
          </span>
          <div className="min-w-0">
            <p className={INTEL.eyebrow}>AI briefing</p>
            <h2 id="ai-intel-overview-title" className={`${TYPOGRAPHY.h2} mt-0.5`}>
              Intelligence overview
            </h2>
            <p className={`${TYPOGRAPHY.caption} mt-1`}>Synthesized from verified pipeline outputs.</p>
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
      <section aria-labelledby="ai-intel-overview-title" className="px-5 py-6 sm:px-6">
        <dl
          className={`grid grid-cols-1 gap-3 sm:grid-cols-2 ${
            family ? 'lg:grid-cols-4' : 'lg:grid-cols-3'
          }`}
        >
          <SnapshotRow label="Evidence confidence">
            <div className="flex items-baseline gap-1.5">
              <span className="font-sans text-[30px] font-medium leading-none tracking-[-0.03em] text-slate-900 tabular-nums">
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
            <SnapshotRow label="Malware family">
              <span className="font-mono text-[15px] leading-snug text-slate-800 break-all">{family}</span>
            </SnapshotRow>
          )}
          <SnapshotRow label="Runtime behaviour">
            <span className="font-sans text-[15px] leading-snug text-slate-700">{runtimeLabel}</span>
          </SnapshotRow>
          <SnapshotRow label="Evidence sources">
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
      <div className="grid grid-cols-1 gap-3 border-t border-slate-200 bg-slate-50/50 p-3 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)] xl:items-start">
        <Card roomy>
          <p className="max-w-[72ch] font-sans text-[17px] font-normal leading-[1.75] tracking-[-0.003em] text-slate-700 [text-wrap:pretty]">
            {narrative}
          </p>
        </Card>

        {/*
          Three answers, three cards. Hairline-divided columns inside one
          surface made "what was discovered", "why Sudarshan concluded this"
          and "recommended analyst action" look like three paragraphs of one
          text rather than three separate answers.
        */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 xl:grid-cols-1">
          <InsightColumn
            icon={<ShieldAlert className="h-4 w-4" aria-hidden />}
            title="What was discovered"
            items={discovered}
          />
          <InsightColumn
            icon={<BrainCircuit className="h-4 w-4" aria-hidden />}
            title="Why Sudarshan concluded this"
            items={why}
          />
          <InsightColumn
            icon={<ClipboardCheck className="h-4 w-4" aria-hidden />}
            title="Recommended analyst action"
            items={recommended}
          />
        </div>
      </div>

    </SocCard>
  );
}
