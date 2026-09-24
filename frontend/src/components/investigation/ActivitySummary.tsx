import { ArrowRight } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import type { InvestigationCounts } from '../../types/investigation';
import { TYPOGRAPHY } from '../../theme/typography';

/**
 * Numeric overview for the top of the evidence view.
 *
 * Before showing raw sandbox tables, say how much there is. "15 URLs
 * contacted, 3 files dropped" is triage information; scrolling three tables to
 * count them is not.
 *
 * Two rules this layout exists to hold:
 *
 * - **A zero is still a finding.** Absence has to stay on the page, or a
 *   section that failed to load reads exactly like a sample that did nothing.
 * - **A zero is not worth a tile.** Six equal boxes, four of them showing a
 *   grey 0, spend most of the screen's width saying nothing and leave the two
 *   real numbers no more prominent than the blanks. The counts that exist get
 *   the tiles; the counts that are zero get named in one line underneath.
 */

interface Tile {
  label: string;
  value: number;
  /** Anchor id to scroll to when clicked, if the section exists. */
  anchor?: string;
}

export function buildActivityTiles(
  data: FraudCardData,
  counts?: InvestigationCounts,
): Tile[] {
  const dynamic = data.dynamic_analysis as Record<string, any> | undefined;
  const networkLogs: any[] = dynamic?.network_logs ?? [];
  const secondary: any[] = dynamic?.secondary_apks ?? [];
  const screenshots: any[] =
    dynamic?.screenshots ?? dynamic?.visual_evidence ?? [];

  /*
   * Runtime events come from the investigation bundle, not from
   * `dynamic_analysis.runtime_events`.
   *
   * The two disagree: the bundle counts evidence records categorised
   * `runtime`, the raw field counts whatever the sandbox happened to write
   * under that key. That produced "Runtime events 0" sitting directly beneath
   * a "Runtime 10" tab badge - the same number, from two sources, eight
   * hundred pixels apart. A reader cannot tell which one is lying, so both
   * stop being worth reading.
   */
  const runtimeEvents =
    counts?.runtimeBehaviors ??
    (dynamic?.runtime_events ?? dynamic?.evidence_records ?? []).length;

  const contacted = new Set(
    networkLogs
      .map((l) => String(l?.url ?? l?.host ?? l?.destination ?? ''))
      .filter(Boolean),
  );

  return [
    { label: 'Runtime events', value: runtimeEvents, anchor: 'dynamic-analysis' },
    { label: 'Endpoints contacted', value: contacted.size, anchor: 'network-capture' },
    { label: 'Secondary APKs', value: secondary.length, anchor: 'secondary-apks' },
    { label: 'Screenshots', value: screenshots.length, anchor: 'screenshots' },
    { label: 'Code findings', value: (data.code_findings ?? []).length, anchor: 'code-findings' },
    {
      label: 'Manifest findings',
      value: (data.manifest_findings ?? []).length,
      anchor: 'manifest-findings',
    },
  ];
}

/** "a, b and c" - a list a non-technical reader can read as a sentence. */
function sentenceList(items: string[]): string {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

/*
 * What each count is, in one line.
 *
 * The number and its noun say how many and of what; they do not say where it
 * came from, and "8 screenshots" means something different if the sandbox took
 * them than if the decompiler found them. One clause each, so a reader who is
 * not an analyst can still tell what they are looking at.
 */
const TILE_CONTEXT: Record<string, string> = {
  'Runtime events': 'Captured while the app ran',
  'Endpoints contacted': 'Distinct hosts seen on the wire',
  'Secondary APKs': 'Payloads dropped or bundled',
  Screenshots: 'Frames captured in the sandbox',
  'Code findings': 'Matches in decompiled source',
  'Manifest findings': 'Declared permissions and components',
};

export function ActivitySummary({
  data,
  counts,
}: {
  data: FraudCardData;
  counts?: InvestigationCounts;
}) {
  const tiles = buildActivityTiles(data, counts);
  const recorded = tiles.filter((t) => t.value > 0);
  const empty = tiles.filter((t) => t.value === 0);

  /*
   * One card per count, not one row holding all of them.
   *
   * These were numerals sharing a single bordered strip, which made the page
   * open on an undifferentiated band of digits - the reader had to parse the
   * whole row before knowing whether any of it mattered. A card each gives
   * every count its own edge, its own label above and its own line of context
   * below, and the grid reflows to whatever the run actually produced instead
   * of holding empty columns for evidence that was never collected.
   */
  return (
    <section
      className="space-y-3"
      data-testid="activity-summary"
      aria-label="What this analysis recorded"
    >
      {recorded.length > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          {recorded.map((tile) => {
            const body = (
              <>
                <span className={`${TYPOGRAPHY.label} block`}>{tile.label}</span>
                <span className="mt-2 block text-[30px] font-semibold leading-none tabular-nums tracking-[-0.03em] text-slate-900">
                  {tile.value}
                </span>
                <span className="mt-2 flex items-center gap-1 text-[13px] leading-tight tracking-[0.01em] text-slate-500">
                  {TILE_CONTEXT[tile.label] ?? 'Recorded during analysis'}
                  {tile.anchor && (
                    <ArrowRight
                      className="h-3 w-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                      aria-hidden
                    />
                  )}
                </span>
              </>
            );

            /*
             * Tiles, not cards.
             *
             * These sit inside the step card that introduces them, so giving
             * them their own border and shadow would be a card inside a card -
             * two competing edges to deliver one number. A tinted fill and the
             * inner radius separate them from the surface they sit on without
             * arguing with it.
             */
            const shell =
              'group block rounded-[var(--tile-radius)] bg-slate-50 p-4 text-left';

            return tile.anchor ? (
              <a
                key={tile.label}
                href={`#${tile.anchor}`}
                className={`${shell} transition-colors duration-150 hover:bg-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500`}
              >
                {body}
              </a>
            ) : (
              <div key={tile.label} className={shell}>
                {body}
              </div>
            );
          })}
        </div>
      )}

      {/*
        What the run did not produce, stated once and quietly. It is a caveat
        on the cards above, not a seventh card - an empty tile competing for
        attention with a real count is how a gap starts reading as a finding.
      */}
      {empty.length > 0 && (
        <p className="rounded-[var(--tile-radius)] bg-slate-50 px-4 py-3 text-[15px] leading-relaxed text-slate-500">
          <span className="font-medium text-slate-600">Nothing recorded for</span>{' '}
          {sentenceList(empty.map((t) => t.label.toLowerCase()))}.
        </p>
      )}
    </section>
  );
}

export default ActivitySummary;
