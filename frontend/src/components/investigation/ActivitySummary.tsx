import type { FraudCardData } from '../../App';
import type { InvestigationCounts } from '../../types/investigation';

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

  return (
    <section
      className="rounded-md border border-slate-200 bg-white"
      data-testid="activity-summary"
      aria-label="What this analysis recorded"
    >
      {recorded.length > 0 && (
        /*
         * Left-aligned and intrinsically sized rather than stretched across
         * twelve columns: two numbers spread over full page width is the same
         * emptiness the six-box grid had, just with fewer borders.
         */
        <div className="flex flex-wrap gap-x-10 gap-y-5 px-5 py-4">
          {recorded.map((tile) => {
            const body = (
              <>
                <span className="block text-3xl font-semibold tabular-nums text-slate-900 leading-none">
                  {tile.value}
                </span>
                <span className="mt-1.5 block text-[15px] text-slate-600 leading-tight group-hover:text-slate-900 transition-colors">
                  {tile.label}
                </span>
              </>
            );

            return tile.anchor ? (
              <a
                key={tile.label}
                href={`#${tile.anchor}`}
                className="group min-w-[8rem] rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
              >
                {body}
              </a>
            ) : (
              <div key={tile.label} className="min-w-[8rem]">
                {body}
              </div>
            );
          })}
        </div>
      )}

      {empty.length > 0 && (
        <p
          className={`px-5 text-[15px] leading-relaxed text-slate-500 ${
            recorded.length > 0
              ? 'border-t border-slate-200/70 py-3'
              : 'py-4'
          }`}
        >
          <span className="font-medium text-slate-600">Nothing recorded for</span>{' '}
          {sentenceList(empty.map((t) => t.label.toLowerCase()))}.
        </p>
      )}
    </section>
  );
}

export default ActivitySummary;
