
import type { FraudCardData } from '../../App';

/**
 * Numeric overview for the top of the behaviour section.
 *
 * Before showing raw sandbox tables, say how much there is. "15 URLs
 * contacted, 3 files dropped" is triage information; scrolling three tables to
 * count them is not.
 *
 * Every tile is a real count taken from the data. A tile whose count is zero
 * still renders, because "0 files dropped" is a finding - hiding it would make
 * absence indistinguishable from a section that failed to load.
 */

interface Tile {
  label: string;
  value: number;
  /** Anchor id to scroll to when clicked, if the section exists. */
  anchor?: string;
  emphasis?: boolean;
}

export function buildActivityTiles(data: FraudCardData): Tile[] {
  const dynamic = data.dynamic_analysis as Record<string, any> | undefined;
  const events: any[] =
    dynamic?.runtime_events ?? dynamic?.evidence_records ?? [];
  const networkLogs: any[] = dynamic?.network_logs ?? [];
  const secondary: any[] = dynamic?.secondary_apks ?? [];
  const screenshots: any[] =
    dynamic?.screenshots ?? dynamic?.visual_evidence ?? [];

  const contacted = new Set(
    networkLogs
      .map((l) => String(l?.url ?? l?.host ?? l?.destination ?? ''))
      .filter(Boolean),
  );

  return [
    {
      label: 'Runtime events',
      value: events.length,
      anchor: 'dynamic-analysis',
      emphasis: true,
    },
    { label: 'Endpoints contacted', value: contacted.size, anchor: 'network-capture' },
    {
      label: 'Secondary APKs',
      value: secondary.length,
      anchor: 'secondary-apks',
      emphasis: secondary.length > 0,
    },
    { label: 'Screenshots', value: screenshots.length, anchor: 'screenshots' },
    { label: 'Code findings', value: (data.code_findings ?? []).length },
    { label: 'Manifest findings', value: (data.manifest_findings ?? []).length },
  ];
}

export function ActivitySummary({ data }: { data: FraudCardData }) {
  const tiles = buildActivityTiles(data);

  return (
    <div
      className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2"
      data-testid="activity-summary"
    >
      {tiles.map((tile) => {
        const clickable = Boolean(tile.anchor);
        const body = (
          <>
            <div
              className={[
                'text-2xl font-semibold tabular-nums',
                tile.emphasis && tile.value > 0
                  ? 'text-slate-900'
                  : tile.value === 0
                    ? 'text-slate-300'
                    : 'text-slate-700',
              ].join(' ')}
            >
              {tile.value}
            </div>
            <div className="text-[11px] text-slate-500 leading-tight">
              {tile.label}
            </div>
          </>
        );

        const className = [
          'bg-white border border-slate-200/80 rounded-md px-3 py-2.5 text-left',
          clickable ? 'hover:border-slate-300 hover:bg-slate-50 transition-colors' : '',
        ].join(' ');

        return clickable ? (
          <a key={tile.label} href={`#${tile.anchor}`} className={className}>
            {body}
          </a>
        ) : (
          <div key={tile.label} className={className}>
            {body}
          </div>
        );
      })}
    </div>
  );
}

export default ActivitySummary;
