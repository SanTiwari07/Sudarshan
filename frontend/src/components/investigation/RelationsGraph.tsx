import { useMemo } from 'react';
import SocCard from '../ui/Card';
import type { FraudCardData } from '../../App';

/**
 * Blast-radius graph: the sample at the centre, everything it touches around it.
 *
 * The IOCs were already on the page, spread across three tables (hardcoded
 * URLs, resolved domains, runtime network logs). Reading them meant holding
 * three lists in your head to see that one domain appeared in all three.
 *
 * Drawn as inline SVG on purpose. A graph library would be a new runtime
 * dependency and a bundle cost for one panel, and the layout here is a single
 * ring - it does not need a force simulation to be readable.
 */

type NodeKind = 'domain' | 'ip' | 'apk' | 'url';

interface RelNode {
  id: string;
  label: string;
  kind: NodeKind;
  /** True when the runtime observed it, not just static extraction. */
  observed: boolean;
}

const KIND_COLOR: Record<NodeKind, string> = {
  domain: '#0284c7',
  ip: '#c2410c',
  apk: '#b91c1c',
  url: '#7c3aed',
};

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function classify(value: string): NodeKind {
  if (value.toLowerCase().endsWith('.apk')) return 'apk';
  if (IP_RE.test(value)) return 'ip';
  if (value.startsWith('http://') || value.startsWith('https://')) return 'url';
  return 'domain';
}

/** Trim a URL to its host so the ring stays readable. */
function shorten(value: string): string {
  let out = value.replace(/^https?:\/\//, '').split('/')[0] || value;
  if (out.length > 28) out = `${out.slice(0, 26)}…`;
  return out;
}

export function buildRelationNodes(data: FraudCardData, limit = 18): {
  nodes: RelNode[];
  total: number;
} {
  const dynamic = data.dynamic_analysis as Record<string, any> | undefined;

  const observedValues = new Set<string>();
  for (const log of (dynamic?.network_logs ?? []) as any[]) {
    const raw = log?.url ?? log?.host ?? log?.destination ?? log?.ioc;
    if (typeof raw === 'string' && raw.trim()) observedValues.add(raw.trim());
  }

  const staticValues = new Set<string>();
  for (const value of data.hardcoded_urls_ips ?? []) {
    if (typeof value === 'string' && value.trim()) staticValues.add(value.trim());
  }
  for (const key of Object.keys(data.domains ?? {})) {
    if (key.trim()) staticValues.add(key.trim());
  }
  for (const apk of (dynamic?.secondary_apks ?? []) as any[]) {
    const name = apk?.filename ?? apk?.device_path;
    if (typeof name === 'string' && name.trim()) observedValues.add(name.trim());
  }

  const byLabel = new Map<string, RelNode>();
  const push = (value: string, observed: boolean) => {
    const label = shorten(value);
    const existing = byLabel.get(label);
    if (existing) {
      // Seen statically AND at runtime - runtime is the stronger claim.
      if (observed) existing.observed = true;
      return;
    }
    byLabel.set(label, {
      id: `${label}-${byLabel.size}`,
      label,
      kind: classify(value),
      observed,
    });
  };

  observedValues.forEach((v) => push(v, true));
  staticValues.forEach((v) => push(v, false));

  const all = Array.from(byLabel.values());
  // Observed first: if the ring is truncated, keep what actually happened.
  all.sort((a, b) => Number(b.observed) - Number(a.observed));
  return { nodes: all.slice(0, limit), total: all.length };
}

export function RelationsGraph({ data }: { data: FraudCardData }) {
  const { nodes, total } = useMemo(() => buildRelationNodes(data), [data]);

  if (nodes.length === 0) {
    return (
      <SocCard severity="info">
        <div className="px-4 py-3 border-b border-slate-100">
          <h3 className="text-sm font-semibold text-slate-800">Relations</h3>
        </div>
        <div className="px-4 py-6 text-sm text-slate-500">
          No network indicators or dropped files were extracted for this sample.
        </div>
      </SocCard>
    );
  }

  const W = 720;
  const H = 420;
  const cx = W / 2;
  const cy = H / 2;
  const radius = Math.min(W, H) / 2 - 74;
  const observedCount = nodes.filter((n) => n.observed).length;

  return (
    <SocCard severity={observedCount > 0 ? 'high' : 'info'}>
      <div className="px-4 py-3 border-b border-slate-100 flex items-baseline justify-between">
        <h3 className="text-sm font-semibold text-slate-800">
          Relations &mdash; blast radius
        </h3>
        <span className="text-xs text-slate-500">
          {total} indicator{total === 1 ? '' : 's'}
          {total > nodes.length && ` (showing ${nodes.length})`}
        </span>
      </div>

      <div className="px-2 py-2 overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="w-full h-auto min-w-[560px]"
          role="img"
          aria-label={`Relationship graph: ${total} indicators connected to the sample`}
        >
          {nodes.map((node, i) => {
            const angle = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
            const x = cx + Math.cos(angle) * radius;
            const y = cy + Math.sin(angle) * radius;
            const anchor = x < cx - 8 ? 'end' : x > cx + 8 ? 'start' : 'middle';
            const labelX = x + (anchor === 'end' ? -10 : anchor === 'start' ? 10 : 0);
            return (
              <g key={node.id}>
                <line
                  x1={cx}
                  y1={cy}
                  x2={x}
                  y2={y}
                  stroke={node.observed ? '#94a3b8' : '#e2e8f0'}
                  strokeWidth={node.observed ? 1.5 : 1}
                  strokeDasharray={node.observed ? undefined : '3 3'}
                />
                <circle
                  cx={x}
                  cy={y}
                  r={node.observed ? 6 : 4.5}
                  fill={node.observed ? KIND_COLOR[node.kind] : '#fff'}
                  stroke={KIND_COLOR[node.kind]}
                  strokeWidth={1.5}
                />
                <text
                  x={labelX}
                  y={y + 3.5}
                  textAnchor={anchor}
                  className="text-[13px]"
                  fill="#475569"
                  fontFamily="ui-monospace, monospace"
                >
                  {node.label}
                </text>
              </g>
            );
          })}

          <circle cx={cx} cy={cy} r={34} fill="#0f172a" />
          <text
            x={cx}
            y={cy + 4}
            textAnchor="middle"
            fill="#fff"
            className="text-[13px]"
            fontFamily="ui-monospace, monospace"
          >
            APK
          </text>
        </svg>
      </div>

      <div className="px-4 py-2 border-t border-slate-100 flex flex-wrap gap-4 text-[13px] text-slate-500">
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-slate-700" />
          observed at runtime ({observedCount})
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2.5 h-2.5 rounded-full border border-slate-400 bg-white" />
          extracted statically &mdash; not seen contacted
        </span>
      </div>
    </SocCard>
  );
}

export default RelationsGraph;
