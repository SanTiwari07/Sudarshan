import { Network } from 'lucide-react';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL_THEME } from './intelTokens';

const NODES = [
  { id: 'apk', label: 'APK' },
  { id: 'cert', label: 'Certificate' },
  { id: 'package', label: 'Package' },
  { id: 'domains', label: 'Domains' },
  { id: 'ips', label: 'IPs' },
  { id: 'urls', label: 'URLs' },
  { id: 'campaign', label: 'Campaign' },
  { id: 'family', label: 'Family' },
  { id: 'mitre', label: 'MITRE' },
];

type Props = {
  activeNode: string | null;
  onSelect: (id: string) => void;
  family: string;
  campaign: string;
};

export default function IocRelationshipGraph({ activeNode, onSelect, family, campaign }: Props) {
  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Network className="h-4 w-4" />}
        title="IOC relationship graph"
        subtitle="Filter the registry by entity type"
      />
      <IntelCardBody compact>
        <div className="flex flex-wrap gap-2">
          {NODES.map((node) => {
            const active = activeNode === node.id;
            const sub =
              node.id === 'family' && family !== 'Unknown'
                ? family
                : node.id === 'campaign'
                  ? campaign
                  : undefined;
            return (
              <button
                key={node.id}
                type="button"
                onClick={() => onSelect(node.id)}
                className={`px-3 py-2 rounded-lg border text-left text-xs font-semibold transition-all duration-200 min-w-[5.5rem] ${
                  active
                    ? `${INTEL_THEME.observed}`
                    : 'bg-white text-slate-700 border-slate-200 hover:border-blue-300 hover:bg-blue-50'
                }`}
              >
                {node.label}
                {sub && (
                  <span className={`block text-[10px] font-normal mt-0.5 truncate max-w-[8rem] ${active ? 'text-blue-100' : 'text-slate-500'}`}>
                    {sub}
                  </span>
                )}
              </button>
            );
          })}
          <button
            type="button"
            onClick={() => onSelect('all')}
            className="px-3 py-2 rounded-lg border border-dashed border-slate-300 text-xs text-slate-600 hover:bg-slate-50"
          >
            Clear filter
          </button>
        </div>
      </IntelCardBody>
    </IntelCard>
  );
}
