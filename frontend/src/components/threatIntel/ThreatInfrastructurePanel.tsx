import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { Server } from 'lucide-react';
import CopyButton from '../ui/CopyButton';
import type { InfrastructureSummary } from '../../lib/threatIntelModel';

function ListBlock({ title, items }: { title: string; items: string[] }) {
  if (!items.length) {
    return (
      <div>
        <div className="text-[10px] uppercase text-slate-500 font-semibold">{title}</div>
        <p className="text-xs text-slate-400 mt-1">No infrastructure attribution</p>
      </div>
    );
  }
  return (
    <div>
      <div className="text-[10px] uppercase text-slate-500 font-semibold mb-1">{title} ({items.length})</div>
      <ul className="max-h-28 overflow-y-auto space-y-1">
        {items.slice(0, 12).map((v) => (
          <li key={v} className="font-mono text-[10px] text-slate-800 flex justify-between gap-2">
            <span className="truncate" title={v}>{v}</span>
            <CopyButton value={v} />
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function ThreatInfrastructurePanel({ infra }: { infra: InfrastructureSummary }) {
  const hasGeo = infra.countries.length > 0;

  return (
    <SocCard>
      <SectionHeader icon={<Server className="h-4 w-4" />} title="Threat infrastructure" subtitle="From IOC extraction and correlation" />
      <div className="p-4 grid sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
        <ListBlock title="Domains" items={infra.domains} />
        <ListBlock title="IPs" items={infra.ips} />
        <ListBlock title="URLs" items={infra.urls} />
        <ListBlock title="Certificates" items={infra.certificates} />
        <ListBlock title="Countries" items={infra.countries} />
        <ListBlock title="ASN" items={infra.asns} />
        <ListBlock title="Hosting providers" items={infra.hosting} />
      </div>
      {!hasGeo && (
        <p className="px-4 pb-4 text-[10px] text-slate-500">Map unavailable - no geolocation coordinates in correlated IOC data.</p>
      )}
    </SocCard>
  );
}
