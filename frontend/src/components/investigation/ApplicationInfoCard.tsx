import type { FraudCardData } from '../../App';
import { extractAppMetadata } from '../../lib/analystCopy';
import SocCard from '../ui/Card';
import CopyButton from '../ui/CopyButton';
import Badge from '../ui/Badge';
import HelpTerm from './HelpTerm';
import {
  Box,
  Cpu,
  Fingerprint,
  Hash,
  Package,
  Shield,
  SlidersHorizontal,
} from 'lucide-react';

function InfoRow({
  icon,
  label,
  children,
  copy,
}: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
  copy?: string;
}) {
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-slate-100 last:border-0">
      <span className="text-blue-600 mt-0.5">{icon}</span>
      <div className="flex-1 min-w-0">
        <div className="text-[10px] uppercase tracking-wide font-semibold text-slate-500">{label}</div>
        <div className="text-xs text-slate-800 mt-0.5 break-all">{children}</div>
      </div>
      {copy && <CopyButton value={copy} />}
    </div>
  );
}

export default function ApplicationInfoCard({ data }: { data: FraudCardData }) {
  const meta = extractAppMetadata(data);
  const displayName = data.app_name || data.package_name || 'Unknown application';

  return (
    <SocCard className="border border-slate-200 rounded-md">
      <div className="px-4 py-3 border-b border-slate-200 bg-slate-50 flex items-center gap-2">
        <Package className="h-4 w-4 text-slate-500" />
        <h2 className="text-xs font-bold uppercase tracking-wider text-slate-800 font-mono">Application Information</h2>
      </div>
      <div className="px-4 py-2.5 bg-slate-50/40 border-b border-slate-100">
        <div className="text-xs font-bold text-slate-900 truncate font-mono">{displayName}</div>
      </div>
      <div className="px-4 py-2 divide-y divide-slate-100">
        <InfoRow icon={<Box className="h-3.5 w-3.5" />} label="Package Name">
          <span className="font-mono text-xs">{data.package_name || '-'}</span>
        </InfoRow>
        <InfoRow icon={<Hash className="h-3.5 w-3.5" />} label="SHA256" copy={data.sha256}>
          <span className="font-mono text-xs text-slate-600">{data.sha256}</span>
        </InfoRow>
        <InfoRow icon={<SlidersHorizontal className="h-3.5 w-3.5" />} label="Analysis Mode">
          <span className="font-mono text-xs">{data.analysis_mode}</span>
        </InfoRow>
        <InfoRow icon={<Fingerprint className="h-3.5 w-3.5" />} label="Malware Family">
          <span className="font-mono text-xs">
            {data.family_classification !== 'Unknown' ? (
              <HelpTerm term="Malware Family">{data.family_classification}</HelpTerm>
            ) : (
              'No family match'
            )}
          </span>
        </InfoRow>
        <InfoRow icon={<Shield className="h-3.5 w-3.5" />} label="Signing Certificate">
          <span className="text-xs text-slate-700">{meta.certSummary}</span>
        </InfoRow>
        <InfoRow icon={<Cpu className="h-3.5 w-3.5" />} label="App Version">
          <span className="font-mono text-xs">{meta.version}</span>
        </InfoRow>
        <InfoRow icon={<Cpu className="h-3.5 w-3.5" />} label="Target SDK">
          <span className="font-mono text-xs">{meta.targetSdk}</span>
        </InfoRow>
        <InfoRow icon={<Package className="h-3.5 w-3.5" />} label="File Size">
          <span className="font-mono text-xs">{meta.size}</span>
        </InfoRow>
        <div className="py-3 flex flex-wrap gap-2 border-t-0">
          <Badge label={data.analysis_mode} className="bg-blue-50 text-blue-700 border border-blue-200" />
          {data.targets_indian_banks && (
            <Badge label="Banking targets referenced" className="bg-red-50 text-red-700 border border-red-200" />
          )}
        </div>
      </div>
    </SocCard>
  );
}
