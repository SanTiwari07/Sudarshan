import type { FraudCardData } from '../../App';
import { extractAppMetadata } from '../../lib/analystCopy';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
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
    <SocCard>
      <SectionHeader
        icon={<Package className="h-4 w-4" />}
        title="Application Information"
        subtitle="Identity and analysis context for this APK."
      />
      <div className="px-5 py-2 bg-slate-50 border-b border-slate-100">
        <div className="text-sm font-bold text-slate-900 truncate">{displayName}</div>
      </div>
      <div className="px-5 py-3">
        <InfoRow icon={<Box className="h-4 w-4" />} label="Package Name">
          <span className="font-mono">{data.package_name || '—'}</span>
        </InfoRow>
        <InfoRow icon={<Hash className="h-4 w-4" />} label="SHA256" copy={data.sha256}>
          <span className="font-mono">{data.sha256}</span>
        </InfoRow>
        <InfoRow icon={<SlidersHorizontal className="h-4 w-4" />} label="Analysis Mode">
          {data.analysis_mode}
        </InfoRow>
        <InfoRow icon={<Fingerprint className="h-4 w-4" />} label="Malware Family">
          {data.family_classification !== 'Unknown' ? (
            <HelpTerm term="Malware Family">{data.family_classification}</HelpTerm>
          ) : (
            'No family match'
          )}
        </InfoRow>
        <InfoRow icon={<Shield className="h-4 w-4" />} label="Signing Certificate">
          {meta.certSummary}
        </InfoRow>
        <InfoRow icon={<Cpu className="h-4 w-4" />} label="App Version">
          {meta.version}
        </InfoRow>
        <InfoRow icon={<Cpu className="h-4 w-4" />} label="Target SDK">
          {meta.targetSdk}
        </InfoRow>
        <InfoRow icon={<Package className="h-4 w-4" />} label="File Size">
          {meta.size}
        </InfoRow>
        <div className="pt-3 flex flex-wrap gap-2">
          <Badge label={data.analysis_mode} className="bg-blue-50 text-blue-700 border border-blue-200" />
          {data.targets_indian_banks && (
            <Badge label="Banking targets referenced" className="bg-red-50 text-red-700 border border-red-200" />
          )}
        </div>
      </div>
    </SocCard>
  );
}
