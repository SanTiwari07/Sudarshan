import { Info } from 'lucide-react';
import SocCard from '../ui/Card';
import { INTEL } from './intelTokens';

export default function ThreatIntelPageIntro() {
  return (
    <SocCard className="p-5 sm:p-6 border-slate-200 shadow-sm">
      <div className="flex items-start gap-3">
        <span className="p-2 rounded-lg bg-slate-100 text-blue-700 shrink-0">
          <Info className="h-4 w-4" />
        </span>
        <div className="space-y-3 min-w-0">
          <h2 className="text-sm font-semibold text-slate-900">What does this page tell you?</h2>
          <p className={`${INTEL.meta} leading-relaxed max-w-3xl`}>
            Threat Intelligence compares this application&apos;s behaviour against known banking malware and fraud
            campaigns.
          </p>
          <p className={`${INTEL.meta} leading-relaxed max-w-3xl`}>
            Instead of only saying &ldquo;malware detected,&rdquo; Sudarshan explains whether similar attacks have been
            seen before, which banking behaviours match, how confident the evidence is, and what operational action should
            be taken.
          </p>
        </div>
      </div>
    </SocCard>
  );
}
