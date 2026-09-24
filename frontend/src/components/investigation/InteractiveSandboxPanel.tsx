import { ShieldAlert } from 'lucide-react';
import type { FraudCardData } from '../../App';
import ResiliencePanel from './ResiliencePanel';


export default function InteractiveSandboxPanel({ data }: { data: FraudCardData }) {
  return (
    <div className="border rounded-xl overflow-hidden bg-white border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
      <div className="border-b border-slate-200 bg-amber-50/50 px-5 py-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-amber-600" />
          <h3 className="font-semibold text-slate-900 text-sm">Sandbox Interventions</h3>
        </div>
      </div>
      <div className="p-4">
        <p className="text-sm text-slate-600 mb-4">
          The analysis engine may have been evaded. Use these manual interventions to trigger latent behavior in the secure sandbox.
        </p>
        <ResiliencePanel 
          sessionId={data.sha256}
          packageName={data.package_name}
          antiEvasion={data.dynamic_analysis?.anti_evasion}
        />
      </div>
    </div>
  );
}
