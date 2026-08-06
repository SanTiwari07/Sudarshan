import { INTEL } from './intelTokens';

export default function ThreatIntelPageShell({ children }: { children: React.ReactNode }) {
  return (
    <div className={`w-full min-w-0 ${INTEL.sectionGap} pb-10`}>
      {children}
    </div>
  );
}
