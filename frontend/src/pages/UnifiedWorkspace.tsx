import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { ErrorState } from '../components/ui/Skeleton';
import VerdictBlock from '../components/investigation/VerdictBlock';
import CaseSummaryStrip from '../components/investigation/CaseSummaryStrip';
import AttackStory from '../components/investigation/AttackStory';
import VisualImpersonationExecutiveCard from '../components/investigation/VisualImpersonationExecutiveCard';
import InteractiveSandboxPanel from '../components/investigation/InteractiveSandboxPanel';
import { useInvestigationUI } from '../context/InvestigationUIContext';
import { useAnalysis } from '../context/AnalysisContext';
import { useRuntimeScreenshots } from '../hooks/useRuntimeScreenshots';

import type { FraudCardData } from '../App';

export default function UnifiedWorkspace({ data }: { data: FraudCardData | null }) {
  const location = useLocation();
  const { openTechnicalEvidence, openAskAi, closeAllDrawers } = useInvestigationUI();
  const { investigationBundle } = useAnalysis();
  const { entries: screenshotEntries } = useRuntimeScreenshots(data?.sha256);
  
  // Keep drawer in sync if URL changes
  useEffect(() => {
    if (location.pathname.endsWith('/evidence')) {
       openTechnicalEvidence();
    } else if (location.pathname.endsWith('/intel')) {
       // TODO: openIntel(); for now maybe technical evidence or nothing
       openTechnicalEvidence();
    } else if (location.pathname.endsWith('/ask')) {
       openAskAi();
    } else {
       closeAllDrawers();
    }
  }, [location.pathname, openTechnicalEvidence, openAskAi, closeAllDrawers]);

  if (!data) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-50">
        <ErrorState title="Not found" message="No analysis found for this hash." />
      </div>
    );
  }

  const stripCounts =
      investigationBundle && screenshotEntries.length > 0
        ? { ...investigationBundle.counts, screenshots: screenshotEntries.length }
        : investigationBundle?.counts;

  return (
    <div className="flex-1 overflow-auto bg-slate-50">
      <div className="mx-auto max-w-6xl space-y-6 p-6">
        {stripCounts && (
           <CaseSummaryStrip riskScore={data.final_risk_score} counts={stripCounts} />
        )}
          
          <VerdictBlock data={data} />
          
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div className="space-y-6">
              <AttackStory data={data} />
              <InteractiveSandboxPanel data={data} />
            </div>
            
            <div className="space-y-6">
              <VisualImpersonationExecutiveCard data={data} />
            </div>
          </div>
          
          <div className="mt-8 flex justify-center space-x-4 pb-12">
             <button 
                onClick={openTechnicalEvidence}
                className="px-4 py-2 bg-white border border-slate-300 rounded-md shadow-sm text-sm font-medium text-slate-700 hover:bg-slate-50"
             >
                View Technical Evidence
             </button>
             <button 
                onClick={openAskAi}
                className="px-4 py-2 bg-indigo-50 border border-indigo-200 rounded-md shadow-sm text-sm font-medium text-indigo-700 hover:bg-indigo-100"
             >
                Ask Assistant
             </button>
          </div>
      </div>
    </div>
  );
}
