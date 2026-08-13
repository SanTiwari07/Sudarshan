import { useState } from 'react';
import { AlertTriangle, Loader2 } from 'lucide-react';
import { SocCard } from '../ui/Card';
import UrlDiscoveryArea from '../discovery/UrlDiscoveryArea';
import UploadDropZone from './UploadDropZone';
import StageCard from './StageCard';
import InvestigationProgress from './progress/InvestigationProgress';
import CompletionScreen from './progress/CompletionScreen';
import { useAnalysisSession } from './useAnalysisSession';
import type { FraudCardData } from '../../App';
import { getToken } from '../../pages/Login';
import { TYPOGRAPHY } from '../../theme/typography';

type UploadPageProps = {
  onAnalysisComplete: (data: FraudCardData) => void;
};

const PIPELINE_OVERVIEW = [
  { title: 'Static Intelligence', description: 'Manifest, MobSF, certificates, and code findings', icon: 'static' as const },
  { title: 'Dynamic Intelligence', description: 'Emulator sandbox with Frida runtime hooks', icon: 'dynamic' as const },
  { title: 'Threat Correlation', description: 'VT, OTX, and banking fraud family mapping', icon: 'threat' as const },
  { title: 'Risk Engine', description: 'STEI, BFCI, and FRS deterministic scoring', icon: 'risk' as const },
  { title: 'AI Investigation', description: 'Executive narrative and SOC recommendations', icon: 'ai' as const },
  { title: 'Report Generation', description: 'Fraud card, technical view, and export artifacts', icon: 'report' as const },
];

export default function UploadPage({ onAnalysisComplete }: UploadPageProps) {
  const [mode, setMode] = useState<'apk' | 'url'>('apk');
  const session = useAnalysisSession(onAnalysisComplete);
  const { phase, file, setFile, error, smoothProgress, result, pipelineUi, isBusy, startAnalysis, reset } =
    session;

  if (phase === 'complete' && result) {
    return <CompletionScreen fileName={file?.name ?? result.app_name ?? 'APK'} />;
  }

  if (phase === 'uploading' || phase === 'analyzing' || (phase === 'error' && file)) {
    return (
      <InvestigationProgress
        fileName={file?.name ?? 'APK'}
        progress={smoothProgress}
        error={phase === 'error' ? error : null}
        onRetry={phase === 'error' ? reset : undefined}
        stageTitle={pipelineUi?.title}
        stageDescription={pipelineUi?.description}
      />
    );
  }

  return (
    <div className="upload-fade-in flex justify-center px-4 py-10 sm:py-16">
      <div className="w-full max-w-[68rem]">
        <SocCard className="p-8 sm:p-10 lg:p-12 border-slate-200/80 shadow-sm">
          <div className="flex border-b border-slate-200 mb-6 overflow-x-auto scrollbar-hide">
            <button
              onClick={() => setMode('apk')}
              className={`px-6 py-3 ${TYPOGRAPHY.button} border-b-2 transition-colors ${
                mode === 'apk'
                  ? 'border-blue-600 text-blue-700 bg-blue-50'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
              }`}
            >
              Upload APK
            </button>
            <button
              onClick={() => setMode('url')}
              className={`px-6 py-3 ${TYPOGRAPHY.button} border-b-2 transition-colors ${
                mode === 'url'
                  ? 'border-blue-600 text-blue-700 bg-blue-50'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
              }`}
            >
              Website URL
            </button>
          </div>

          {mode === 'apk' ? (
            <UploadDropZone
              file={file}
              onFile={setFile}
              disabled={isBusy}
              disabledMessage={isBusy ? 'Analysis in progress. Please wait.' : undefined}
            />
          ) : (
            <UrlDiscoveryArea 
              disabled={isBusy}
              onAnalyzeCandidate={async (candidateId, sessionId, filename) => {
                try {
                  const token = import.meta.env.VITE_DEV_TOKEN || getToken();
                  const res = await fetch(`${import.meta.env.VITE_API_BASE || 'http://localhost:8000/api/v1'}/discovery/${sessionId}/analyze`, {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      ...(token ? { Authorization: `Bearer ${token}` } : {})
                    },
                    body: JSON.stringify({ candidate_id: candidateId })
                  });
                  if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || 'Failed to queue analysis');
                  }
                  const data = await res.json();
                  session.startAnalysisFromJob(data.job_id, filename);
                } catch (e: any) {
                  alert(e.message);
                }
              }}
            />
          )}

          <section className="mt-12" aria-labelledby="pipeline-overview-heading">
            <h2
              id="pipeline-overview-heading"
              className={TYPOGRAPHY.h2}
            >
              Pipeline overview
            </h2>
            <p className={`${TYPOGRAPHY.bodySmall} mt-1 mb-6`}>
              Stages executed automatically after you submit an APK.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {PIPELINE_OVERVIEW.map((p) => (
                <StageCard
                  key={p.title}
                  title={p.title}
                  description={p.description}
                  icon={p.icon}
                  overview
                />
              ))}
            </div>
          </section>

          {error && (
            <div className="mt-8 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-red-800">
              <AlertTriangle className="h-5 w-5 shrink-0" aria-hidden />
              <p className={TYPOGRAPHY.bodySmall}>{error}</p>
            </div>
          )}

          {mode === 'apk' && (
            <button
              type="button"
              disabled={!file || isBusy}
              onClick={() => void startAnalysis()}
              className={`mt-10 w-full h-14 flex justify-center items-center gap-2 rounded-[13px] ${TYPOGRAPHY.button} text-white bg-blue-700 shadow-sm hover:bg-blue-800 hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-500 disabled:bg-slate-300 disabled:text-slate-500 disabled:shadow-none disabled:cursor-not-allowed transition-all duration-200`}
            >
              {isBusy ? (
                <>
                  <Loader2 className="h-5 w-5 animate-spin" aria-hidden />
                  Analysis in progress…
                </>
              ) : (
                'Analyze application'
              )}
            </button>
          )}
        </SocCard>
      </div>
    </div>
  );
}
