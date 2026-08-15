import { useState } from 'react';
import { AlertTriangle, Loader2 } from 'lucide-react';
import { SocCard } from '../ui/Card';
import UrlDiscoveryArea from '../discovery/UrlDiscoveryArea';
import UploadDropZone from './UploadDropZone';
import StageCard from './StageCard';
import CompletionScreen from './progress/CompletionScreen';
import { useAnalysisSession } from './useAnalysisSession';
import type { FraudCardData } from '../../App';
import { getToken } from '../../pages/Login';
import { API_BASE } from '../../config';
import type { StageStatus } from './pipelineStages';
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

  const getCardStatus = (cardIndex: number): StageStatus | undefined => {
    if (phase === 'idle' || phase === 'uploading') return undefined;
    if (phase === 'error') return 'error';
    if (phase === 'complete') return 'complete';
    
    const stageOrder = [
      ['QUEUED', 'VALIDATING', 'STATIC_ANALYSIS'],
      ['ANALYSIS_ENGINE', 'DYNAMIC_PREPARATION', 'DYNAMIC_ANALYSIS', 'EVIDENCE_PROCESSING'],
      ['THREAT_CORRELATION'],
      ['RISK_ASSESSMENT'],
      ['INTELLIGENCE_GENERATION'],
      ['REPORT_GENERATION', 'PERSISTING', 'COMPLETED']
    ];

    const rawStage = pipelineUi?.rawStage || 'QUEUED';
    let activeIndex = 0;
    for (let i = 0; i < stageOrder.length; i++) {
      if (stageOrder[i].includes(rawStage)) {
        activeIndex = i;
        break;
      }
    }
    
    if (cardIndex < activeIndex) return 'complete';
    if (cardIndex === activeIndex) return 'active';
    return 'pending';
  };

  return (
    <div className="upload-fade-in flex justify-center px-4 py-10 sm:py-16">
      <div className="w-full max-w-[68rem]">
        <SocCard className="p-8 sm:p-10 lg:p-12 border-slate-200/80 shadow-sm">
          {phase === 'idle' && (
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
          )}

          {(phase === 'idle' || phase === 'error' || (!isBusy && file)) && mode === 'apk' ? (
            <UploadDropZone
              file={file}
              onFile={setFile}
              disabled={isBusy}
              disabledMessage={isBusy ? 'Analysis in progress. Please wait.' : undefined}
            />
          ) : phase === 'idle' && mode === 'url' ? (
            <UrlDiscoveryArea 
              disabled={isBusy}
              onAnalyzeCandidate={async (candidateId, sessionId, filename) => {
                try {
                  const token = import.meta.env.VITE_DEV_TOKEN || getToken();
                  const res = await fetch(`${API_BASE}/discovery/${sessionId}/analyze`, {
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
          ) : phase === 'uploading' ? (
            <div className="flex flex-col items-center justify-center py-12 px-4 text-center border-2 border-dashed border-slate-200 rounded-2xl bg-slate-50/50">
              <Loader2 className="h-10 w-10 text-blue-600 animate-spin mb-4" aria-hidden />
              <h3 className="text-lg font-semibold text-slate-900">Uploading APK</h3>
              <p className="text-sm font-medium text-slate-500 mt-2 mb-6 break-all max-w-md">{file?.name}</p>
              
              <div className="w-full max-w-xs space-y-2">
                <div className="flex justify-between text-xs font-medium text-slate-500">
                  <span>Uploading...</span>
                  <span>{Math.round(smoothProgress)}%</span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200">
                  <div 
                    className="h-full bg-blue-600 transition-all duration-300 ease-out"
                    style={{ width: `${smoothProgress}%` }}
                  />
                </div>
              </div>
              <p className="text-xs text-slate-400 mt-6">Please wait while the APK is securely uploaded.</p>
            </div>
          ) : phase === 'analyzing' ? (
            <div className="flex flex-col items-center justify-center py-12 px-4 text-center border border-blue-100 rounded-2xl bg-blue-50/30 shadow-sm relative overflow-hidden">
              <div className="absolute top-0 left-0 w-full h-1 bg-blue-100">
                <div 
                  className="h-full bg-blue-500 transition-all duration-300 ease-out" 
                  style={{ width: `${smoothProgress}%` }} 
                />
              </div>
              <div className="relative">
                <div className="absolute inset-0 bg-blue-400 blur-xl opacity-20 rounded-full animate-pulse" />
                <Loader2 className="relative h-10 w-10 text-blue-600 animate-spin mb-4" aria-hidden />
              </div>
              <h3 className="text-lg font-semibold text-slate-900">Analyzing APK</h3>
              <p className="text-sm font-medium text-slate-500 mt-1 mb-2 break-all max-w-md">Case: {file?.name}</p>
              
              <div className="mt-4 py-3 px-5 rounded-xl bg-white border border-blue-100 shadow-sm max-w-md w-full text-left">
                <p className="text-xs font-semibold text-blue-800 uppercase tracking-wider mb-1">Current Stage</p>
                <p className="text-sm font-medium text-slate-900">{pipelineUi?.title || 'Processing'}</p>
                {pipelineUi?.description && (
                  <p className="text-xs text-slate-500 mt-1 line-clamp-2">{pipelineUi.description}</p>
                )}
              </div>
              
              <p className="text-xs text-slate-400 mt-6" aria-live="polite">Do not close this window while analysis is running.</p>
            </div>
          ) : null}

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
              {PIPELINE_OVERVIEW.map((p, index) => (
                <StageCard
                  key={p.title}
                  title={p.title}
                  description={p.description}
                  icon={p.icon}
                  status={getCardStatus(index)}
                  overview
                />
              ))}
            </div>
          </section>

          {phase === 'error' && error && (
            <div className="mt-8 flex items-start justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-red-800">
              <div className="flex gap-3">
                <AlertTriangle className="h-5 w-5 shrink-0" aria-hidden />
                <div>
                  <p className="font-semibold text-sm">Analysis Failed</p>
                  <p className={`${TYPOGRAPHY.bodySmall} mt-1`}>{error}</p>
                </div>
              </div>
              <button
                type="button"
                onClick={reset}
                className="text-sm font-medium text-red-700 hover:text-red-900 focus:outline-none focus-visible:underline bg-white/50 px-3 py-1.5 rounded-lg border border-red-200"
              >
                Retry Analysis
              </button>
            </div>
          )}

          {phase === 'idle' && mode === 'apk' && (
            <button
              type="button"
              disabled={!file || isBusy}
              onClick={() => void startAnalysis()}
              className={`mt-10 w-full h-14 flex justify-center items-center gap-2 rounded-[13px] ${TYPOGRAPHY.button} text-white bg-blue-700 shadow-sm hover:bg-blue-800 hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-500 disabled:bg-slate-300 disabled:text-slate-500 disabled:shadow-none disabled:cursor-not-allowed transition-all duration-200`}
            >
              Analyze application
            </button>
          )}
        </SocCard>
      </div>
    </div>
  );
}
