import { useState } from 'react';
import { AlertTriangle, Loader2, Sparkles } from 'lucide-react';
import { SocCard } from '../ui/Card';
import UrlDiscoveryArea from '../discovery/UrlDiscoveryArea';
import UploadDropZone from './UploadDropZone';
import PipelineStepper, { type PipelineStage } from './PipelineStepper';
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

const PIPELINE_OVERVIEW: readonly PipelineStage[] = [
  { title: 'Static', description: 'Manifest, certificates, code findings', icon: 'static' },
  { title: 'Dynamic', description: 'Emulator sandbox with Frida hooks', icon: 'dynamic' },
  { title: 'Correlation', description: 'VirusTotal, OTX, family mapping', icon: 'threat' },
  { title: 'Risk engine', description: 'STEI, BFCI and FRS scoring', icon: 'risk' },
  { title: 'Investigation', description: 'Narrative and recommendations', icon: 'ai' },
  { title: 'Report', description: 'Fraud card and export artifacts', icon: 'report' },
] as const;

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
    <div className="upload-fade-in w-full min-w-0 space-y-4">
      <SocCard className="p-6 sm:p-8 lg:p-10 border-slate-200/80 shadow-sm">
        {phase === 'idle' && (
          <div
            role="group"
            aria-label="Analysis source"
            className="inline-flex rounded-md border border-slate-300 bg-slate-50 p-0.5 mb-6"
          >
            {(['apk', 'url'] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMode(m)}
                aria-pressed={mode === m}
                className={`px-4 py-1.5 rounded text-[15px] font-medium transition-colors cursor-pointer ${
                  mode === m
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                {m === 'apk' ? 'Upload APK' : 'Website URL'}
              </button>
            ))}
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
            <h3 className="text-lg font-bold text-slate-900">Uploading APK</h3>
            <p className="text-xs font-mono text-slate-500 mt-1 mb-6 break-all max-w-md">{file?.name}</p>
            
            <div className="w-full max-w-sm space-y-2">
              <div className="flex justify-between text-xs font-mono text-slate-600">
                <span>Uploading…</span>
                <span>{Math.round(smoothProgress)}%</span>
              </div>
              <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-200">
                <div 
                  className="h-full bg-blue-600 transition-all duration-300 ease-out"
                  style={{ width: `${smoothProgress}%` }}
                />
              </div>
            </div>
            <p className="text-xs text-slate-400 mt-5">Please wait while the APK is securely transferred.</p>
          </div>
        ) : phase === 'analyzing' ? (
          <div className="flex flex-col items-center justify-center py-12 px-4 text-center border border-blue-100 rounded-2xl bg-blue-50/30 shadow-xs relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1.5 bg-blue-100">
              <div 
                className="h-full bg-blue-500 transition-all duration-300 ease-out" 
                style={{ width: `${smoothProgress}%` }} 
              />
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-blue-400 blur-xl opacity-20 rounded-full animate-pulse" />
              <Loader2 className="relative h-10 w-10 text-blue-600 animate-spin mb-4" aria-hidden />
            </div>
            <h3 className="text-lg font-bold text-slate-900">Analyzing APK in Sandbox</h3>
            <p className="text-xs font-mono text-slate-500 mt-0.5 mb-3 break-all max-w-md">Case: {file?.name}</p>
            
            <div className="mt-4 py-3 px-5 rounded-xl bg-white border border-blue-100 shadow-2xs max-w-lg w-full text-left">
              <p className="text-[12px] font-bold text-blue-800 uppercase tracking-wider mb-1 font-mono">Current Stage</p>
              <p className="text-sm font-bold text-slate-900">{pipelineUi?.title || 'Processing'}</p>
              {pipelineUi?.description && (
                <p className="text-xs text-slate-500 mt-1 line-clamp-2">{pipelineUi.description}</p>
              )}
            </div>
            
            <p className="text-xs text-slate-400 mt-5" aria-live="polite">Do not close this window while analysis is running.</p>
          </div>
        ) : null}

        <section className="mt-8 pt-6 border-t border-slate-100" aria-labelledby="pipeline-overview-heading">
          <div className="flex flex-wrap items-baseline justify-between gap-2 mb-5">
            <h2 id="pipeline-overview-heading" className={TYPOGRAPHY.h3}>
              Analysis pipeline
            </h2>
            <p className={TYPOGRAPHY.caption}>
              Six stages, run automatically on intake
            </p>
          </div>
          <PipelineStepper stages={PIPELINE_OVERVIEW} statusOf={getCardStatus} />
        </section>

        {phase === 'error' && error && (
          <div className="mt-5 flex items-start justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-red-800">
            <div className="flex gap-3">
              <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" aria-hidden />
              <div>
                <p className="font-bold text-xs">Analysis Failed</p>
                <p className="text-xs text-red-700 mt-0.5">{error}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={reset}
              className="text-xs font-semibold text-red-700 hover:text-red-900 bg-white px-3 py-1.5 rounded-lg border border-red-200 shadow-2xs cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        {phase === 'idle' && mode === 'apk' && (
          <button
            type="button"
            disabled={!file || isBusy}
            onClick={() => void startAnalysis()}
            className={`${TYPOGRAPHY.button} mt-6 w-full h-12 text-white bg-blue-700 shadow-sm hover:bg-blue-800 disabled:bg-slate-100 disabled:text-slate-400 disabled:shadow-none`}
          >
            <Sparkles className="h-4 w-4" aria-hidden />
            Analyse application
          </button>
        )}
      </SocCard>
    </div>
  );
}
