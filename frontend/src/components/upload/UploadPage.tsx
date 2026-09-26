import { useState } from 'react';
import { AlertTriangle, Gauge, Layers3, Link2, Loader2, ShieldCheck, Smartphone, Sparkles } from 'lucide-react';
import RecentCases from './RecentCases';
import UrlDiscoveryArea from '../discovery/UrlDiscoveryArea';
import UploadDropZone from './UploadDropZone';
import PipelineStepper, { type PipelineStage } from './PipelineStepper';
import CompletionScreen from './progress/CompletionScreen';
import { useAnalysisSession } from './useAnalysisSession';
import type { FraudCardData } from '../../types/case';
import { getToken } from '../../pages/Login';
import { API_BASE } from '../../config';
import type { StageStatus } from './pipelineStages';

type UploadPageProps = {
  onAnalysisComplete: (data: FraudCardData) => void;
};

const PIPELINE_OVERVIEW: readonly PipelineStage[] = [
  { title: 'Static analysis', description: 'Decompile the app; read its manifest, permissions and code', icon: 'static' },
  { title: 'Sandbox run', description: 'Launch it on an instrumented emulator and watch what it does', icon: 'dynamic' },
  { title: 'Threat intelligence', description: 'Match hashes, domains and families against known threats', icon: 'threat' },
  { title: 'Risk scoring', description: 'Combine the evidence into a 0-100 fraud risk score', icon: 'risk' },
  { title: 'Investigation', description: 'Write the narrative and recommended next steps', icon: 'ai' },
  { title: 'Case report', description: 'Save a fraud card with exportable evidence', icon: 'report' },
] as const;

export default function UploadPage({ onAnalysisComplete }: UploadPageProps) {
  const [mode, setMode] = useState<'apk' | 'url'>('apk');
  const [skipDynamic, setSkipDynamic] = useState(false);
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

  const showPicker = (phase === 'idle' || phase === 'error' || (!isBusy && file)) && mode === 'apk';

  return (
    <div className="upload-fade-in w-full min-w-0 max-w-[1600px] mx-auto pb-8 sm:pb-12">
      {/* Hero: what this is on the left, the one thing to do on the right. */}
      <section className="relative overflow-hidden rounded-2xl sm:rounded-3xl bg-[#0b1120] text-white shadow-xl shadow-slate-900/10 min-h-[calc(100vh-2.5rem)] sm:min-h-[calc(100vh-3rem)] lg:min-h-[calc(100vh-4rem)] flex flex-col justify-between">
        {/* Decorative backdrop: soft glows and a faint grid. */}
        <div aria-hidden className="pointer-events-none absolute inset-0">
          <div className="absolute -top-40 -left-32 h-[28rem] w-[28rem] rounded-full bg-blue-600/20 blur-3xl" />
          <div className="absolute -bottom-20 -right-20 h-[24rem] w-[24rem] rounded-full bg-indigo-600/10 blur-3xl" />
          <div
            className="absolute inset-0 opacity-[0.07]"
            style={{
              backgroundImage:
                'linear-gradient(to right, white 1px, transparent 1px), linear-gradient(to bottom, white 1px, transparent 1px)',
              backgroundSize: '44px 44px',
              maskImage: 'radial-gradient(ellipse at 25% 40%, black 30%, transparent 75%)',
              WebkitMaskImage: 'radial-gradient(ellipse at 25% 40%, black 30%, transparent 75%)',
            }}
          />
        </div>

        <div className="relative grid grid-cols-1 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] gap-6 xl:gap-8 px-5 sm:px-7 xl:px-9 py-4 sm:py-5 xl:py-6 items-center flex-1">
          <div className="min-w-0 py-1">
            <span className="inline-flex items-center gap-2 rounded-full bg-white/10 px-3 py-1 text-xs font-semibold text-blue-200 ring-1 ring-inset ring-white/15">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.9)]" />
              Sandbox online
            </span>
            <h1 className="mt-3 sm:mt-3.5 text-2xl sm:text-3xl xl:text-4xl font-semibold tracking-[-0.035em] leading-[1.12]">
              Is this app
              <br />
              <span className="text-blue-400">
                safe to trust?
              </span>
            </h1>
            <p className="mt-2.5 text-xs sm:text-sm text-slate-300 leading-relaxed max-w-lg">
              Upload an Android APK or paste a suspicious link. Sudarshan takes the app apart, runs it
              in a sandbox, checks it against known banking threats, and gives you one scored case file.
            </p>

            <dl className="mt-3.5 sm:mt-4 grid grid-cols-3 gap-2.5 sm:gap-3 max-w-lg">
              {[
                [Layers3, '6 stages', 'fully automatic'],
                [ShieldCheck, 'Isolated', 'sandbox execution'],
                [Gauge, '0-100', 'deterministic score'],
              ].map(([Icon, value, label]) => {
                const I = Icon as typeof Layers3;
                return (
                  <div key={value as string} className="rounded-xl bg-white/[0.06] ring-1 ring-inset ring-white/10 p-2.5 sm:p-3 transition-colors hover:bg-white/[0.09]">
                    <I className="h-4 w-4 text-blue-300" aria-hidden />
                    <dt className="mt-1.5 text-sm sm:text-base font-semibold tracking-[-0.02em]">{value as string}</dt>
                    <dd className="text-[11px] text-slate-400 mt-0.5">{label as string}</dd>
                  </div>
                );
              })}
            </dl>
          </div>

          {/* Upload panel */}
          <div className="min-w-0 rounded-2xl bg-white text-slate-900 p-4 sm:p-5 shadow-xl shadow-black/25">
            {phase === 'idle' && (
              <div role="group" aria-label="Analysis source" className="grid grid-cols-2 rounded-xl bg-slate-100 p-1 mb-3 sm:mb-3.5">
                {(['apk', 'url'] as const).map((m) => {
                  const Icon = m === 'apk' ? Smartphone : Link2;
                  return (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setMode(m)}
                      aria-pressed={mode === m}
                      className={`inline-flex items-center justify-center gap-2 h-8 sm:h-9 rounded-lg text-xs sm:text-sm font-semibold transition-all cursor-pointer ${
                        mode === m ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-800'
                      }`}
                    >
                      <Icon className="h-4 w-4" aria-hidden />
                      {m === 'apk' ? 'Upload APK' : 'Website URL'}
                    </button>
                  );
                })}
              </div>
            )}

            {showPicker ? (
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
            ) : phase === 'uploading' || phase === 'analyzing' ? (
              <div className="flex flex-col items-center justify-center min-h-[220px] sm:min-h-[240px] py-4 sm:py-5 px-4 text-center">
                <div className="relative mb-3 sm:mb-3.5">
                  <div className="absolute inset-0 bg-blue-500 blur-xl opacity-30 rounded-full animate-pulse" />
                  <span className="relative flex h-12 w-12 sm:h-14 sm:w-14 items-center justify-center rounded-2xl bg-blue-50 ring-1 ring-blue-100 shadow-sm">
                    <Loader2 className="h-6 w-6 sm:h-7 sm:w-7 text-blue-600 animate-spin" aria-hidden />
                  </span>
                </div>
                <h3 className="text-base sm:text-lg font-bold tracking-[-0.015em] text-slate-900">
                  {phase === 'uploading' ? 'Uploading APK' : pipelineUi?.title || 'Analysing in sandbox'}
                </h3>
                <p className="text-xs text-slate-500 mt-1 break-all max-w-sm">
                  {phase === 'uploading' ? file?.name : pipelineUi?.description || file?.name}
                </p>
                <div className="w-full max-w-xs sm:max-w-sm mt-3.5 space-y-1.5">
                  <div className="flex justify-between text-xs font-semibold text-slate-600">
                    <span>{phase === 'uploading' ? 'Transferring' : 'Overall progress'}</span>
                    <span className="tabular-nums text-slate-800">{Math.round(smoothProgress)}%</span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100">
                    <div
                      className="h-full rounded-full bg-blue-600 transition-all duration-300 ease-out"
                      style={{ width: `${smoothProgress}%` }}
                    />
                  </div>
                </div>
                <p className="text-[11px] text-slate-400 mt-3" aria-live="polite">
                  Keep this tab open while the analysis runs.
                </p>
              </div>
            ) : null}

            {phase === 'error' && error && (
              <div className="mt-3 flex items-start justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-3 text-red-800">
                <div className="flex gap-3">
                  <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
                  <div>
                    <p className="font-semibold text-xs sm:text-sm">Analysis failed</p>
                    <p className="text-xs text-red-700 mt-0.5">{error}</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={reset}
                  className="text-xs font-semibold text-red-700 hover:text-red-900 bg-white px-2.5 py-1 rounded-lg border border-red-200 cursor-pointer"
                >
                  Retry
                </button>
              </div>
            )}

            {phase === 'idle' && mode === 'apk' && (
              <div className="mt-3 sm:mt-3.5 flex flex-col gap-2.5">
                <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-2 sm:p-2.5">
                  <label className="flex items-start gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      className="mt-0.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500 h-4 w-4 shrink-0"
                      checked={skipDynamic}
                      onChange={(e) => setSkipDynamic(e.target.checked)}
                      disabled={isBusy}
                    />
                    <div className="flex flex-col">
                      <span className="text-xs font-semibold text-slate-800">
                        Skip dynamic analysis (faster, static only)
                      </span>
                      <span className="text-[10px] sm:text-[11px] text-slate-500 mt-0.5 leading-tight">
                        {skipDynamic
                          ? 'Only decompilation, MobSF, and heuristic checks will run. Sandbox execution will be skipped.'
                          : 'Full analysis enabled: decompilation + live Frida instrumentation in the Android sandbox.'}
                      </span>
                    </div>
                  </label>
                </div>
                <button
                  type="button"
                  disabled={!file || isBusy}
                  onClick={() => void startAnalysis(skipDynamic)}
                  className="w-full h-10 sm:h-10.5 inline-flex items-center justify-center gap-2 rounded-xl text-xs sm:text-sm font-semibold text-white bg-blue-600 shadow-sm hover:bg-blue-700 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-400 disabled:shadow-none"
                >
                  <Sparkles className="h-4 w-4" aria-hidden />
                  {file
                    ? skipDynamic
                      ? 'Start Static Analysis (Skip Sandbox)'
                      : 'Start Full Analysis (Static + Dynamic)'
                    : 'Choose an APK to start'}
                </button>
              </div>
            )}

          </div>
        </div>

        {/* The pipeline as a strip: integrated directly inside the blue hero box */}
        <div className="relative border-t border-white/10 bg-white/[0.02] px-5 py-2.5 sm:px-7 sm:py-3 xl:px-9 xl:py-3.5">
          <div className="flex flex-wrap items-baseline justify-between gap-2 mb-2">
            <h2 id="pipeline-heading" className="text-xs sm:text-sm font-semibold tracking-[-0.015em] text-white">
              {isBusy ? 'Analysis progress' : 'What happens after you upload'}
            </h2>
            <p className="text-[11px] sm:text-xs text-slate-400">Six stages, run automatically · usually a few minutes</p>
          </div>
          <PipelineStepper stages={PIPELINE_OVERVIEW} statusOf={getCardStatus} dark />
        </div>
      </section>

      <div className="mt-10 sm:mt-12 lg:mt-14">
        <RecentCases />
      </div>
    </div>
  );
}
