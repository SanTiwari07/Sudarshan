/** Maps backend orchestrator stages to analyst-facing copy and progress weights. */

export type BackendPipelineState = {
  progress_pct?: number;
  pipeline_stage?: string;
  pipeline_substage?: string;
  pipeline_message?: string;
  elapsed_ms?: number;
};

const STAGE_COPY: Record<
  string,
  { title: string; description: string; progressAnchor: number }
> = {
  QUEUED: {
    title: 'Queued',
    description: 'Waiting for an analysis worker slot.',
    progressAnchor: 3,
  },
  VALIDATING: {
    title: 'Evidence collection',
    description: 'Receiving the APK and verifying package integrity.',
    progressAnchor: 8,
  },
  STATIC_ANALYSIS: {
    title: 'Static intelligence',
    description: 'MobSF, native analyzer, APKTool, and JADX static review.',
    progressAnchor: 35,
  },
  ANALYSIS_ENGINE: {
    title: 'Analysis engine',
    description: 'Running static and dynamic analysis in the hardened analysis-engine microservice.',
    progressAnchor: 50,
  },
  DYNAMIC_PREPARATION: {
    title: 'Sandbox preparation',
    description: 'Preparing emulator session, install, and launch.',
    progressAnchor: 48,
  },
  DYNAMIC_ANALYSIS: {
    title: 'Runtime behaviour analysis',
    description: 'Frida instrumentation, Agentic Explorer, and network capture.',
    progressAnchor: 68,
  },
  EVIDENCE_PROCESSING: {
    title: 'Evidence processing',
    description: 'Workflow reconstruction, BFCI scoring, and VIDE merge.',
    progressAnchor: 74,
  },
  THREAT_CORRELATION: {
    title: 'Threat attribution',
    description: 'Correlating IOCs with VirusTotal, OTX, and AbuseIPDB.',
    progressAnchor: 80,
  },
  RISK_ASSESSMENT: {
    title: 'Risk assessment',
    description: 'Calculating deterministic FRS from verified evidence.',
    progressAnchor: 86,
  },
  INTELLIGENCE_GENERATION: {
    title: 'AI investigation',
    description: 'RAG indexing and Gemini 2.5 Flash narrative synthesis.',
    progressAnchor: 93,
  },
  REPORT_GENERATION: {
    title: 'Report generation',
    description: 'Preparing exportable investigation deliverables.',
    progressAnchor: 96,
  },
  PERSISTING: {
    title: 'Finalizing case',
    description: 'Persisting case data and investigation index.',
    progressAnchor: 98,
  },
  COMPLETED: {
    title: 'Complete',
    description: 'Investigation package ready.',
    progressAnchor: 100,
  },
  FAILED: {
    title: 'Failed',
    description: 'Analysis did not complete successfully.',
    progressAnchor: 100,
  },
};

export function resolvePipelineUi(state: BackendPipelineState | null): {
  progress: number;
  title: string;
  description: string;
  substage?: string;
} {
  const stage = state?.pipeline_stage || 'QUEUED';
  const copy = STAGE_COPY[stage] || {
    title: stage.replace(/_/g, ' '),
    description: state?.pipeline_message || 'Analysis in progress…',
    progressAnchor: state?.progress_pct ?? 5,
  };
  const backendPct =
    typeof state?.progress_pct === 'number' ? state.progress_pct : copy.progressAnchor;
  const progress = Math.min(99, Math.max(0, backendPct));
  const description = state?.pipeline_message?.trim() || copy.description;
  const substage = state?.pipeline_substage?.trim() || undefined;
  return {
    progress,
    title: copy.title,
    description: substage ? `${description} (${substage})` : description,
    substage,
  };
}
