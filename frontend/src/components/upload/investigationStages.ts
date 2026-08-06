export type InvestigationStageStatus = 'pending' | 'active' | 'complete';

export type InvestigationStage = {
  id: string;
  title: string;
  description: string;
  /** Progress (0–100) at which this stage is considered complete */
  progressEnd: number;
  nextSteps: string[];
};

export const INVESTIGATION_STAGES: InvestigationStage[] = [
  {
    id: 'evidence',
    title: 'Evidence collection',
    description:
      'Securely receiving the application package and preserving a verifiable chain of custody for downstream analysis.',
    progressEnd: 15,
    nextSteps: [
      'Extract manifest and permissions',
      'Begin static intelligence review',
      'Prepare runtime sandbox session',
    ],
  },
  {
    id: 'static',
    title: 'Static intelligence',
    description:
      'Examining the APK structure, declared components, dangerous permissions, certificates, and static indicators without executing the application.',
    progressEnd: 40,
    nextSteps: [
      'Launch runtime behaviour analysis',
      'Monitor accessibility and overlay patterns',
      'Capture network and API activity',
    ],
  },
  {
    id: 'runtime',
    title: 'Runtime behaviour analysis',
    description:
      'Executing the application in a controlled sandbox to observe real-world behaviour, including SMS, overlays, accessibility abuse, and command-and-control activity.',
    progressEnd: 70,
    nextSteps: [
      'Correlate indicators with threat intelligence',
      'Map behaviour to MITRE ATT&CK techniques',
      'Identify banking-relevant attack patterns',
    ],
  },
  {
    id: 'threat',
    title: 'Threat attribution',
    description:
      'Correlating runtime behaviour, extracted indicators of compromise, known malware signatures, and banking threat intelligence to identify the malware family and attack campaign.',
    progressEnd: 85,
    nextSteps: [
      'Calculate fraud risk score',
      'Classify malware family',
      'Generate executive report',
      'Prepare technical evidence',
    ],
  },
  {
    id: 'risk',
    title: 'Risk assessment',
    description:
      'Applying Sudarshan’s deterministic risk models to quantify banking impact, customer exposure, and recommended SOC response priority.',
    progressEnd: 95,
    nextSteps: [
      'Generate executive report',
      'Prepare technical evidence',
      'Finalize investigation package',
    ],
  },
  {
    id: 'report',
    title: 'Executive report generation',
    description:
      'Synthesizing findings into an analyst-ready fraud intelligence report with narrative, recommendations, and exportable evidence.',
    progressEnd: 100,
    nextSteps: ['Open investigation report'],
  },
];

export function stageStatesForProgress(progress: number): InvestigationStageStatus[] {
  return INVESTIGATION_STAGES.map((stage, i) => {
    const prevEnd = i === 0 ? 0 : INVESTIGATION_STAGES[i - 1].progressEnd;
    if (progress >= stage.progressEnd) return 'complete';
    if (progress >= prevEnd) return 'active';
    return 'pending';
  });
}

export function activeStageIndex(progress: number): number {
  const states = stageStatesForProgress(progress);
  const active = states.findIndex((s) => s === 'active');
  if (active >= 0) return active;
  if (progress >= 100) return INVESTIGATION_STAGES.length - 1;
  return 0;
}
