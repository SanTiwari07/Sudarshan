export type StageStatus = 'pending' | 'active' | 'complete';

export type PipelineStageDef = {
  id: string;
  title: string;
  shortLabel: string;
  description: string;
  progress: number;
  logMessage: string;
  /** Horizontal pipeline bucket */
  bucket: 'upload' | 'static' | 'dynamic' | 'threat' | 'risk' | 'ai' | 'report';
};

export const PIPELINE_STAGES: PipelineStageDef[] = [
  {
    id: 'upload',
    title: 'APK Uploaded',
    shortLabel: 'Upload',
    description: 'Secure transfer to analysis gateway',
    progress: 5,
    logMessage: 'Uploading APK to Sudarshan gateway…',
    bucket: 'upload',
  },
  {
    id: 'sha256',
    title: 'SHA256 Generated',
    shortLabel: 'SHA256',
    description: 'Cryptographic fingerprint for case linkage',
    progress: 10,
    logMessage: 'Generating SHA256 hash…',
    bucket: 'upload',
  },
  {
    id: 'verify',
    title: 'APK Verification',
    shortLabel: 'Verify',
    description: 'Package integrity and format checks',
    progress: 20,
    logMessage: 'Verifying APK structure…',
    bucket: 'upload',
  },
  {
    id: 'manifest',
    title: 'Manifest Parsed',
    shortLabel: 'Manifest',
    description: 'Components, permissions, and entry points',
    progress: 30,
    logMessage: 'Parsing Android manifest…',
    bucket: 'static',
  },
  {
    id: 'permissions',
    title: 'Permission Analysis',
    shortLabel: 'Permissions',
    description: 'Dangerous and banking-sensitive grants',
    progress: 40,
    logMessage: 'Analyzing permission model…',
    bucket: 'static',
  },
  {
    id: 'mobsf',
    title: 'MobSF Analysis',
    shortLabel: 'MobSF',
    description: 'Static code and binary intelligence',
    progress: 50,
    logMessage: 'Running MobSF static engine…',
    bucket: 'static',
  },
  {
    id: 'static_done',
    title: 'Static Intelligence Complete',
    shortLabel: 'Static',
    description: 'Manifest, code, and certificate findings merged',
    progress: 55,
    logMessage: 'Static intelligence phase complete.',
    bucket: 'static',
  },
  {
    id: 'dynamic',
    title: 'Dynamic Runtime',
    shortLabel: 'Dynamic',
    description: 'Emulator sandbox execution',
    progress: 60,
    logMessage: 'Launching emulator sandbox…',
    bucket: 'dynamic',
  },
  {
    id: 'behaviour',
    title: 'Behaviour Monitoring',
    shortLabel: 'Behaviour',
    description: 'Frida hooks and runtime telemetry',
    progress: 70,
    logMessage: 'Injecting Frida and collecting runtime events…',
    bucket: 'dynamic',
  },
  {
    id: 'threat',
    title: 'Threat Correlation',
    shortLabel: 'Threat',
    description: 'VT, OTX, and family attribution',
    progress: 80,
    logMessage: 'Correlating threat intelligence feeds…',
    bucket: 'threat',
  },
  {
    id: 'risk',
    title: 'Risk Engine',
    shortLabel: 'Risk',
    description: 'STEI, BFCI, and FRS scoring',
    progress: 90,
    logMessage: 'Running deterministic risk engine…',
    bucket: 'risk',
  },
  {
    id: 'ai',
    title: 'AI Report',
    shortLabel: 'AI',
    description: 'Executive narrative and recommendations',
    progress: 95,
    logMessage: 'Generating AI investigation report…',
    bucket: 'ai',
  },
  {
    id: 'complete',
    title: 'Completed',
    shortLabel: 'Done',
    description: 'Investigation package ready for analyst review',
    progress: 100,
    logMessage: 'Analysis completed successfully.',
    bucket: 'report',
  },
];

export const HORIZONTAL_PIPELINE = [
  { key: 'upload', label: 'UPLOAD' },
  { key: 'static', label: 'STATIC' },
  { key: 'dynamic', label: 'DYNAMIC' },
  { key: 'threat', label: 'THREAT' },
  { key: 'risk', label: 'RISK' },
  { key: 'ai', label: 'AI' },
  { key: 'report', label: 'REPORT' },
] as const;

export const WORKFLOW_CARDS = [
  {
    title: 'Upload APK',
    description: 'Submit package to dual-audience intelligence pipeline',
    icon: 'upload' as const,
  },
  {
    title: 'Static Intelligence',
    description: 'Manifest, permissions, MobSF, and certificate forensics',
    icon: 'static' as const,
  },
  {
    title: 'Dynamic Runtime Analysis',
    description: 'Sandbox execution with Frida instrumentation',
    icon: 'dynamic' as const,
  },
  {
    title: 'Threat Correlation',
    description: 'Multi-source IOC and family attribution',
    icon: 'threat' as const,
  },
  {
    title: 'Deterministic Risk Engine',
    description: 'STEI · BFCI · FRS with evidence ledger',
    icon: 'risk' as const,
  },
  {
    title: 'AI Intelligence',
    description: 'Narrative, timeline, and analyst recommendations',
    icon: 'ai' as const,
  },
  {
    title: 'Fraud Report',
    description: 'Executive and technical deliverables for SOC handoff',
    icon: 'report' as const,
  },
];

export const CAPABILITY_SECTIONS = [
  {
    title: 'Static Analysis',
    items: ['Extracts Manifest', 'Permissions', 'API Usage', 'Certificates', 'IOCs'],
  },
  {
    title: 'Dynamic Analysis',
    items: ['Runtime Behaviour', 'Accessibility Abuse', 'Overlay Detection', 'SMS Monitoring', 'Network Analysis'],
  },
  {
    title: 'Risk Engine',
    items: ['STEI', 'BFCI', 'FRS', 'Evidence Correlation'],
  },
  {
    title: 'AI Intelligence',
    items: ['Threat Summary', 'Recommendations', 'Timeline', 'Evidence Explanation'],
  },
];

export const ESTIMATED_MINUTES = { min: 3, max: 5 };
