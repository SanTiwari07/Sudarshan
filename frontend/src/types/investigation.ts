export type LedgerScope =
  | 'full'
  | 'stei'
  | 'dynamic'
  | 'correlation'
  | 'banking'
  | 'ct'
  | 'bt'
  | 'pr'
  | 'ob'
  | 'ir';

export type RiskExplanationPayload = {
  evidence_lines?: string[];
  component_evidence?: Record<string, string[]>;
  stei_evidence_by_axis?: Record<string, string[]>;
};

export type InvestigationEvidence = {
  id: string;
  title: string;
  severity: string;
  confidence: number;
  category: 'static' | 'runtime' | 'intel' | 'score' | 'scenario';
  sourceEngine: string;
  timestampMs?: number;
  description?: string;
  mitreId?: string;
  mitreName?: string;
  screenshotRef?: string;
  hookNames?: string[];
  artifactRefs?: string[];
  contributionLabel?: string;
  linkedLedgerLineIds?: string[];
};

export type LedgerLine = {
  id: string;
  component: string;
  label: string;
  detail: string;
  contribution?: number;
  contributionLabel?: string;
  evidenceIds: string[];
  axis?: string;
};

export type TimelineEvent = {
  id: string;
  timestampMs: number;
  label: string;
  source: string;
  category: string;
  evidenceIds: string[];
  contributionLabel?: string;
  kind: 'forensic' | 'score' | 'workflow';
};

export type InvestigationCounts = {
  staticFindings: number;
  runtimeBehaviors: number;
  mitreTechniques: number;
  iocMatches: number;
  familyMatches: number;
  screenshots: number;
  evidenceRecords: number;
};

export type InvestigationBundle = {
  evidenceRecords: InvestigationEvidence[];
  ledgerLines: LedgerLine[];
  timelineEvents: TimelineEvent[];
  counts: InvestigationCounts;
};
