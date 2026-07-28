import { useState } from 'react';
import { GitBranch, ChevronDown, ChevronRight, AlertTriangle, CheckCircle2, Activity, Shield } from 'lucide-react';

// ─── Types ─────────────────────────────────────────────────────────────────────

export type WorkflowStage = {
  label: string;
  technique_id: string;
  description: string;
  start_ms: number;
  end_ms: number;
  evidence_ids: string[];
  hook_names: string[];
  confidence: number;
};

export type FraudWorkflow = {
  stages: WorkflowStage[];
  fraud_sequence_detected: boolean;
  sequence_label: string;
  chain_confidence: number;
  total_events_analyzed: number;
  stage_count: number;
};

// ─── Sequence label display config ────────────────────────────────────────────

const SEQUENCE_STYLES: Record<string, { label: string; color: string; bg: string; border: string }> = {
  FULL_ACCOUNT_TAKEOVER: {
    label: 'Full Account Takeover',
    color: 'text-red-700',
    bg: 'bg-red-50',
    border: 'border-red-300',
  },
  OTP_THEFT_CHAIN: {
    label: 'OTP Theft Chain',
    color: 'text-orange-700',
    bg: 'bg-orange-50',
    border: 'border-orange-300',
  },
  OVERLAY_PHISHING_CHAIN: {
    label: 'Overlay Phishing',
    color: 'text-yellow-700',
    bg: 'bg-yellow-50',
    border: 'border-yellow-300',
  },
  DROPPER_CHAIN: {
    label: 'Dropper Chain',
    color: 'text-purple-700',
    bg: 'bg-purple-50',
    border: 'border-purple-300',
  },
  CREDENTIAL_SCRAPE: {
    label: 'Credential Scrape',
    color: 'text-blue-700',
    bg: 'bg-blue-50',
    border: 'border-blue-300',
  },
  BEHAVIORAL_ANOMALY: {
    label: 'Behavioral Anomaly',
    color: 'text-gray-700',
    bg: 'bg-gray-50',
    border: 'border-gray-300',
  },
  NONE: {
    label: 'No Sequence Detected',
    color: 'text-green-700',
    bg: 'bg-green-50',
    border: 'border-green-300',
  },
};

// ─── Stage confidence color ────────────────────────────────────────────────────

function confidenceColor(c: number): string {
  if (c >= 0.8) return 'bg-red-500';
  if (c >= 0.6) return 'bg-orange-400';
  if (c >= 0.4) return 'bg-yellow-400';
  return 'bg-gray-300';
}

function confidenceText(c: number): string {
  if (c >= 0.8) return 'text-red-700';
  if (c >= 0.6) return 'text-orange-600';
  if (c >= 0.4) return 'text-yellow-600';
  return 'text-gray-500';
}

// ─── Individual Stage Card ─────────────────────────────────────────────────────

function StageCard({
  stage,
  index,
  isLast,
}: {
  stage: WorkflowStage;
  index: number;
  isLast: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const durationS = ((stage.end_ms - stage.start_ms) / 1000).toFixed(1);

  return (
    <div className="relative flex gap-3">
      {/* Vertical connector line */}
      <div className="flex flex-col items-center">
        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0 ${confidenceColor(stage.confidence)}`}>
          {index + 1}
        </div>
        {!isLast && (
          <div className="w-0.5 flex-1 bg-gray-200 mt-1 mb-1 min-h-4" />
        )}
      </div>

      {/* Stage content */}
      <div className="flex-1 pb-4">
        <button
          id={`workflow-stage-${index}`}
          onClick={() => setExpanded(!expanded)}
          className="w-full text-left"
          aria-expanded={expanded}
        >
          <div className="flex items-start justify-between gap-2 p-3 rounded-lg border border-gray-200 bg-white hover:border-blue-300 hover:bg-blue-50 transition-colors">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold text-gray-800">{stage.label}</span>
                <span className="text-xs font-mono px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded">
                  {stage.technique_id}
                </span>
                <span className={`text-xs font-medium ${confidenceText(stage.confidence)}`}>
                  {(stage.confidence * 100).toFixed(0)}% confidence
                </span>
              </div>
              <p className="text-xs text-gray-500 mt-1 line-clamp-2">{stage.description}</p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className="text-xs text-gray-400 whitespace-nowrap">{durationS}s</span>
              {expanded
                ? <ChevronDown className="h-4 w-4 text-gray-400" />
                : <ChevronRight className="h-4 w-4 text-gray-400" />
              }
            </div>
          </div>
        </button>

        {expanded && (
          <div className="mt-1 ml-0 p-3 rounded-lg border border-gray-100 bg-gray-50 text-xs space-y-2">
            <div>
              <span className="font-medium text-gray-600">Full description: </span>
              <span className="text-gray-700">{stage.description}</span>
            </div>
            {stage.hook_names.length > 0 && (
              <div>
                <span className="font-medium text-gray-600">Hooks fired: </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {stage.hook_names.map((h) => (
                    <code key={h} className="px-1.5 py-0.5 bg-slate-100 border border-slate-200 text-slate-800 rounded text-xs font-mono">
                      {h}
                    </code>
                  ))}
                </div>
              </div>
            )}
            <div className="flex gap-4 text-gray-500">
              <span><b>{stage.evidence_ids.length}</b> evidence events</span>
              <span>Duration: <b>{durationS}s</b></span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main WorkflowDiagram Component ───────────────────────────────────────────

export default function WorkflowDiagram({ workflow }: { workflow: FraudWorkflow | null | undefined }) {
  if (!workflow) {
    return (
      <div className="flex items-center gap-2 px-4 py-3 text-sm text-green-700 bg-green-50 rounded-lg border border-green-200">
        <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
        <span>No dynamic analysis data — workflow reconstruction requires Frida runtime data.</span>
      </div>
    );
  }

  if (!workflow.fraud_sequence_detected || workflow.stages.length === 0) {
    return (
      <div className="flex items-center gap-2 px-4 py-3 text-sm text-green-700 bg-green-50 rounded-lg border border-green-200">
        <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
        <span>
          No fraud workflow reconstructed from {workflow.total_events_analyzed} runtime events.
          No behavioral fraud sequence was detected.
        </span>
      </div>
    );
  }

  const seqStyle = SEQUENCE_STYLES[workflow.sequence_label] ?? SEQUENCE_STYLES['BEHAVIORAL_ANOMALY'];

  return (
    <div className="space-y-4">
      {/* ── Header badge ── */}
      <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${seqStyle.bg} ${seqStyle.border}`}>
        <Activity className={`h-5 w-5 flex-shrink-0 ${seqStyle.color}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-sm font-bold ${seqStyle.color}`}>{seqStyle.label}</span>
            <span className="text-xs text-gray-500">
              {(workflow.chain_confidence * 100).toFixed(0)}% chain confidence
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-0.5">
            {workflow.stage_count} stages detected from {workflow.total_events_analyzed} runtime events
          </p>
        </div>
        <Shield className={`h-5 w-5 flex-shrink-0 ${seqStyle.color} opacity-60`} />
      </div>

      {/* ── MITRE ATT&CK techniques summary ── */}
      <div className="flex flex-wrap gap-1.5">
        {Array.from(new Set(workflow.stages.map((s) => s.technique_id))).map((tid) => (
          <a
            key={tid}
            href={`https://attack.mitre.org/techniques/${tid}/`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 px-2 py-1 text-xs font-mono font-medium bg-blue-50 border border-blue-200 text-blue-700 rounded hover:bg-blue-100 transition-colors shadow-2xs"
            title={`View ${tid} on MITRE ATT&CK for Mobile`}
          >
            <GitBranch className="h-3 w-3" />
            {tid}
          </a>
        ))}
      </div>

      {/* ── Causal chain stages ── */}
      <div className="pl-1">
        {workflow.stages.map((stage, i) => (
          <StageCard
            key={`${stage.label}-${i}`}
            stage={stage}
            index={i}
            isLast={i === workflow.stages.length - 1}
          />
        ))}
      </div>

      {/* ── Footer evidence count ── */}
      <div className="flex items-center gap-1.5 text-xs text-gray-400 pt-1">
        <AlertTriangle className="h-3.5 w-3.5 text-yellow-500" />
        <span>
          Workflow reconstructed deterministically from {workflow.total_events_analyzed} Frida runtime events.
          Stages are ranked by causal precedence, not temporal order alone.
        </span>
      </div>
    </div>
  );
}
