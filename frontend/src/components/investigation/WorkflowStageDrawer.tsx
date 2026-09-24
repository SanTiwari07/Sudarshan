import { useInvestigationUI } from '../../context/InvestigationUIContext';
import DrawerShell from '../ui/DrawerShell';
import type { FraudCardData, WorkflowStage } from '../../types/case';
import type { InvestigationBundle } from '../../types/investigation';
import { TYPOGRAPHY } from '../../theme/typography';
import {
  Clock,
  Shield,
  Layers,
  FileCode,
  ArrowRight,
  ExternalLink,
  Activity,
  CheckCircle2,
} from 'lucide-react';

export default function WorkflowStageDrawer({
  data,
  bundle,
  stageIndex,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
  stageIndex: number;
}) {
  const { closeDrawer, openEvidence } = useInvestigationUI();
  const stages = data.fraud_workflow?.stages || [];
  const stage: WorkflowStage | undefined = stages[stageIndex];

  if (!stage) {
    return (
      <DrawerShell
        open={true}
        onClose={closeDrawer}
        title="Workflow Stage Detail"
        subtitle="Stage details not found"
      >
        <p className="text-sm text-slate-500">The requested workflow stage could not be located in the current case.</p>
      </DrawerShell>
    );
  }

  const durationSec = Math.max(0.1, ((stage.end_ms - stage.start_ms) / 1000)).toFixed(1);

  return (
    <DrawerShell
      open={true}
      onClose={closeDrawer}
      title={stage.label}
      subtitle={`Stage ${stageIndex + 1} of ${stages.length} in Attack Sequence`}
    >
      <div className="space-y-6">
        {/* Stage Overview Banner */}
        <div className="rounded-xl bg-slate-50 border border-slate-200 p-4">
          <div className="flex items-center justify-between text-xs text-slate-600 mb-2">
            <span className="flex items-center gap-1.5 font-medium">
              <Clock className="h-3.5 w-3.5 text-slate-400" />
              Runtime Window: {(stage.start_ms / 1000).toFixed(1)}s - {(stage.end_ms / 1000).toFixed(1)}s ({durationSec}s)
            </span>
            <span className="px-2 py-0.5 rounded font-semibold text-[11px] bg-blue-50 text-blue-700 border border-blue-200">
              Confidence: {Math.round((stage.confidence ?? 0.85) * 100)}%
            </span>
          </div>
          <p className="text-sm text-slate-800 leading-relaxed font-medium">
            {stage.description}
          </p>
        </div>

        {/* MITRE Technique */}
        {stage.technique_id && (
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-2">
              <Shield className="h-3.5 w-3.5 text-blue-600" />
              ATT&CK Mapping
            </h3>
            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-200 bg-white shadow-2xs">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-slate-900 bg-slate-100 px-2 py-1 rounded border border-slate-200">
                  {stage.technique_id}
                </span>
                <span className="text-xs text-slate-600 font-medium">{stage.label}</span>
              </div>
              <a
                href={`https://attack.mitre.org/techniques/${stage.technique_id.replace(/\./g, '/')}`}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1 font-semibold"
              >
                <span>MITRE Matrix</span>
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </div>
        )}

        {/* Hook Instrumentation */}
        {stage.hook_names && stage.hook_names.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-2">
              <Activity className="h-3.5 w-3.5 text-slate-600" />
              Frida Telemetry & Hooks Triggered
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {stage.hook_names.map((hook, idx) => (
                <span
                  key={idx}
                  className="px-2.5 py-1 rounded bg-slate-100 text-slate-700 font-mono text-[11px] border border-slate-200"
                >
                  {hook}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Supporting Evidence Records */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-2">
              <Layers className="h-3.5 w-3.5 text-blue-600" />
              Grounded Forensic Evidence ({stage.evidence_ids?.length || 0})
            </h3>
            <span className="text-[11px] text-slate-400">Click to inspect</span>
          </div>

          {(!stage.evidence_ids || stage.evidence_ids.length === 0) ? (
            <p className="text-xs text-slate-500 italic p-3 rounded-lg border border-slate-200 bg-slate-50/50">
              No specific discrete evidence IDs attached to this timeline slice.
            </p>
          ) : (
            <div className="space-y-2">
              {stage.evidence_ids.map((id) => {
                const record = bundle.evidenceRecords.find((r) => r.id === id);
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => openEvidence(id)}
                    className="w-full text-left p-3 rounded-lg border border-slate-200 hover:border-blue-300 hover:bg-blue-50/30 transition-all flex items-center justify-between group shadow-2xs"
                  >
                    <div className="min-w-0 pr-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 px-1.5 py-0.5 rounded border border-blue-200">
                          {id}
                        </span>
                        <span className="text-xs font-semibold text-slate-900 truncate">
                          {record?.title || 'Forensic Evidence Finding'}
                        </span>
                      </div>
                      {record?.description && (
                        <p className="text-xs text-slate-500 truncate mt-1">
                          {record.description}
                        </p>
                      )}
                    </div>
                    <ArrowRight className="h-4 w-4 text-slate-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all shrink-0" />
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </DrawerShell>
  );
}
