import type { FraudCardData, VideResult } from '../../App';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import {
  formatVideConfidence,
  getVideUiState,
  resolveVideFromData,
  VIDE_BASELINE_SHORT_NAMES,
  videConfidenceValue,
  videEvidenceSources,
} from '../../lib/videUi';
import { AlertTriangle, Eye, Fingerprint, ShieldAlert } from 'lucide-react';

function pct(value: number | undefined): string {
  if (value == null || Number.isNaN(value)) return '-';
  return `${Math.round(value * 100)}%`;
}

function capabilityLabels(data: FraudCardData): string[] {
  const out: string[] = [];
  if (data.has_accessibility_abuse) out.push('Accessibility abuse');
  if (data.has_system_alert_window) out.push('Overlay capability');
  if (data.has_sms_read_write) out.push('SMS read/write');
  return out;
}

function UnavailableBody({ vide, missing }: { vide?: VideResult; missing?: boolean }) {
  return (
    <div className="p-4 text-xs text-slate-600 space-y-2">
      <p className="font-medium text-slate-800">Analysis unavailable</p>
      <p>
        {missing
          ? 'VIDE results were not returned for this investigation. Re-run analysis or open a case saved after VIDE was enabled.'
          : `Visual impersonation analysis could not be completed${vide?.status ? ` (${vide.status})` : ''}.`}
      </p>
      {vide?.error ? <p className="text-slate-500 font-mono text-[11px] break-words">{vide.error}</p> : null}
      {(vide?.vide_compare?.evidence_lines ?? []).length > 0 && (
        <ul className="list-disc list-inside text-slate-600 space-y-0.5">
          {(vide?.vide_compare?.evidence_lines ?? []).slice(0, 4).map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AnalyzedBody({ vide, data }: { vide: VideResult; data: FraudCardData }) {
  const compare = vide.vide_compare;
  const confidence = videConfidenceValue(vide);
  const evidence = videEvidenceSources(vide);
  const signer = vide.signer_impersonation;

  return (
    <div className="p-4 space-y-4 text-xs text-slate-600">
      <div>
        <p className="text-sm font-semibold text-slate-800">No banking UI impersonation detected</p>
        <p className="mt-1">VIDE-F001 did not fire for this sample against lab baselines.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="p-3 rounded-lg border border-slate-200 bg-slate-50/80">
          <div className="text-[10px] uppercase tracking-wide text-slate-500">VIDE confidence</div>
          <div className="text-lg font-bold text-slate-900 tabular-nums mt-0.5">
            {formatVideConfidence(confidence)}
          </div>
        </div>
        <div className="p-3 rounded-lg border border-slate-200 bg-slate-50/80">
          <div className="text-[10px] uppercase tracking-wide text-slate-500">Status</div>
          <div className="text-sm font-semibold text-slate-800 mt-0.5">{vide.status || 'OK'}</div>
        </div>
      </div>

      <div>
        <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">Baselines analyzed</div>
        <p className="text-slate-800 font-medium">{Object.values(VIDE_BASELINE_SHORT_NAMES).join(' · ')}</p>
      </div>

      {evidence.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">Evidence</div>
          <p>{evidence.join(' · ')}</p>
        </div>
      )}

      {(compare?.scores?.string_jaccard != null ||
        compare?.scores?.tree_similarity != null ||
        compare?.scores?.color_match != null) && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          <Metric label="String similarity" value={pct(compare?.scores?.string_jaccard)} />
          <Metric label="UI structure" value={pct(compare?.scores?.tree_similarity)} />
          <Metric label="Visual identity" value={pct(compare?.scores?.color_match)} />
        </div>
      )}

      <div className="p-3 rounded-lg border border-slate-200 bg-slate-50">
        <div className="text-[10px] uppercase tracking-wide text-slate-500">Signer</div>
        <div className="mt-1 font-semibold text-slate-800">
          {signer?.detected ? 'Mismatch / impersonation signal' : 'No signer impersonation (CH06)'}
        </div>
      </div>

      {vide.critical_visual_cluster && (
        <div className="p-3 rounded-lg border border-amber-200 bg-amber-50 text-amber-900">
          Critical visual cluster flag is set without VIDE-F001 detection - review correlated capabilities.
        </div>
      )}

      {(compare?.evidence_lines ?? []).length > 0 && (
        <details className="text-slate-600">
          <summary className="cursor-pointer font-semibold text-slate-700">Deterministic evidence lines</summary>
          <ul className="mt-2 space-y-1 list-disc list-inside">
            {(compare?.evidence_lines ?? []).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </details>
      )}

      {capabilityLabels(data).length > 0 && (
        <div className="text-slate-500">
          Related capabilities: {capabilityLabels(data).join(', ')}
        </div>
      )}
    </div>
  );
}

function DetectedBody({ vide, data }: { vide: VideResult; data: FraudCardData }) {
  const compare = vide.vide_compare;
  const signer = vide.signer_impersonation;
  const scores = compare?.scores;
  const matched = compare?.matched_strings ?? [];
  const caps = capabilityLabels(data);

  return (
    <div className="p-4 space-y-4 text-xs">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <div className="text-[10px] uppercase tracking-wide text-slate-500">Target institution</div>
          <div className="text-lg font-semibold text-slate-900 mt-0.5">
            {compare?.institution_display || vide.visual_impersonation_institution || 'Unknown'}
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wide text-slate-500">Rule</div>
          <div className="text-sm font-bold text-red-700 mt-0.5">{compare?.rule_id || 'VIDE-F001'}</div>
          <div className="text-slate-600 mt-1">Banking UI impersonation detected</div>
        </div>
      </div>

      <div>
        <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-2">Structural similarity</div>
        <div className="text-2xl font-bold text-slate-900 tabular-nums">
          {formatVideConfidence(videConfidenceValue(vide))}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        <Metric label="String similarity" value={pct(scores?.string_jaccard)} />
        <Metric label="UI structure" value={pct(scores?.tree_similarity)} />
        <Metric label="Visual identity" value={pct(scores?.color_match)} />
      </div>

      {matched.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-2">Matched UI elements</div>
          <ul className="list-disc list-inside text-slate-700 space-y-0.5">
            {matched.slice(0, 12).map((s) => (
              <li key={s} className="capitalize">
                {s}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="p-3 rounded-lg border border-slate-200 bg-slate-50">
        <div className="text-[10px] uppercase tracking-wide text-slate-500">Signer</div>
        <div className="mt-1 font-semibold text-slate-800">
          {signer?.detected ? 'MISMATCH / IMPERSONATION' : 'Unknown / Mismatch'}
        </div>
        {(signer?.evidence_lines ?? []).slice(0, 2).map((line) => (
          <p key={line} className="text-slate-600 mt-1">
            {line}
          </p>
        ))}
      </div>

      {vide.critical_visual_cluster && (
        <div className="p-3 rounded-lg border border-red-200 bg-red-50">
          <div className="flex items-center gap-2 text-red-800 font-semibold">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            Critical visual cluster
          </div>
          <p className="text-red-900/90 mt-2">Visual impersonation</p>
          {caps.length > 0 ? (
            <ul className="mt-1 list-disc list-inside text-red-900/80">
              {caps.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          ) : (
            <p className="text-red-900/80 mt-1">Plus qualifying high-risk capability evidence</p>
          )}
        </div>
      )}

      {(compare?.evidence_lines ?? []).length > 0 && (
        <details className="text-slate-600">
          <summary className="cursor-pointer font-semibold text-slate-700">Deterministic evidence lines</summary>
          <ul className="mt-2 space-y-1 list-disc list-inside">
            {(compare?.evidence_lines ?? []).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-2 rounded-lg border border-slate-200 bg-white">
      <div className="text-[10px] uppercase text-slate-500">{label}</div>
      <div className="text-sm font-semibold text-slate-900 tabular-nums mt-0.5">{value}</div>
    </div>
  );
}

export default function VisualImpersonationPanel({ data }: { data: FraudCardData }) {
  const vide = resolveVideFromData(data);
  const state = getVideUiState(vide);

  const subtitle =
    state === 'missing'
      ? 'VIDE payload missing'
      : state === 'unavailable'
        ? `VIDE ${vide?.status || 'unavailable'}`
        : state === 'detected'
          ? 'Banking UI impersonation signal'
          : 'Deterministic VIDE engine (lab baselines)';

  const headerIcon =
    state === 'detected' || vide?.critical_visual_cluster || vide?.signer_impersonation?.detected ? (
      <AlertTriangle className="h-4 w-4 text-red-600" />
    ) : (
      <Eye className="h-4 w-4" />
    );

  return (
    <SocCard>
      <SectionHeader icon={headerIcon} title="Visual impersonation" subtitle={subtitle} />
      {vide?.signer_impersonation?.detected && (
        <div className="px-4 pb-0 flex items-center gap-2 text-xs text-amber-800">
          <Fingerprint className="h-3.5 w-3.5" />
          CH06 signer impersonation signal present
        </div>
      )}
      {state === 'missing' && <UnavailableBody missing />}
      {state === 'unavailable' && vide && <UnavailableBody vide={vide} />}
      {state === 'analyzed' && vide && <AnalyzedBody vide={vide} data={data} />}
      {state === 'detected' && vide && <DetectedBody vide={vide} data={data} />}
    </SocCard>
  );
}
