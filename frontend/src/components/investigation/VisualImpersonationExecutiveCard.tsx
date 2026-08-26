import { Link } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import {
  formatVideConfidence,
  getVideUiState,
  resolveVideFromData,
  VIDE_BASELINE_SHORT_NAMES,
  videColorSwatches,
  videConfidenceTier,
  videConfidenceValue,
  videEvidenceSources,
  videForensics,
  videMatchedText,
  videTierLabel,
  videTierStyles,
} from '../../lib/videUi';
import { AlertTriangle, Eye, LayoutTemplate, Palette, ShieldAlert, Type } from 'lucide-react';
import { useCaseLinks } from '../../hooks/useCaseLinks';

export default function VisualImpersonationExecutiveCard({ data }: { data: FraudCardData }) {
  const links = useCaseLinks();
  const vide = resolveVideFromData(data);
  const state = getVideUiState(vide);

  if (state === 'missing') {
    return (
      <SocCard className="border-slate-200/80">
        <div className="px-4 sm:px-5 py-4 flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-600 border border-slate-200/80">
            <Eye className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <p className="font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Visual impersonation</p>
            <p className="text-sm font-semibold text-slate-800 mt-0.5">Analysis unavailable</p>
            <p className="text-xs text-slate-500 mt-1">VIDE results were not included in this case payload.</p>
          </div>
        </div>
      </SocCard>
    );
  }

  const compare = vide!.vide_compare;
  const confidence = videConfidenceValue(vide!);

  if (state === 'unavailable') {
    return (
      <SocCard className="border-slate-200/80">
        <div className="px-4 sm:px-5 py-4 flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-600 border border-slate-200/80">
            <Eye className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <p className="font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Visual impersonation</p>
            <p className="text-sm font-semibold text-slate-800 mt-0.5">Analysis unavailable</p>
            <p className="text-xs text-slate-500 mt-1">
              {vide!.error?.trim() || `VIDE status: ${vide!.status || 'UNAVAILABLE'}`}
            </p>
          </div>
        </div>
      </SocCard>
    );
  }

  if (state === 'analyzed') {
    const evidence = videEvidenceSources(vide!);
    return (
      <SocCard className="border-slate-200/80">
        <div className="px-4 sm:px-5 py-4 flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-600 border border-slate-200/80">
            <Eye className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Visual impersonation</p>
            <p className="text-sm font-semibold text-slate-800 mt-0.5">No banking-app impersonation detected</p>
            <p className="text-xs text-slate-600 mt-1">
              VIDE compared the application interface against available laboratory banking UI baselines.
            </p>
            <p className="text-xs text-slate-600 mt-1">
              {VIDE_BASELINE_SHORT_NAMES.length} baselines checked
              {confidence != null ? (
                <>
                  {' '}
                  · Confidence <span className="font-semibold tabular-nums">{formatVideConfidence(confidence)}</span>
                </>
              ) : null}
            </p>
            <p className="text-xs text-slate-500 mt-1">No sufficiently similar interface was identified.</p>
            {evidence.length > 0 && (
              <p className="text-[13px] text-slate-500 mt-1">Evidence: {evidence.join(' · ')}</p>
            )}
            <Link
              to={links.evidence}
              className="inline-flex items-center gap-1 text-xs text-blue-700 font-semibold hover:underline mt-2"
            >
              View visual evidence
              <span aria-hidden>→</span>
            </Link>
          </div>
        </div>
      </SocCard>
    );
  }

  const institution =
    compare?.institution_display || vide!.visual_impersonation_institution || 'Laboratory banking-style baseline';
  const ruleId = compare?.rule_id || 'VIDE-F001';

  // Prefer the tier the engine stamped on the verdict; derive it only for cases
  // analysed before the engine emitted one.
  const tier = vide!.visual_impersonation_tier || videConfidenceTier(confidence);
  const tierText = vide!.visual_impersonation_tier_label || videTierLabel(tier);
  const styles = videTierStyles(tier);

  const forensics = videForensics(vide!);
  const swatches = videColorSwatches(vide!);
  const matchedText = videMatchedText(vide!);
  const hierarchy = forensics?.view_hierarchy;
  const signatures = hierarchy?.matched_signatures || [];

  const caps: string[] = [];
  if (data.has_accessibility_abuse) caps.push('Accessibility abuse');
  if (data.has_system_alert_window) caps.push('Overlay capability');
  if (data.has_sms_read_write) caps.push('SMS read/write');

  return (
    <SocCard className={styles.card}>
      <div className="px-4 sm:px-5 py-4 border-b border-slate-200/80 bg-slate-50/60">
        <div className="flex items-start gap-3">
          <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${styles.icon}`}>
            <Eye className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Visual impersonation</p>
            <p className="text-lg font-semibold text-slate-900 truncate">{institution}</p>
            <p className="text-sm text-slate-600 mt-0.5">
              <span className="font-semibold tabular-nums">{formatVideConfidence(confidence)}</span> similarity
              <span className={`ml-2 rounded border px-1.5 py-0.5 text-[13px] font-semibold ${styles.chip}`}>
                {tierText}
              </span>
            </p>
          </div>
        </div>
      </div>

      <div className="px-4 sm:px-5 py-3 space-y-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`font-mono font-semibold border px-2 py-1 rounded ${styles.chip}`}>{ruleId}</span>
          <span className="text-slate-700 font-medium">Matched laboratory baseline</span>
        </div>

        {/*
          Why this is a clone, on the three axes the engine scores. Colour first:
          it is the axis that carries attribution, and a reader who can see the
          bank's own hex next to the suspect's can check the finding rather than
          take the score on trust.
        */}
        {swatches.length > 0 && (
          <div className="rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2.5">
            <div className="flex items-center gap-2 font-semibold text-slate-800">
              <Palette className="h-3.5 w-3.5 shrink-0" />
              Brand colour scheme
              {forensics?.color_scheme?.score != null && (
                <span className="font-normal text-slate-500 tabular-nums">
                  {formatVideConfidence(forensics.color_scheme.score)} match
                </span>
              )}
            </div>
            <ul className="mt-2 space-y-1.5">
              {swatches.map((sw) => (
                <li key={`${sw.baseline_hex}-${sw.suspect_hex}`} className="flex items-center gap-2">
                  <span
                    className="h-4 w-4 shrink-0 rounded border border-slate-300"
                    style={{ backgroundColor: sw.suspect_hex }}
                    aria-hidden
                  />
                  <span className="font-mono text-slate-800">{sw.suspect_hex}</span>
                  <span className="text-slate-400" aria-hidden>
                    &#8596;
                  </span>
                  <span
                    className="h-4 w-4 shrink-0 rounded border border-slate-300"
                    style={{ backgroundColor: sw.baseline_hex }}
                    aria-hidden
                  />
                  <span className="font-mono text-slate-800">{sw.baseline_hex}</span>
                  <span className="text-slate-500 tabular-nums">&#916;E {sw.delta_e.toFixed(1)}</span>
                  {sw.verdict && <span className="text-slate-500 truncate">&middot; {sw.verdict}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}

        {matchedText.length > 0 && (
          <div className="rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2.5">
            <div className="flex items-center gap-2 font-semibold text-slate-800">
              <Type className="h-3.5 w-3.5 shrink-0" />
              UI text &amp; strings
              {forensics?.ui_text != null && (
                <span className="font-normal text-slate-500 tabular-nums">
                  {forensics.ui_text.matched_count ?? matchedText.length}
                  {forensics.ui_text.target_count ? `/${forensics.ui_text.target_count}` : ''} labels
                </span>
              )}
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {matchedText.map((label) => (
                <span
                  key={label}
                  className="rounded border border-slate-300 bg-white px-1.5 py-0.5 text-slate-700"
                >
                  {label}
                </span>
              ))}
            </div>
          </div>
        )}

        {hierarchy?.score != null && (
          <div className="rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2.5">
            <div className="flex items-center gap-2 font-semibold text-slate-800">
              <LayoutTemplate className="h-3.5 w-3.5 shrink-0" />
              View hierarchy
              <span className="font-normal text-slate-500 tabular-nums">
                {formatVideConfidence(hierarchy.score)} structural similarity
              </span>
            </div>
            {signatures.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {signatures.map((sig) => (
                  <span
                    key={sig}
                    className="rounded border border-slate-300 bg-white px-1.5 py-0.5 font-mono text-slate-700"
                  >
                    {sig}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {vide!.critical_visual_cluster && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5">
            <div className="flex items-center gap-2 font-semibold text-red-800">
              <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
              Critical visual cluster
            </div>
            <p className="text-red-900/90 mt-1.5">Visual impersonation</p>
            {caps.length > 0 ? (
              <ul className="list-disc list-inside text-red-900/80 mt-1">
                {caps.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            ) : (
              <p className="text-red-900/80 mt-1">Plus qualifying high-risk capability evidence</p>
            )}
          </div>
        )}

        {vide!.signer_impersonation?.detected && (
          <div className="flex items-center gap-2 text-amber-800">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            CH06 signer impersonation signal
          </div>
        )}

        <Link
          to={links.evidence}
          className="inline-flex items-center gap-1 text-blue-700 font-semibold hover:underline"
        >
          View evidence
          <span aria-hidden>→</span>
        </Link>
      </div>
    </SocCard>
  );
}
