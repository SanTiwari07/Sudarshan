import type {
  FraudCardData,
  VideConfidenceTier,
  VideForensicBreakdown,
  VideForensicSwatch,
  VideResult,
} from '../types/case';

/** Short labels for lab baselines shipped in sudarshan_core/data/ui_baselines. */
export const VIDE_BASELINE_SHORT_NAMES = ['SBI', 'HDFC', 'ICICI'];

export type VideUiState = 'detected' | 'analyzed' | 'unavailable' | 'missing';

export function isVidePresent(vide?: VideResult | null): boolean {
  return Boolean(vide && typeof vide === 'object' && Object.keys(vide).length > 0);
}

export function getVideUiState(vide?: VideResult | null): VideUiState {
  if (!isVidePresent(vide)) return 'missing';
  if (vide!.available === false || vide!.status === 'UNAVAILABLE' || vide!.status === 'ERROR') {
    return 'unavailable';
  }
  const compare = vide!.vide_compare;
  const detected = Boolean(compare?.detected && vide!.visual_impersonation_detected);
  if (detected) return 'detected';
  return 'analyzed';
}

export function videConfidenceValue(vide: VideResult): number | undefined {
  const compare = vide.vide_compare;
  const raw = compare?.confidence ?? vide.visual_impersonation_confidence;
  if (raw == null || Number.isNaN(raw)) return undefined;
  return raw;
}

export function formatVideConfidence(confidence: number | undefined): string {
  if (confidence == null || Number.isNaN(confidence)) return '-';
  return `${(confidence * 100).toFixed(1)}%`;
}

/**
 * Confidence bands, mirroring `engines/vide/forensics.py`.
 *
 * Detection fires at 0.20, so a verdict spans everything from "wears this
 * bank's colours and little else" to "pixel-faithful clone". Rendering both as
 * the same red banner would overstate the weak end, which is the end an
 * analyst most needs to triage rather than act on.
 */
export const VIDE_DETECTION_THRESHOLD = 0.2;
export const VIDE_TIER_HIGH = 0.6;
export const VIDE_TIER_MODERATE = 0.35;

export function videConfidenceTier(confidence: number | undefined): VideConfidenceTier {
  if (confidence == null || Number.isNaN(confidence)) return 'none';
  if (confidence >= VIDE_TIER_HIGH) return 'high';
  if (confidence >= VIDE_TIER_MODERATE) return 'moderate';
  if (confidence >= VIDE_DETECTION_THRESHOLD) return 'low';
  return 'none';
}

export function videTierLabel(tier: VideConfidenceTier): string {
  switch (tier) {
    case 'high':
      return 'High similarity';
    case 'moderate':
      return 'Moderate similarity';
    case 'low':
      return 'Low / suspicious impersonation';
    default:
      return 'Below detection threshold';
  }
}

/** Tailwind classes per tier, so severity reads at a glance without a legend. */
export function videTierStyles(tier: VideConfidenceTier): {
  card: string;
  chip: string;
  icon: string;
} {
  switch (tier) {
    case 'high':
      return {
        card: 'border-red-200/60',
        chip: 'bg-red-50 text-red-800 border-red-200',
        icon: 'bg-red-100 text-red-700 border-red-200/80',
      };
    case 'moderate':
      return {
        card: 'border-orange-200/60',
        chip: 'bg-orange-50 text-orange-800 border-orange-200',
        icon: 'bg-orange-100 text-orange-700 border-orange-200/80',
      };
    case 'low':
      return {
        card: 'border-amber-200/60',
        chip: 'bg-amber-50 text-amber-800 border-amber-200',
        icon: 'bg-amber-100 text-amber-800 border-amber-200/80',
      };
    default:
      return {
        card: 'border-slate-200/80',
        chip: 'bg-slate-50 text-slate-700 border-slate-200',
        icon: 'bg-slate-100 text-slate-600 border-slate-200/80',
      };
  }
}

/**
 * The forensic breakdown for this case, wherever the payload carries it.
 *
 * The engine puts it at the top level and on each comparer's result; older
 * payloads have none. Falling back through them keeps a card written against
 * the new shape working on a case analysed before it existed.
 */
export function videForensics(vide: VideResult): VideForensicBreakdown | undefined {
  const breakdown =
    vide.forensic_breakdown ||
    vide.vide_compare?.forensics ||
    vide.corpus_compare?.forensics;
  if (!breakdown || Object.keys(breakdown).length === 0) return undefined;
  return breakdown;
}

/** Swatch pairs to render, strongest match first. */
export function videColorSwatches(vide: VideResult, limit = 6): VideForensicSwatch[] {
  const matches = videForensics(vide)?.color_scheme?.matches;
  if (matches?.length) return matches.slice(0, limit);

  // Pre-breakdown payloads carried the raw palette matches instead.
  const legacy = vide.corpus_compare?.color_matches || [];
  return legacy.slice(0, limit).map((m) => {
    const deltaE = m.delta_e ?? m.distance ?? 0;
    return {
      baseline_hex: (m.baseline || '').toUpperCase(),
      suspect_hex: (m.suspect || '').toUpperCase(),
      delta_e: deltaE,
      score: m.score ?? 0,
      verdict: m.verdict ?? '',
      exact: (m.baseline || '').toLowerCase() === (m.suspect || '').toLowerCase(),
    };
  });
}

/** Banking labels the suspect reproduced, for the UI-elements badge row. */
export function videMatchedText(vide: VideResult, limit = 8): string[] {
  const forensic = videForensics(vide)?.ui_text?.matched_strings;
  const matched =
    forensic?.length ? forensic : vide.vide_compare?.matched_strings || vide.corpus_compare?.matched_strings || [];
  return matched.slice(0, limit);
}

export function videEvidenceSources(vide: VideResult): string[] {
  const sources: string[] = [];
  const summary = vide.suspect_profile_summary?.sources;
  if (summary) {
    if (summary.includes('apktool') || summary.includes('layout')) sources.push('Static UI');
    if (summary.includes('webview') || summary.includes('dynamic')) sources.push('WebView');
  } else {
    sources.push('Static UI');
  }
  if (vide.ui_hierarchy_integrated) sources.push('WebView');
  if (vide.signer_impersonation) sources.push('Signer');
  return [...new Set(sources)];
}

export function resolveVideFromData(data: FraudCardData): VideResult | undefined {
  const vide = data.vide;
  if (!isVidePresent(vide)) return undefined;
  return vide;
}
