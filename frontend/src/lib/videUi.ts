import type { FraudCardData, VideResult } from '../App';

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
