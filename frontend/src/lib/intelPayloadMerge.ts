import type { FraudCardData, ThreatCorrelation } from '../App';
import type { IntelApiPayload } from './threatIntelModel';

export type ProviderUiStatus = 'available' | 'no_result' | 'unavailable' | 'error' | 'loading';

export type MergedThreatIntel = {
  virusTotal: IntelApiPayload['virus_total'];
  alienvault: IntelApiPayload['alienvault'];
  abuseipdb: IntelApiPayload['abuseipdb'];
  sourcesStatus: IntelApiPayload['sources_status'];
  threatScore: number | null;
  correlationScore: number | null;
  axisIncluded: boolean;
  iocsFromCase: FraudCardData['threat_correlation'] extends infer T ? T extends { ioc_reputation: infer I } ? I : never : never;
};

function sourcesQueried(corr: ThreatCorrelation | undefined, pattern: RegExp): boolean {
  return Boolean(corr?.sources_queried?.some((s) => pattern.test(s)));
}

/** Case payload has hash-level VT outcome recorded (not merely available / sources_queried). */
export function isVtCaseDetailComplete(corr: ThreatCorrelation | undefined): boolean {
  if (!sourcesQueried(corr, /virustotal/i)) return false;
  if (!corr) return false;
  return Number.isFinite(corr.sha256_detections) && Number.isFinite(corr.sha256_total);
}

/** OTX pulse / association fields on case IOCs or merged intel block. */
export function isOtxCaseDetailComplete(corr: ThreatCorrelation | undefined): boolean {
  if (!sourcesQueried(corr, /otx|alienvault/i)) return false;
  if (!corr) return false;
  return corr.ioc_reputation?.some((i) => i.otx_pulses != null) ?? false;
}

/** AbuseIPDB confidence on relevant IOCs when IPs were in scope. */
export function isAbuseCaseDetailComplete(corr: ThreatCorrelation | undefined): boolean {
  if (!sourcesQueried(corr, /abuseipdb/i)) return false;
  if (!corr) return false;
  const ipIocs =
    corr.ioc_reputation?.filter((i) => i.type?.toUpperCase() === 'IP' || i.type?.toUpperCase() === 'IPV4') ?? [];
  const ips = corr.malicious_ips ?? [];
  if (ipIocs.length === 0 && ips.length === 0) return true;
  return corr.ioc_reputation?.some((i) => i.abuse_score != null) ?? false;
}

export function intelApiNeededForCase(data: FraudCardData): boolean {
  const corr = data.threat_correlation;
  return !(
    isVtCaseDetailComplete(corr) &&
    isOtxCaseDetailComplete(corr) &&
    isAbuseCaseDetailComplete(corr)
  );
}

function vtFromCase(corr: ThreatCorrelation): IntelApiPayload['virus_total'] {
  return {
    available: sourcesQueried(corr, /virustotal/i),
    malicious: corr.sha256_detections ?? 0,
    total: corr.sha256_total ?? 0,
    ratio: corr.vt_detection_ratio ?? 0,
    permalink: '',
    vendors: corr.vt_malicious_vendors ?? [],
    reputation: 0,
    suggested_label: corr.known_family ?? undefined,
  };
}

function otxFromCase(corr: ThreatCorrelation): IntelApiPayload['alienvault'] {
  const pulses = corr.ioc_reputation?.reduce((max, i) => Math.max(max, i.otx_pulses ?? 0), 0) ?? 0;
  return {
    available: sourcesQueried(corr, /otx|alienvault/i),
    pulse_count: pulses,
    campaign: corr.campaign || 'None',
    pulses: [],
  };
}

function abuseFromCase(corr: ThreatCorrelation): IntelApiPayload['abuseipdb'] {
  const scores = corr.ioc_reputation?.map((i) => i.abuse_score).filter((s): s is number => s != null) ?? [];
  const maxConf = scores.length ? Math.max(...scores) : 0;
  return {
    available: sourcesQueried(corr, /abuseipdb/i),
    confidence: maxConf,
    reports: scores.length,
  };
}

function prefer<T>(caseVal: T | null | undefined, apiVal: T | null | undefined): T | null | undefined {
  if (caseVal != null && caseVal !== '' && !(Array.isArray(caseVal) && caseVal.length === 0 && Array.isArray(apiVal) && apiVal.length > 0)) {
    return caseVal;
  }
  return apiVal ?? caseVal;
}

function mergeVt(
  caseBlock: IntelApiPayload['virus_total'],
  apiBlock: IntelApiPayload['virus_total'] | undefined,
): IntelApiPayload['virus_total'] {
  if (!apiBlock) return caseBlock;
  return {
    available: caseBlock.available || apiBlock.available,
    malicious: prefer(caseBlock.malicious, apiBlock.malicious) ?? 0,
    total: prefer(caseBlock.total, apiBlock.total) ?? 0,
    ratio: caseBlock.ratio > 0 ? caseBlock.ratio : apiBlock.ratio ?? caseBlock.ratio,
    permalink: apiBlock.permalink || caseBlock.permalink,
    vendors: caseBlock.vendors?.length ? caseBlock.vendors : apiBlock.vendors ?? [],
    reputation: apiBlock.reputation ?? caseBlock.reputation,
    suggested_label: prefer(caseBlock.suggested_label, apiBlock.suggested_label) ?? undefined,
  };
}

function mergeOtx(
  caseBlock: IntelApiPayload['alienvault'],
  apiBlock: IntelApiPayload['alienvault'] | undefined,
): IntelApiPayload['alienvault'] {
  if (!apiBlock) return caseBlock;
  return {
    available: caseBlock.available || apiBlock.available,
    pulse_count: caseBlock.pulse_count > 0 ? caseBlock.pulse_count : apiBlock.pulse_count ?? caseBlock.pulse_count,
    campaign: prefer(caseBlock.campaign !== 'None' ? caseBlock.campaign : null, apiBlock.campaign) || 'None',
    pulses: apiBlock.pulses?.length ? apiBlock.pulses : caseBlock.pulses,
  };
}

function mergeAbuse(
  caseBlock: IntelApiPayload['abuseipdb'],
  apiBlock: IntelApiPayload['abuseipdb'] | undefined,
): IntelApiPayload['abuseipdb'] {
  if (!apiBlock) return caseBlock;
  return {
    available: caseBlock.available || apiBlock.available,
    confidence: caseBlock.confidence > 0 ? caseBlock.confidence : apiBlock.confidence ?? caseBlock.confidence,
    reports: caseBlock.reports > 0 ? caseBlock.reports : apiBlock.reports ?? caseBlock.reports,
  };
}

export function mergeIntelWithCase(data: FraudCardData, api: IntelApiPayload | null): MergedThreatIntel {
  const corr = data.threat_correlation;
  const frs = data.frs_breakdown;
  const axisIncluded = Boolean(frs && !frs.axes_excluded?.includes('correlation'));

  const emptyVt: IntelApiPayload['virus_total'] = {
    available: false,
    malicious: 0,
    total: 0,
    ratio: 0,
    permalink: '',
    vendors: [],
    reputation: 0,
  };
  const emptyOtx: IntelApiPayload['alienvault'] = {
    available: false,
    pulse_count: 0,
    campaign: 'None',
    pulses: [],
  };
  const emptyAbuse: IntelApiPayload['abuseipdb'] = {
    available: false,
    confidence: 0,
    reports: 0,
  };

  const caseVt = corr ? vtFromCase(corr) : emptyVt;
  const caseOtx = corr ? otxFromCase(corr) : emptyOtx;
  const caseAbuse = corr ? abuseFromCase(corr) : emptyAbuse;

  return {
    virusTotal: mergeVt(caseVt, api?.virus_total),
    alienvault: mergeOtx(caseOtx, api?.alienvault),
    abuseipdb: mergeAbuse(caseAbuse, api?.abuseipdb),
    sourcesStatus: api?.sources_status?.length ? api.sources_status : [],
    threatScore: corr?.threat_score ?? api?.threat_score ?? null,
    correlationScore: frs?.correlation ?? null,
    axisIncluded,
    iocsFromCase: corr?.ioc_reputation ?? [],
  };
}

function sourceStatusFor(
  merged: MergedThreatIntel,
  pattern: RegExp,
): { status: string; message: string } | undefined {
  return merged.sourcesStatus.find((s) => pattern.test(s.name));
}

export function providerUiStatus(
  provider: 'virustotal' | 'otx' | 'abuseipdb',
  merged: MergedThreatIntel,
  fetchState: 'idle' | 'loading' | 'error',
): ProviderUiStatus {
  if (fetchState === 'loading') return 'loading';

  const pattern =
    provider === 'virustotal' ? /virustotal/i : provider === 'otx' ? /otx|alienvault/i : /abuseipdb/i;
  const src = sourceStatusFor(merged, pattern);

  if (src?.status === 'error') return 'error';
  if (src?.status === 'missing_key') return 'unavailable';

  if (provider === 'virustotal') {
    const vt = merged.virusTotal;
    if (!vt.available && fetchState === 'error') return 'error';
    if (!vt.available) return 'unavailable';
    if (vt.malicious > 0 || vt.total > 0) return 'available';
    return 'no_result';
  }

  if (provider === 'otx') {
    const otx = merged.alienvault;
    if (!otx.available && fetchState === 'error') return 'error';
    if (!otx.available) return 'unavailable';
    if (otx.pulse_count > 0 || (otx.pulses?.length ?? 0) > 0) return 'available';
    return 'no_result';
  }

  const abuse = merged.abuseipdb;
  if (!abuse.available && fetchState === 'error') return 'error';
  if (!abuse.available) return 'unavailable';
  if (abuse.confidence > 0 || abuse.reports > 0) return 'available';
  return 'no_result';
}

export const PROVIDER_STATUS_LABEL: Record<ProviderUiStatus, string> = {
  available: 'Available',
  no_result: 'No result',
  unavailable: 'Unavailable',
  error: 'Error',
  loading: 'Loading',
};
