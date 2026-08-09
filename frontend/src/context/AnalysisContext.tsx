import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import type { FraudCardData } from '../App';
import { API_BASE, authHeaders } from '../config';
import { useInvestigationModel } from '../hooks/useInvestigationModel';
import type { InvestigationBundle } from '../types/investigation';
import { fetchScreenshotManifest, type ScreenshotManifestEntry } from '../lib/screenshotManifest';

interface AnalysisContextType {
  analysisResult: FraudCardData | null;
  activeSha256: string | null;
  loading: boolean;
  error: string | null;
  runtimeEvidenceRaw: Record<string, unknown>[];
  screenshotManifestEntries: ScreenshotManifestEntry[];
  investigationBundle: InvestigationBundle | null;
  setAnalysisResult: (data: FraudCardData | null) => void;
  loadCaseByHash: (sha256: string) => Promise<FraudCardData | null>;
  loadInvestigationBundle: (sha256: string) => Promise<void>;
  clearAnalysis: () => void;
}

const AnalysisContext = createContext<AnalysisContextType | undefined>(undefined);

/** Normalize legacy risk-engine SOC strings that used an em dash after the verb phrase. */
function normalizeRecommendedAction(text: string): string {
  return text.replace(/\s*\u2014\s*/g, ' - ');
}

function mapCaseDetailToFraudCard(caseDetail: Record<string, unknown>): FraudCardData {
  const dyn = (caseDetail.dynamic_analysis || caseDetail.dynamic_result) as FraudCardData['dynamic_analysis'];
  return {
    sha256: String(caseDetail.sha256),
    package_name: String(caseDetail.package_name || 'Unknown'),
    app_name: String(caseDetail.app_name || ''),
    analysis_mode: String(caseDetail.analysis_mode || 'static'),
    family_classification: String(caseDetail.family_classification || 'Unknown'),
    base_score: Number(caseDetail.base_score ?? caseDetail.final_risk_score ?? 0),
    ai_confidence_multiplier: Number(caseDetail.ai_confidence_multiplier ?? 1),
    final_risk_score: Number(caseDetail.final_risk_score ?? 0),
    risk_band: String(caseDetail.risk_band || 'Safe'),
    confidence: Number(caseDetail.confidence ?? 70),
    recommended_action: normalizeRecommendedAction(
      String(
        caseDetail.recommended_action ||
          (caseDetail.intelligence_report as { recommended_actions?: string[] })?.recommended_actions?.[0] ||
          'Monitor application',
      ),
    ),
    frs_breakdown: caseDetail.frs_breakdown as FraudCardData['frs_breakdown'],
    risk_explanation: caseDetail.risk_explanation as FraudCardData['risk_explanation'],
    threat_scenario_table: (caseDetail.threat_scenario_table as FraudCardData['threat_scenario_table']) || [],
    all_permissions: (caseDetail.all_permissions as string[]) || [],
    hardcoded_urls_ips: (caseDetail.hardcoded_urls_ips as string[]) || [],
    targets_indian_banks: Boolean(caseDetail.targets_indian_banks),
    has_accessibility_abuse: Boolean(caseDetail.has_accessibility_abuse),
    has_sms_read_write: Boolean(caseDetail.has_sms_read_write),
    has_system_alert_window: Boolean(caseDetail.has_system_alert_window),
    obfuscation_score: Number(caseDetail.obfuscation_score || 0),
    has_reflection: Boolean(caseDetail.has_reflection),
    threat_correlation: caseDetail.threat_correlation as FraudCardData['threat_correlation'],
    dynamic_available: Boolean(caseDetail.dynamic_available),
    dynamic_analysis: dyn,
    dynamic_result: (caseDetail.dynamic_result || caseDetail.dynamic_analysis) as FraudCardData['dynamic_result'],
    manifest_findings: (caseDetail.manifest_findings as FraudCardData['manifest_findings']) || [],
    code_findings: (caseDetail.code_findings as FraudCardData['code_findings']) || [],
    dangerous_permissions: (caseDetail.dangerous_permissions as FraudCardData['dangerous_permissions']) || [],
    activities: (caseDetail.activities as string[]) || [],
    services: (caseDetail.services as string[]) || [],
    receivers: (caseDetail.receivers as string[]) || [],
    certificate: (caseDetail.certificate as Record<string, unknown>) || {},
    domains: (caseDetail.domains as Record<string, unknown>) || {},
    hardcoded_secrets: (caseDetail.hardcoded_secrets as string[]) || [],
    intelligence_report: caseDetail.intelligence_report as FraudCardData['intelligence_report'],
    fraud_workflow: caseDetail.fraud_workflow as FraudCardData['fraud_workflow'],
    providers: (caseDetail.providers as string[]) || [],
    exported_activities: (caseDetail.exported_activities as string[]) || [],
    exported_services: (caseDetail.exported_services as string[]) || [],
    exported_receivers: (caseDetail.exported_receivers as string[]) || [],
    binary_analysis: caseDetail.binary_analysis as FraudCardData['binary_analysis'],
    network_security: caseDetail.network_security as Record<string, unknown>,
    trackers: caseDetail.trackers as FraudCardData['trackers'],
    emails: (caseDetail.emails as string[]) || [],
    apktool_enrichment: caseDetail.apktool_enrichment as FraudCardData['apktool_enrichment'],
    jadx_enrichment: caseDetail.jadx_enrichment as FraudCardData['jadx_enrichment'],
    vide: caseDetail.vide as FraudCardData['vide'],
    executive_view: (caseDetail.executive_view as FraudCardData['executive_view']) || {
      risk_badge: String(caseDetail.risk_band || 'Safe'),
      plain_english_narrative:
        (caseDetail.intelligence_report as { plain_english_narrative?: string })?.plain_english_narrative ||
        'Analysis completed.',
      recommended_actions: (
        (caseDetail.intelligence_report as { recommended_actions?: string[] })?.recommended_actions || []
      ).map(normalizeRecommendedAction),
      customer_advisory_draft:
        (caseDetail.intelligence_report as { customer_advisory_draft?: string })?.customer_advisory_draft || '',
    },
    technical_view: (caseDetail.technical_view as FraudCardData['technical_view']) || {
      permissions_fired: [],
      strings_fired: [],
      apis_fired: [],
      matched_rule: 'Standard Analysis',
      decoded_manifest_excerpts: [],
    },
  };
}

async function fetchRuntimeEvidence(sha256: string): Promise<Record<string, unknown>[]> {
  try {
    const res = await fetch(`${API_BASE}/cases/${sha256}/evidence`, { headers: authHeaders() });
    if (!res.ok) return [];
    const body = await res.json();
    return (body.evidence as Record<string, unknown>[]) || [];
  } catch {
    return [];
  }
}

export function AnalysisProvider({ children }: { children: React.ReactNode }) {
  const [analysisResult, setAnalysisState] = useState<FraudCardData | null>(null);
  const [runtimeEvidenceRaw, setRuntimeEvidenceRaw] = useState<Record<string, unknown>[]>([]);
  const [screenshotManifestEntries, setScreenshotManifestEntries] = useState<ScreenshotManifestEntry[]>([]);
  const [activeSha256, setActiveSha256] = useState<string | null>(() => {
    return sessionStorage.getItem('sudarshan_active_sha256');
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const investigationBundle = useInvestigationModel(
    analysisResult,
    runtimeEvidenceRaw,
    screenshotManifestEntries,
  );

  const refreshScreenshotManifest = useCallback(async (sha256: string) => {
    const manifest = await fetchScreenshotManifest(sha256, 'timeline');
    const list = manifest?.entries?.length ? manifest.entries : manifest?.screenshots || [];
    setScreenshotManifestEntries(list);
  }, []);

  const setAnalysisResult = useCallback((data: FraudCardData | null) => {
    setAnalysisState(data);
    if (data?.sha256) {
      setActiveSha256(data.sha256);
      sessionStorage.setItem('sudarshan_active_sha256', data.sha256);
      fetchRuntimeEvidence(data.sha256).then(setRuntimeEvidenceRaw);
      void refreshScreenshotManifest(data.sha256);
    } else {
      setActiveSha256(null);
      setRuntimeEvidenceRaw([]);
      setScreenshotManifestEntries([]);
      sessionStorage.removeItem('sudarshan_active_sha256');
    }
  }, [refreshScreenshotManifest]);

  const clearAnalysis = useCallback(() => {
    setAnalysisState(null);
    setActiveSha256(null);
    setRuntimeEvidenceRaw([]);
    setScreenshotManifestEntries([]);
    sessionStorage.removeItem('sudarshan_active_sha256');
  }, []);

  const loadInvestigationBundle = useCallback(async (sha256: string) => {
    const ev = await fetchRuntimeEvidence(sha256);
    setRuntimeEvidenceRaw(ev);
    await refreshScreenshotManifest(sha256);
  }, [refreshScreenshotManifest]);

  const loadCaseByHash = useCallback(async (sha256: string): Promise<FraudCardData | null> => {
    if (analysisResult?.sha256 === sha256 && runtimeEvidenceRaw.length > 0) {
      return analysisResult;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/cases/${sha256}`, {
        headers: authHeaders(),
      });

      if (!res.ok) {
        throw new Error(`Failed to load case ${sha256} (${res.status})`);
      }

      const caseDetail = await res.json();
      const fullData = mapCaseDetailToFraudCard(caseDetail);
      const ev = await fetchRuntimeEvidence(sha256);
      setRuntimeEvidenceRaw(ev);
      await refreshScreenshotManifest(sha256);
      setAnalysisResult(fullData);
      return fullData;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error restoring case data';
      setError(msg);
      return null;
    } finally {
      setLoading(false);
    }
  }, [refreshScreenshotManifest, setAnalysisResult]);

  useEffect(() => {
    if (activeSha256 && !analysisResult) {
      loadCaseByHash(activeSha256);
    }
  }, [activeSha256, analysisResult, loadCaseByHash]);

  const value = useMemo(
    () => ({
      analysisResult,
      activeSha256,
      loading,
      error,
      runtimeEvidenceRaw,
      screenshotManifestEntries,
      investigationBundle,
      setAnalysisResult,
      loadCaseByHash,
      loadInvestigationBundle,
      clearAnalysis,
    }),
    [
      analysisResult,
      activeSha256,
      loading,
      error,
      runtimeEvidenceRaw,
      screenshotManifestEntries,
      investigationBundle,
      setAnalysisResult,
      loadCaseByHash,
      loadInvestigationBundle,
      clearAnalysis,
    ],
  );

  return (
    <AnalysisContext.Provider value={value}>
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis() {
  const context = useContext(AnalysisContext);
  if (!context) {
    throw new Error('useAnalysis must be used within an AnalysisProvider');
  }
  return context;
}
