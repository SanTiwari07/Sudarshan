import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { FraudCardData } from '../App';
import { API_BASE, authHeaders } from '../config';

interface AnalysisContextType {
  analysisResult: FraudCardData | null;
  activeSha256: string | null;
  loading: boolean;
  error: string | null;
  setAnalysisResult: (data: FraudCardData | null) => void;
  loadCaseByHash: (sha256: string) => Promise<FraudCardData | null>;
  clearAnalysis: () => void;
}

const AnalysisContext = createContext<AnalysisContextType | undefined>(undefined);

export function AnalysisProvider({ children }: { children: React.ReactNode }) {
  const [analysisResult, setAnalysisState] = useState<FraudCardData | null>(null);
  const [activeSha256, setActiveSha256] = useState<string | null>(() => {
    return sessionStorage.getItem('sudarshan_active_sha256');
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const setAnalysisResult = useCallback((data: FraudCardData | null) => {
    setAnalysisState(data);
    if (data?.sha256) {
      setActiveSha256(data.sha256);
      sessionStorage.setItem('sudarshan_active_sha256', data.sha256);
    } else {
      setActiveSha256(null);
      sessionStorage.removeItem('sudarshan_active_sha256');
    }
  }, []);

  const clearAnalysis = useCallback(() => {
    setAnalysisState(null);
    setActiveSha256(null);
    sessionStorage.removeItem('sudarshan_active_sha256');
  }, []);

  const loadCaseByHash = useCallback(async (sha256: string): Promise<FraudCardData | null> => {
    if (analysisResult?.sha256 === sha256) {
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
      
      // Adapt CaseDetail into FraudCardData structure if missing full static payload
      const fullData: FraudCardData = {
        sha256: caseDetail.sha256,
        package_name: caseDetail.package_name || 'Unknown',
        app_name: caseDetail.app_name || '',
        analysis_mode: caseDetail.analysis_mode || 'static',
        family_classification: caseDetail.family_classification || 'Unknown',
        base_score: caseDetail.final_risk_score || 0,
        ai_confidence_multiplier: 1.0,
        final_risk_score: caseDetail.final_risk_score || 0,
        risk_band: caseDetail.risk_band || 'Safe',
        confidence: caseDetail.confidence || 70,
        recommended_action: caseDetail.intelligence_report?.recommended_actions?.[0] || 'Monitor application',
        frs_breakdown: caseDetail.frs_breakdown,
        threat_scenario_table: caseDetail.threat_scenario_table,
        all_permissions: caseDetail.all_permissions || [],
        hardcoded_urls_ips: caseDetail.hardcoded_urls_ips || [],
        targets_indian_banks: caseDetail.targets_indian_banks || false,
        has_accessibility_abuse: caseDetail.has_accessibility_abuse || false,
        has_sms_read_write: caseDetail.has_sms_read_write || false,
        has_system_alert_window: caseDetail.has_system_alert_window || false,
        obfuscation_score: caseDetail.obfuscation_score || 0,
        has_reflection: caseDetail.has_reflection || false,
        threat_correlation: caseDetail.threat_correlation,
        dynamic_available: caseDetail.dynamic_available || false,
        dynamic_analysis: caseDetail.dynamic_analysis,
        manifest_findings: caseDetail.manifest_findings || [],
        code_findings: caseDetail.code_findings || [],
        dangerous_permissions: caseDetail.dangerous_permissions || [],
        activities: caseDetail.activities || [],
        services: caseDetail.services || [],
        receivers: caseDetail.receivers || [],
        certificate: caseDetail.certificate || {},
        domains: caseDetail.domains || {},
        hardcoded_secrets: caseDetail.hardcoded_secrets || [],
        intelligence_report: caseDetail.intelligence_report,
        fraud_workflow: caseDetail.fraud_workflow,
        executive_view: caseDetail.executive_view || {
          risk_badge: caseDetail.risk_band || 'Safe',
          plain_english_narrative: caseDetail.intelligence_report?.plain_english_narrative || 'Analysis completed.',
          recommended_actions: caseDetail.intelligence_report?.recommended_actions || [],
          customer_advisory_draft: caseDetail.intelligence_report?.customer_advisory_draft || '',
        },
        technical_view: caseDetail.technical_view || {
          permissions_fired: [],
          strings_fired: [],
          apis_fired: [],
          matched_rule: 'Standard Analysis',
          decoded_manifest_excerpts: [],
        },
      };

      setAnalysisResult(fullData);
      return fullData;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error restoring case data';
      setError(msg);
      return null;
    } finally {
      setLoading(false);
    }
  }, [analysisResult, setAnalysisResult]);

  // Restore on mount/reload if session has an active SHA256 and result is null
  useEffect(() => {
    if (activeSha256 && !analysisResult) {
      loadCaseByHash(activeSha256);
    }
  }, [activeSha256, analysisResult, loadCaseByHash]);

  return (
    <AnalysisContext.Provider
      value={{
        analysisResult,
        activeSha256,
        loading,
        error,
        setAnalysisResult,
        loadCaseByHash,
        clearAnalysis,
      }}
    >
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
