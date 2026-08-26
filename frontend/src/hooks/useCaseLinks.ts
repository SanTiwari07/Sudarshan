import { useMemo } from 'react';
import { useAnalysis } from '../context/AnalysisContext';
import { caseRoutes, type CaseRoutes } from '../lib/caseRoutes';

/**
 * Section links for the case currently loaded.
 *
 * Components deep inside the investigation link across to sibling sections -
 * "inspect runtime analysis", "view threat intelligence" - and most of them do
 * not otherwise need the case object. Reading the sha here keeps those call
 * sites from having to thread `data` down purely to build a URL.
 *
 * Falls back to the legacy case-less paths when no case is loaded. Those are
 * permanent redirects, so the link still resolves rather than 404ing; it just
 * cannot name the case until one is open.
 */
export function useCaseLinks(): CaseRoutes {
  const { analysisResult, activeSha256 } = useAnalysis();
  const sha = analysisResult?.sha256 || activeSha256;

  return useMemo(() => {
    if (sha) return caseRoutes(sha);
    return {
      root: '/fraud-card',
      summary: '/fraud-card',
      evidence: '/technical',
      intel: '/threat-intel',
      ask: '/chat',
    };
  }, [sha]);
}
