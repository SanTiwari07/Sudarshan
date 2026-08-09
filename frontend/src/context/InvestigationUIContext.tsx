import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { LedgerScope } from '../types/investigation';
import type { TechnicalFindingId } from '../lib/technicalFindings';
import type { ScoreInfluenceAxis } from '../lib/scoreInfluenceModel';

type InvestigationUIContextValue = {
  ledgerOpen: boolean;
  ledgerScope: LedgerScope;
  openLedger: (scope?: LedgerScope) => void;
  closeLedger: () => void;
  drawerEvidenceId: string | null;
  openEvidence: (id: string) => void;
  closeEvidence: () => void;
  explanationFindingId: TechnicalFindingId | null;
  findingEvidenceId: TechnicalFindingId | null;
  openFindingExplanation: (id: TechnicalFindingId) => void;
  openFindingEvidence: (id: TechnicalFindingId) => void;
  closeFindingExplanation: () => void;
  closeFindingEvidence: () => void;
  timelineFocusMs: number | null;
  setTimelineFocus: (ms: number | null) => void;
  influenceDetailOpen: boolean;
  influenceAxis: ScoreInfluenceAxis | null;
  openInfluenceDetail: (axis: ScoreInfluenceAxis) => void;
  closeInfluenceDetail: () => void;
};

const InvestigationUIContext = createContext<InvestigationUIContextValue | null>(null);

export function InvestigationUIProvider({ children }: { children: React.ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [ledgerOpen, setLedgerOpen] = useState(false);
  const [ledgerScope, setLedgerScope] = useState<LedgerScope>('full');
  const [drawerEvidenceId, setDrawerEvidenceId] = useState<string | null>(null);
  const [explanationFindingId, setExplanationFindingId] = useState<TechnicalFindingId | null>(null);
  const [findingEvidenceId, setFindingEvidenceId] = useState<TechnicalFindingId | null>(null);
  const [timelineFocusMs, setTimelineFocusMs] = useState<number | null>(null);
  const [influenceDetailOpen, setInfluenceDetailOpen] = useState(false);
  const [influenceAxis, setInfluenceAxis] = useState<ScoreInfluenceAxis | null>(null);

  useEffect(() => {
    const ev = searchParams.get('evidence');
    const ledger = searchParams.get('ledger');
    if (ev) {
      setDrawerEvidenceId(ev);
    }
    if (ledger) {
      setLedgerOpen(true);
      setLedgerScope(ledger as LedgerScope);
    }
  }, [searchParams]);

  const closeFindingExplanation = useCallback(() => setExplanationFindingId(null), []);
  const closeFindingEvidence = useCallback(() => setFindingEvidenceId(null), []);

  const openLedger = useCallback((scope: LedgerScope = 'full') => {
    setLedgerScope(scope);
    setLedgerOpen(true);
  }, []);

  const closeLedger = useCallback(() => setLedgerOpen(false), []);

  const openEvidence = useCallback(
    (id: string) => {
      setExplanationFindingId(null);
      setFindingEvidenceId(null);
      setDrawerEvidenceId(id);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('evidence', id);
        return next;
      });
    },
    [setSearchParams],
  );

  const closeEvidence = useCallback(() => {
    setDrawerEvidenceId(null);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('evidence');
      return next;
    });
  }, [setSearchParams]);

  const openFindingExplanation = useCallback(
    (id: TechnicalFindingId) => {
      setFindingEvidenceId(null);
      setDrawerEvidenceId(null);
      setExplanationFindingId(id);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.delete('evidence');
        return next;
      });
    },
    [setSearchParams],
  );

  const openFindingEvidence = useCallback(
    (id: TechnicalFindingId) => {
      setExplanationFindingId(null);
      setDrawerEvidenceId(null);
      setFindingEvidenceId(id);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.delete('evidence');
        return next;
      });
    },
    [setSearchParams],
  );

  const openInfluenceDetail = useCallback((axis: ScoreInfluenceAxis) => {
    setInfluenceAxis(axis);
    setInfluenceDetailOpen(true);
  }, []);

  const closeInfluenceDetail = useCallback(() => {
    setInfluenceDetailOpen(false);
    setInfluenceAxis(null);
  }, []);

  const value = useMemo(
    () => ({
      ledgerOpen,
      ledgerScope,
      openLedger,
      closeLedger,
      drawerEvidenceId,
      openEvidence,
      closeEvidence,
      explanationFindingId,
      findingEvidenceId,
      openFindingExplanation,
      openFindingEvidence,
      closeFindingExplanation,
      closeFindingEvidence,
      timelineFocusMs,
      setTimelineFocus: setTimelineFocusMs,
      influenceDetailOpen,
      influenceAxis,
      openInfluenceDetail,
      closeInfluenceDetail,
    }),
    [
      ledgerOpen,
      ledgerScope,
      openLedger,
      closeLedger,
      drawerEvidenceId,
      openEvidence,
      closeEvidence,
      explanationFindingId,
      findingEvidenceId,
      openFindingExplanation,
      openFindingEvidence,
      closeFindingExplanation,
      closeFindingEvidence,
      timelineFocusMs,
      influenceDetailOpen,
      influenceAxis,
      openInfluenceDetail,
      closeInfluenceDetail,
    ],
  );

  return (
    <InvestigationUIContext.Provider value={value}>{children}</InvestigationUIContext.Provider>
  );
}

export function useInvestigationUI() {
  const ctx = useContext(InvestigationUIContext);
  if (!ctx) {
    throw new Error('useInvestigationUI must be used within InvestigationUIProvider');
  }
  return ctx;
}
