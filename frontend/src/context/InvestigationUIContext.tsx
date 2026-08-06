import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { LedgerScope } from '../types/investigation';

type InvestigationUIContextValue = {
  ledgerOpen: boolean;
  ledgerScope: LedgerScope;
  openLedger: (scope?: LedgerScope) => void;
  closeLedger: () => void;
  drawerEvidenceId: string | null;
  openEvidence: (id: string) => void;
  closeEvidence: () => void;
  timelineFocusMs: number | null;
  setTimelineFocus: (ms: number | null) => void;
};

const InvestigationUIContext = createContext<InvestigationUIContextValue | null>(null);

export function InvestigationUIProvider({ children }: { children: React.ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [ledgerOpen, setLedgerOpen] = useState(false);
  const [ledgerScope, setLedgerScope] = useState<LedgerScope>('full');
  const [drawerEvidenceId, setDrawerEvidenceId] = useState<string | null>(null);
  const [timelineFocusMs, setTimelineFocusMs] = useState<number | null>(null);

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

  const openLedger = useCallback((scope: LedgerScope = 'full') => {
    setLedgerScope(scope);
    setLedgerOpen(true);
  }, []);

  const closeLedger = useCallback(() => setLedgerOpen(false), []);

  const openEvidence = useCallback(
    (id: string) => {
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

  const value = useMemo(
    () => ({
      ledgerOpen,
      ledgerScope,
      openLedger,
      closeLedger,
      drawerEvidenceId,
      openEvidence,
      closeEvidence,
      timelineFocusMs,
      setTimelineFocus: setTimelineFocusMs,
    }),
    [
      ledgerOpen,
      ledgerScope,
      openLedger,
      closeLedger,
      drawerEvidenceId,
      openEvidence,
      closeEvidence,
      timelineFocusMs,
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
