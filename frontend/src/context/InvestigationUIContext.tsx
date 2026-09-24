import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { LedgerScope } from '../types/investigation';
import type { TechnicalFindingId } from '../lib/technicalFindings';
import type { ScoreInfluenceAxis } from '../lib/scoreInfluenceModel';

/**
 * Investigation overlay state, as a stack.
 *
 * Previously this held five independent booleans and ids, and they did not
 * coordinate. `openEvidence` cleared two of its siblings but not the score
 * ledger or the influence detail; `openLedger` and `openInfluenceDetail`
 * cleared nothing at all. Since the ledger opens evidence and the influence
 * detail opens the ledger, three overlays could be live at once, layered by
 * whatever z-index each had hand-rolled, with no way back to the one
 * underneath - closing the top one just revealed a panel the reader had
 * already mentally left.
 *
 * Modelling it as a stack keeps the drill-downs, which are deliberate and
 * useful, and makes "back" mean something. Only the top of the stack renders.
 *
 * The five original open/close functions and every derived selector are kept
 * exactly as they were, so all twenty-one existing call sites are untouched by
 * this change. They are now thin wrappers over push/pop.
 */

/**
 * How much of the investigation to show by default.
 *
 * The same case has to serve a bank manager with twenty seconds, an analyst
 * with twenty minutes and an engineer who wants the raw Frida records. Building
 * three products would guarantee they drift apart and disagree; this is one
 * product with one default-visibility setting.
 *
 * It is NOT a permission system. Every reader can still reach every level - the
 * setting decides what is open on arrival, not what exists.
 */
export type CaseDepth = 'summary' | 'analyst' | 'forensic';

export const CASE_DEPTHS: CaseDepth[] = ['summary', 'analyst', 'forensic'];

/*
 * Depth is now fixed at the deepest level, and there is no switch.
 *
 * The Detail control that used to set this was removed from the case bar. That
 * left a choice with no chooser, and the old default - 'summary' - was the one
 * that hides things: the raw section on the technical view (logcat, Frida
 * events, binary analysis), the counts strip on the case summary, and the
 * MITRE technique id on each attack stage. Keeping that default would have
 * turned "remove a control" into "delete evidence from the product", which is
 * not the same edit.
 *
 * The stored value is deliberately not read any more. Nothing can write it
 * now, so all it could do is pin a returning reader to whatever they last
 * picked - including 'summary' - with no way back.
 */
const FIXED_DEPTH: CaseDepth = 'forensic';

export type DrawerRequest =
  | { kind: 'evidence'; id: string }
  | { kind: 'finding-explanation'; id: TechnicalFindingId }
  | { kind: 'finding-evidence'; id: TechnicalFindingId }
  | { kind: 'score-influence'; axis: ScoreInfluenceAxis }
  | { kind: 'score-ledger'; scope: LedgerScope }
  | { kind: 'workflow-stage'; stageIndex: number }
  | { kind: 'target-detail' };

type InvestigationUIContextValue = {
  /** Full stack, oldest first. Only the last entry renders. */
  drawerStack: DrawerRequest[];
  activeDrawer: DrawerRequest | null;
  /** True when closing the active drawer reveals another one. */
  canGoBack: boolean;
  pushDrawer: (req: DrawerRequest) => void;
  /** Pop one level. Reveals the drawer underneath, if any. */
  closeDrawer: () => void;
  closeAllDrawers: () => void;

  // ── Legacy surface, derived from the stack ──────────────────────────────
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

  depth: CaseDepth;
  /** True when at least the analyst level is shown. Fixed true. */
  atLeastAnalyst: boolean;
  /** True at the deepest level. Fixed true - raw forensic dumps always show. */
  isForensic: boolean;
  influenceDetailOpen: boolean;
  influenceAxis: ScoreInfluenceAxis | null;
  openInfluenceDetail: (axis: ScoreInfluenceAxis) => void;
  closeInfluenceDetail: () => void;
  openWorkflowStage: (stageIndex: number) => void;
  openTargetDetail: () => void;
};

const InvestigationUIContext = createContext<InvestigationUIContextValue | null>(null);

function sameRequest(a: DrawerRequest | undefined, b: DrawerRequest): boolean {
  if (!a || a.kind !== b.kind) return false;
  if (a.kind === 'score-influence' && b.kind === 'score-influence') return a.axis === b.axis;
  if (a.kind === 'score-ledger' && b.kind === 'score-ledger') return a.scope === b.scope;
  if (a.kind === 'workflow-stage' && b.kind === 'workflow-stage') return a.stageIndex === b.stageIndex;
  if (a.kind === 'target-detail' && b.kind === 'target-detail') return true;
  if ('id' in a && 'id' in b) return a.id === b.id;
  return false;
}

export function InvestigationUIProvider({ children }: { children: React.ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [stack, setStack] = useState<DrawerRequest[]>([]);
  const [timelineFocusMs, setTimelineFocusMs] = useState<number | null>(null);

  const activeDrawer = stack.length > 0 ? stack[stack.length - 1] : null;

  const pushDrawer = useCallback((req: DrawerRequest) => {
    setStack((prev) => {
      // Re-opening what is already on top is a no-op rather than a duplicate
      // stack entry that would need two closes to dismiss.
      if (sameRequest(prev[prev.length - 1], req)) return prev;
      return [...prev, req];
    });
  }, []);

  const closeDrawer = useCallback(() => {
    setStack((prev) => prev.slice(0, -1));
  }, []);

  const closeAllDrawers = useCallback(() => setStack([]), []);

  /*
   * URL sync, one direction at a time.
   *
   * `?evidence=` and `?ledger=` are deep-link entry points. This effect only
   * reads them: it pushes when the URL names something that is not already on
   * top. Writing back on every push would fight the router and put a stack
   * entry in history for each drill-down step.
   */
  useEffect(() => {
    const ev = searchParams.get('evidence');
    const ledger = searchParams.get('ledger');
    if (ev) {
      pushDrawer({ kind: 'evidence', id: ev });
    } else if (ledger) {
      pushDrawer({ kind: 'score-ledger', scope: ledger as LedgerScope });
    }
  }, [searchParams, pushDrawer]);

  const clearEvidenceParam = useCallback(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete('evidence');
        next.delete('ledger');
        return next;
      },
      { replace: true },
    );
  }, [setSearchParams]);

  // ── Legacy wrappers ───────────────────────────────────────────────────────

  const openEvidence = useCallback(
    (id: string) => pushDrawer({ kind: 'evidence', id }),
    [pushDrawer],
  );

  const openFindingExplanation = useCallback(
    (id: TechnicalFindingId) => pushDrawer({ kind: 'finding-explanation', id }),
    [pushDrawer],
  );

  const openFindingEvidence = useCallback(
    (id: TechnicalFindingId) => pushDrawer({ kind: 'finding-evidence', id }),
    [pushDrawer],
  );

  const openInfluenceDetail = useCallback(
    (axis: ScoreInfluenceAxis) => pushDrawer({ kind: 'score-influence', axis }),
    [pushDrawer],
  );

  const openLedger = useCallback(
    (scope: LedgerScope = 'full') => pushDrawer({ kind: 'score-ledger', scope }),
    [pushDrawer],
  );

  /*
   * Every legacy close pops one level.
   *
   * A drawer only ever calls its own close, and a drawer only renders when it
   * is on top, so "pop" and "close me" are the same operation. Routing them all
   * through one function is what keeps the stack honest.
   */
  const popAndClearParams = useCallback(() => {
    closeDrawer();
    if (searchParams.has('evidence') || searchParams.has('ledger')) {
      clearEvidenceParam();
    }
  }, [closeDrawer, clearEvidenceParam, searchParams]);

  const openWorkflowStage = useCallback(
    (stageIndex: number) => pushDrawer({ kind: 'workflow-stage', stageIndex }),
    [pushDrawer],
  );

  const openTargetDetail = useCallback(
    () => pushDrawer({ kind: 'target-detail' }),
    [pushDrawer],
  );

  const value = useMemo(
    () => ({
      drawerStack: stack,
      activeDrawer,
      canGoBack: stack.length > 1,
      pushDrawer,
      closeDrawer: popAndClearParams,
      closeAllDrawers,

      ledgerOpen: activeDrawer?.kind === 'score-ledger',
      ledgerScope:
        activeDrawer?.kind === 'score-ledger' ? activeDrawer.scope : ('full' as LedgerScope),
      openLedger,
      closeLedger: popAndClearParams,

      drawerEvidenceId: activeDrawer?.kind === 'evidence' ? activeDrawer.id : null,
      openEvidence,
      closeEvidence: popAndClearParams,

      explanationFindingId:
        activeDrawer?.kind === 'finding-explanation' ? activeDrawer.id : null,
      findingEvidenceId: activeDrawer?.kind === 'finding-evidence' ? activeDrawer.id : null,
      openFindingExplanation,
      openFindingEvidence,
      closeFindingExplanation: popAndClearParams,
      closeFindingEvidence: popAndClearParams,

      timelineFocusMs,
      setTimelineFocus: setTimelineFocusMs,

      depth: FIXED_DEPTH,
      atLeastAnalyst: FIXED_DEPTH !== 'summary',
      isForensic: FIXED_DEPTH === 'forensic',

      influenceDetailOpen: activeDrawer?.kind === 'score-influence',
      influenceAxis: activeDrawer?.kind === 'score-influence' ? activeDrawer.axis : null,
      openInfluenceDetail,
      closeInfluenceDetail: popAndClearParams,

      openWorkflowStage,
      openTargetDetail,
    }),
    [
      stack,
      activeDrawer,
      pushDrawer,
      popAndClearParams,
      closeAllDrawers,
      openLedger,
      openEvidence,
      openFindingExplanation,
      openFindingEvidence,
      openInfluenceDetail,
      openWorkflowStage,
      openTargetDetail,
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
