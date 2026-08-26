import { describe, it, expect, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { InvestigationUIProvider, useInvestigationUI } from './InvestigationUIContext';

/**
 * The drawer stack.
 *
 * Before this, five overlays kept independent state that did not coordinate:
 * `openEvidence` cleared two siblings but not the ledger or the influence
 * detail, and `openLedger` / `openInfluenceDetail` cleared nothing at all.
 * Since the ledger opens evidence and the influence detail opens the ledger,
 * three overlays could be live simultaneously with no way back to the one
 * underneath.
 */

function useUI(initialEntry = '/fraud-card') {
  return renderHook(() => useInvestigationUI(), {
    wrapper: ({ children }) => (
      <MemoryRouter initialEntries={[initialEntry]}>
        <InvestigationUIProvider>{children}</InvestigationUIProvider>
      </MemoryRouter>
    ),
  });
}

// The depth setting persists to localStorage, so tests must not inherit each
// other's choices.
beforeEach(() => {
  localStorage.clear();
});

describe('drawer stack', () => {
  it('starts empty', () => {
    const { result } = useUI();
    expect(result.current.activeDrawer).toBeNull();
    expect(result.current.drawerStack).toEqual([]);
    expect(result.current.canGoBack).toBe(false);
  });

  it('opens one drawer', () => {
    const { result } = useUI();
    act(() => result.current.openEvidence('EVID-001'));

    expect(result.current.activeDrawer).toEqual({ kind: 'evidence', id: 'EVID-001' });
    expect(result.current.drawerEvidenceId).toBe('EVID-001');
    expect(result.current.canGoBack).toBe(false);
  });

  it('preserves the ledger when the ledger opens evidence, and returns to it on close', () => {
    // The exact drill-down that used to strand the reader: the ledger stayed
    // mounted underneath but closing evidence revealed a panel they had
    // already mentally left, with no back affordance.
    const { result } = useUI();

    act(() => result.current.openLedger('stei'));
    expect(result.current.ledgerOpen).toBe(true);
    expect(result.current.ledgerScope).toBe('stei');

    act(() => result.current.openEvidence('EVID-007'));
    expect(result.current.activeDrawer).toEqual({ kind: 'evidence', id: 'EVID-007' });
    expect(result.current.ledgerOpen).toBe(false); // not the top any more
    expect(result.current.canGoBack).toBe(true);

    act(() => result.current.closeEvidence());
    expect(result.current.ledgerOpen).toBe(true);
    expect(result.current.ledgerScope).toBe('stei');
    expect(result.current.canGoBack).toBe(false);
  });

  it('supports the influence -> ledger -> evidence chain three deep', () => {
    const { result } = useUI();

    act(() => result.current.openInfluenceDetail('dynamic'));
    act(() => result.current.openLedger('dynamic'));
    act(() => result.current.openEvidence('EVID-100'));

    expect(result.current.drawerStack).toHaveLength(3);
    expect(result.current.activeDrawer?.kind).toBe('evidence');

    act(() => result.current.closeEvidence());
    expect(result.current.activeDrawer?.kind).toBe('score-ledger');

    act(() => result.current.closeLedger());
    expect(result.current.activeDrawer?.kind).toBe('score-influence');
    expect(result.current.influenceAxis).toBe('dynamic');

    act(() => result.current.closeInfluenceDetail());
    expect(result.current.activeDrawer).toBeNull();
  });

  it('exposes exactly one active drawer at a time', () => {
    const { result } = useUI();

    act(() => result.current.openLedger('full'));
    act(() => result.current.openFindingExplanation('accessibility_abuse' as never));

    const live = [
      result.current.ledgerOpen,
      result.current.drawerEvidenceId !== null,
      result.current.explanationFindingId !== null,
      result.current.findingEvidenceId !== null,
      result.current.influenceDetailOpen,
    ].filter(Boolean);

    expect(live).toHaveLength(1);
  });

  it('does not stack a duplicate when the same drawer is re-opened', () => {
    // Otherwise it would take two closes to dismiss one drawer.
    const { result } = useUI();

    act(() => result.current.openEvidence('EVID-001'));
    act(() => result.current.openEvidence('EVID-001'));

    expect(result.current.drawerStack).toHaveLength(1);

    act(() => result.current.closeEvidence());
    expect(result.current.activeDrawer).toBeNull();
  });

  it('treats a different id as a genuine push', () => {
    const { result } = useUI();

    act(() => result.current.openEvidence('EVID-001'));
    act(() => result.current.openEvidence('EVID-002'));

    expect(result.current.drawerStack).toHaveLength(2);
    expect(result.current.drawerEvidenceId).toBe('EVID-002');

    act(() => result.current.closeEvidence());
    expect(result.current.drawerEvidenceId).toBe('EVID-001');
  });

  it('closeAllDrawers empties the whole stack', () => {
    const { result } = useUI();

    act(() => result.current.openInfluenceDetail('static'));
    act(() => result.current.openLedger('full'));
    act(() => result.current.closeAllDrawers());

    expect(result.current.drawerStack).toEqual([]);
    expect(result.current.activeDrawer).toBeNull();
  });

  it('reports a stable ledgerScope default when the ledger is not on top', () => {
    const { result } = useUI();
    expect(result.current.ledgerScope).toBe('full');
  });
});

describe('reading depth', () => {
  it('defaults to summary - the twenty-second read', () => {
    const { result } = useUI();
    expect(result.current.depth).toBe('summary');
    expect(result.current.atLeastAnalyst).toBe(false);
    expect(result.current.isForensic).toBe(false);
  });

  it('derives the two gates from the level', () => {
    const { result } = useUI();

    act(() => result.current.setDepth('analyst'));
    expect(result.current.atLeastAnalyst).toBe(true);
    expect(result.current.isForensic).toBe(false);

    act(() => result.current.setDepth('forensic'));
    expect(result.current.atLeastAnalyst).toBe(true);
    expect(result.current.isForensic).toBe(true);
  });

  it('persists the choice across sessions', () => {
    const first = useUI();
    act(() => first.result.current.setDepth('forensic'));
    first.unmount();

    const second = useUI();
    expect(second.result.current.depth).toBe('forensic');
  });

  it('ignores a corrupted stored value rather than trusting it', () => {
    localStorage.setItem('sudarshan_case_depth', 'root-access');
    const { result } = useUI();
    expect(result.current.depth).toBe('summary');
  });
});

describe('deep links', () => {
  it('opens the evidence drawer from ?evidence=', () => {
    const { result } = useUI('/fraud-card?evidence=EVID-042');
    expect(result.current.activeDrawer).toEqual({ kind: 'evidence', id: 'EVID-042' });
  });

  it('opens the score ledger from ?ledger=', () => {
    const { result } = useUI('/fraud-card?ledger=correlation');
    expect(result.current.ledgerOpen).toBe(true);
    expect(result.current.ledgerScope).toBe('correlation');
  });

  it('does not re-push the deep-linked drawer on every render', () => {
    const { result, rerender } = useUI('/fraud-card?evidence=EVID-042');
    rerender();
    rerender();
    expect(result.current.drawerStack).toHaveLength(1);
  });
});
