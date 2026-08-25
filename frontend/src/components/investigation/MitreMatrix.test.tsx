import { describe, it, expect } from 'vitest';
import {
  TACTIC_ORDER,
  TECHNIQUE_TACTIC,
  groupByTactic,
  parseTechniqueId,
} from './MitreMatrix';

/**
 * The matrix exists to show whether behaviour CLUSTERS - five techniques under
 * Collection is a spyware profile; five spread across five tactics is not. So
 * the grouping, the kill-chain ordering, and the visible handling of unmapped
 * techniques are what these tests pin.
 */

describe('parseTechniqueId', () => {
  it('pulls the id out of a labelled technique', () => {
    expect(parseTechniqueId('T1412 - Capture SMS Messages')).toBe('T1412');
  });

  it('handles sub-techniques', () => {
    expect(parseTechniqueId('T1417.001 - Keylogging')).toBe('T1417.001');
  });

  it('accepts a bare id', () => {
    expect(parseTechniqueId('T1444')).toBe('T1444');
  });

  it('returns nothing for a string with no technique id', () => {
    expect(parseTechniqueId('not a technique')).toBe('');
  });
});

describe('groupByTactic', () => {
  it('returns nothing for an empty list', () => {
    expect(groupByTactic([])).toEqual([]);
  });

  it('groups techniques under their tactic', () => {
    const groups = groupByTactic([
      'T1412 - Capture SMS Messages',
      'T1417 - Input Capture',
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].tactic).toBe('Collection');
    expect(groups[0].entries.map((e) => e.id)).toEqual(['T1412', 'T1417']);
  });

  it('orders tactics along the kill chain, not by count', () => {
    // Impact has two techniques and Initial Access one, but Initial Access
    // comes first because that is the order an attack proceeds in.
    const groups = groupByTactic([
      'T1582 - SMS Control',
      'T1643 - Generate Traffic',
      'T1444 - Masquerade as Legitimate Application',
    ]);
    expect(groups.map((g) => g.tactic)).toEqual(['Initial Access', 'Impact']);
  });

  it('puts an unmapped technique in a visible Other bucket', () => {
    // An unmapped technique is a gap to close, not a thing to hide.
    const groups = groupByTactic(['T9999 - Something New']);
    expect(groups).toHaveLength(1);
    expect(groups[0].tactic).toBe('Other');
    expect(groups[0].entries[0].id).toBe('T9999');
  });

  it('sorts Other last even when it has the most techniques', () => {
    const groups = groupByTactic([
      'T9997 - a',
      'T9998 - b',
      'T9999 - c',
      'T1444 - Masquerade',
    ]);
    expect(groups[groups.length - 1].tactic).toBe('Other');
  });

  it('deduplicates a technique listed twice', () => {
    const groups = groupByTactic(['T1412 - Capture SMS', 'T1412']);
    expect(groups[0].entries).toHaveLength(1);
  });

  it('ignores entries with no technique id', () => {
    expect(groupByTactic(['', '   ', 'no id here'])).toEqual([]);
  });

  it('survives non-string entries', () => {
    expect(groupByTactic([null, 5, {}] as unknown as string[])).toEqual([]);
  });

  it('falls back to the id when there is no label', () => {
    const groups = groupByTactic(['T1444']);
    expect(groups[0].entries[0].label).toBe('T1444');
  });
});

describe('the tactic map', () => {
  it('only maps techniques onto tactics the matrix can render', () => {
    // A tactic that is not in TACTIC_ORDER would be silently dropped from the
    // output, so a typo here must fail loudly instead.
    for (const [id, tactic] of Object.entries(TECHNIQUE_TACTIC)) {
      expect(TACTIC_ORDER, `${id} maps to an unrenderable tactic`).toContain(
        tactic,
      );
    }
  });

  it('uses well-formed technique ids as keys', () => {
    for (const id of Object.keys(TECHNIQUE_TACTIC)) {
      expect(id).toMatch(/^T\d{4}(\.\d{3})?$/);
    }
  });
});
