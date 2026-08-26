import { describe, it, expect } from 'vitest';
import { SEVERITY, severityOf, caseSeverity } from './severity';

describe('severity tokens', () => {
  it('never encodes meaning in colour alone', () => {
    for (const token of Object.values(SEVERITY)) {
      expect(token.label, token.level).toBeTruthy();
      expect(token.meaning, token.level).toBeTruthy();
      expect(token.icon, token.level).toBeTruthy();
    }
  });

  it('keeps INCOMPLETE visually neutral - never green, never red', () => {
    const t = SEVERITY.INCOMPLETE;
    const surfaces = [t.fg, t.bg, t.border, t.bar, t.badge, t.accent].join(' ');
    expect(surfaces).not.toMatch(/emerald|green|red/);
    expect(surfaces).toMatch(/slate/);
  });

  it('resolves the engine vocabulary', () => {
    expect(severityOf('Critical').level).toBe('CRITICAL');
    expect(severityOf('High').level).toBe('HIGH');
    expect(severityOf('Suspicious').level).toBe('SUSPICIOUS');
    expect(severityOf('Safe').level).toBe('SAFE');
  });

  it('resolves INCOMPLETE_EXERCISE rather than guessing', () => {
    expect(severityOf('INCOMPLETE_EXERCISE').level).toBe('INCOMPLETE');
    expect(severityOf('inconclusive').level).toBe('INCOMPLETE');
  });

  it('returns UNKNOWN for unrecognised input rather than falling through to SAFE', () => {
    // The failure mode of guessing here is a clean bill of health nobody issued.
    expect(severityOf('').level).toBe('UNKNOWN');
    expect(severityOf(null).level).toBe('UNKNOWN');
    expect(severityOf(undefined).level).toBe('UNKNOWN');
    expect(severityOf('banana').level).toBe('UNKNOWN');
    expect(severityOf('Low').level).toBe('UNKNOWN');
  });

  it('lets the inconclusive flag override any band', () => {
    expect(caseSeverity('Safe', true).level).toBe('INCOMPLETE');
    expect(caseSeverity('Critical', true).level).toBe('INCOMPLETE');
    expect(caseSeverity('Safe', false).level).toBe('SAFE');
  });
});
