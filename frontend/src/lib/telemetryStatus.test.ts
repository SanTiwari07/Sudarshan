import { describe, expect, it } from 'vitest';
import { ABSENCE_IS_NOT_BENIGN, describeTelemetry } from './telemetryStatus';
import type { DynamicAnalysis } from '../types/case';

const base = { available: true } as unknown as DynamicAnalysis;

describe('describeTelemetry', () => {
  it('reports "Not recorded" instead of inventing values for old cases', () => {
    const v = describeTelemetry(base);
    expect(v.label).toBe('Not recorded');
    expect(v.tone).toBe('unknown');
    expect(v.hooksInstalled).toBeNull();
    expect(v.encryptedTrafficInspected).toBeNull();
  });

  it('surfaces the recorded failure reason and detach', () => {
    const v = describeTelemetry({
      ...base,
      error: 'PermissionDeniedError: unable to access process',
      telemetry_diagnostics: {
        classification: 'NO_TELEMETRY_OBSERVED',
        explanation: 'lost',
        hooks: { installed: 77 },
        events: { received: 0 },
        session: { attached_at_window_end: false, detach_reason: 'process-terminated' },
      },
    });
    expect(v.label).toBe('Instrumentation lost');
    expect(v.tone).toBe('warn');
    expect(v.hooksInstalled).toBe(77);
    expect(v.detachReason).toBe('process-terminated');
    expect(v.error).toContain('PermissionDeniedError');
  });

  it('discloses that encrypted traffic was not inspected', () => {
    const v = describeTelemetry({
      ...base,
      network_collection: {
        encrypted_traffic_inspected: false,
        limitations: ['No mitmproxy HAR configured: encrypted traffic was NOT inspected.', 42],
      },
    });
    expect(v.encryptedTrafficInspected).toBe(false);
    expect(v.limitations).toEqual(['No mitmproxy HAR configured: encrypted traffic was NOT inspected.']);
  });

  it('never phrases absence of events as benign', () => {
    expect(ABSENCE_IS_NOT_BENIGN).toMatch(/not evidence of benign/);
  });
});
