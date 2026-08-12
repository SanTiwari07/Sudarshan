import { describe, expect, it } from 'vitest';
import {
  hasRuntimeCodeLoadingSignal,
  hasObfuscationSignal,
  isFindingDetected,
} from './technicalFindings';
import type { FraudCardData } from '../App';

const base = {
  technical_view: { permissions_fired: [], strings_fired: [], apis_fired: [], matched_rule: '', decoded_manifest_excerpts: [] },
} as FraudCardData;

describe('technicalFindings detection', () => {
  it('detects runtime code loading from DexClassLoader API', () => {
    const data = {
      ...base,
      obfuscation_score: 0,
      technical_view: { ...base.technical_view!, apis_fired: ['DexClassLoader'] },
    } as FraudCardData;
    expect(hasRuntimeCodeLoadingSignal(data)).toBe(true);
    expect(isFindingDetected('runtime_code_loading', data)).toBe(true);
  });

  it('does not treat obfuscation score alone as runtime code loading', () => {
    const data = { ...base, obfuscation_score: 0.8 } as FraudCardData;
    expect(hasRuntimeCodeLoadingSignal(data)).toBe(false);
    expect(isFindingDetected('runtime_code_loading', data)).toBe(false);
  });

  it('detects obfuscation from score threshold', () => {
    const data = { ...base, obfuscation_score: 0.3 } as FraudCardData;
    expect(hasObfuscationSignal(data)).toBe(true);
  });
});
