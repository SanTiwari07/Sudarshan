import { describe, it, expect } from 'vitest';
import {
  CASE_SECTIONS,
  LEGACY_SECTION_FOR_PATH,
  activeCaseSection,
  caseRoutes,
  caseSectionPath,
} from './caseRoutes';

const SHA = 'a'.repeat(64);

describe('caseSectionPath', () => {
  it('puts the summary at the case root rather than /summary', () => {
    // One canonical URL per case. A trailing /summary would give every case two.
    expect(caseSectionPath(SHA, 'summary')).toBe(`/case/${SHA}`);
  });

  it('nests the other sections under the case', () => {
    expect(caseSectionPath(SHA, 'evidence')).toBe(`/case/${SHA}/evidence`);
    expect(caseSectionPath(SHA, 'intel')).toBe(`/case/${SHA}/intel`);
    expect(caseSectionPath(SHA, 'ask')).toBe(`/case/${SHA}/ask`);
  });

  it('always carries the sha, so a link identifies the sample', () => {
    // The defect this replaces: /technical showed the recipient whatever case
    // they had open, or bounced them to upload.
    for (const path of Object.values(caseRoutes(SHA))) {
      expect(path).toContain(SHA);
    }
  });
});

describe('activeCaseSection', () => {
  it('reads the section out of a pathname', () => {
    expect(activeCaseSection(`/case/${SHA}`)).toBe('summary');
    expect(activeCaseSection(`/case/${SHA}/evidence`)).toBe('evidence');
    expect(activeCaseSection(`/case/${SHA}/intel`)).toBe('intel');
    expect(activeCaseSection(`/case/${SHA}/ask`)).toBe('ask');
  });

  it('tolerates a trailing slash and a query string', () => {
    expect(activeCaseSection(`/case/${SHA}/`)).toBe('summary');
    expect(activeCaseSection(`/case/${SHA}/evidence?evidence=EVID-1`)).toBe('evidence');
    expect(activeCaseSection(`/case/${SHA}/evidence#dynamic-analysis`)).toBe('evidence');
  });

  it('falls back to summary for an unknown section rather than throwing', () => {
    expect(activeCaseSection(`/case/${SHA}/nonsense`)).toBe('summary');
  });

  it('returns null off a case route', () => {
    expect(activeCaseSection('/history')).toBeNull();
    expect(activeCaseSection('/batch/42')).toBeNull();
    expect(activeCaseSection('/')).toBeNull();
  });

  it('round-trips every section', () => {
    for (const section of CASE_SECTIONS) {
      expect(activeCaseSection(caseSectionPath(SHA, section))).toBe(section);
    }
  });
});

describe('legacy paths', () => {
  it('maps every old case-less path to a section', () => {
    // These are in saved links and in PDF reports already delivered to banks.
    expect(LEGACY_SECTION_FOR_PATH['/fraud-card']).toBe('summary');
    expect(LEGACY_SECTION_FOR_PATH['/technical']).toBe('evidence');
    expect(LEGACY_SECTION_FOR_PATH['/threat-intel']).toBe('intel');
    expect(LEGACY_SECTION_FOR_PATH['/chat']).toBe('ask');
  });

  it('covers exactly the four sections, with no orphan', () => {
    const mapped = new Set(Object.values(LEGACY_SECTION_FOR_PATH));
    expect(mapped).toEqual(new Set(CASE_SECTIONS));
  });
});
