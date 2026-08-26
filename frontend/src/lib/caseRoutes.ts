/**
 * Where a case lives.
 *
 * The four investigation views used to sit at four top-level, case-less paths -
 * `/fraud-card`, `/technical`, `/threat-intel`, `/chat` - with the active
 * sample held only in React context and sessionStorage. Two consequences:
 *
 * - A link to an investigation was not a link to an investigation. Sending
 *   `/technical` to a colleague showed them whatever case *they* had open, or
 *   bounced them to the upload page. For a product whose output is evidence
 *   somebody else has to check, that is close to a correctness bug.
 * - The routes were named after the audience ("technical", "executive"), so a
 *   reader had to classify themselves before they could navigate.
 *
 * Nesting under `/case/:sha256` makes the URL the source of truth and lets the
 * sections be named after the question they answer.
 *
 * Every path is built here rather than typed inline so the shape can change
 * again in one edit instead of nineteen.
 */

export const CASE_SECTIONS = ['summary', 'evidence', 'intel', 'ask'] as const;
export type CaseSection = (typeof CASE_SECTIONS)[number];

export const CASE_ROOT = '/case';

export function caseSectionPath(sha256: string, section: CaseSection = 'summary'): string {
  const base = `${CASE_ROOT}/${sha256}`;
  return section === 'summary' ? base : `${base}/${section}`;
}

export type CaseRoutes = Record<CaseSection, string> & { root: string };

export function caseRoutes(sha256: string): CaseRoutes {
  return {
    root: caseSectionPath(sha256, 'summary'),
    summary: caseSectionPath(sha256, 'summary'),
    evidence: caseSectionPath(sha256, 'evidence'),
    intel: caseSectionPath(sha256, 'intel'),
    ask: caseSectionPath(sha256, 'ask'),
  };
}

/** Which section a pathname is in, or null when it is not a case route. */
export function activeCaseSection(pathname: string): CaseSection | null {
  const m = pathname.match(/^\/case\/[^/]+(?:\/([^/?#]+))?/);
  if (!m) return null;
  const tail = m[1];
  if (!tail) return 'summary';
  return (CASE_SECTIONS as readonly string[]).includes(tail) ? (tail as CaseSection) : 'summary';
}

/**
 * The legacy paths, mapped onto sections.
 *
 * Kept indefinitely rather than for a deprecation window: these URLs are in
 * saved links, in PDF reports already delivered to banks, and in the grounded
 * citations the AI assistant emitted before this change. Breaking them would
 * break evidence trails that are the point of the product.
 */
export const LEGACY_SECTION_FOR_PATH: Record<string, CaseSection> = {
  '/fraud-card': 'summary',
  '/technical': 'evidence',
  '/threat-intel': 'intel',
  '/chat': 'ask',
};

export const SECTION_LABELS: Record<CaseSection, { label: string; hint: string }> = {
  summary: { label: 'Case', hint: 'what is it, and what should we do?' },
  evidence: { label: 'Evidence', hint: 'what proves it?' },
  intel: { label: 'Intelligence', hint: 'have we seen it before?' },
  ask: { label: 'Ask SUDARSHAN', hint: 'anything else' },
};
