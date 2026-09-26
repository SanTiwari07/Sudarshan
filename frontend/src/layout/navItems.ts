import type { LucideIcon } from 'lucide-react';
import {
  FolderOpen,
  Layers,
  Compass,
  Settings,
  Plus,
} from 'lucide-react';

export type NavItem = {
  to: string;
  label: string;
  shortLabel: string;
  icon: LucideIcon;
  /** Highlight when pathname starts with this prefix */
  matchPrefix?: string;
  /** Match the path exactly, never as a prefix */
  exact?: boolean;
  /** Nav-only: render as disabled control (no route yet) */
  disabled?: boolean;
};

/**
 * Navigation is grouped by what the analyst is trying to do:
 *
 *  - "New analysis" is the primary action and lives above the groups as a
 *    button, not as a row among peers.
 *  - Workspace: everything that exists independently of a case.
 *  - Open case: a single link back to the case that is loaded. It only renders
 *    when a case exists, so there is never a nav item that silently redirects
 *    somewhere else. The case's own sections are tabs on the case page.
 */
export const NAV_NEW_ANALYSIS: NavItem = {
  to: '/',
  label: 'New analysis',
  shortLabel: 'Analyse',
  icon: Plus,
  exact: true,
};

export const NAV_WORKSPACE: NavItem[] = [
  { to: '/history', label: 'Cases', shortLabel: 'Cases', icon: FolderOpen, matchPrefix: '/history' },
  { to: '/batch', label: 'Batch scan', shortLabel: 'Batch', icon: Layers, matchPrefix: '/batch' },
  { to: '/discovery', label: 'URL discovery', shortLabel: 'Discovery', icon: Compass, matchPrefix: '/discovery' },
];

export const NAV_SYSTEM: NavItem[] = [
  { to: '/settings', label: 'Settings', shortLabel: 'Settings', icon: Settings, matchPrefix: '/settings' },
];

/** Human title for the current route, shown in the top bar. */
export function pageTitleFor(pathname: string): string {
  if (pathname === '/') return 'New analysis';
  if (pathname.startsWith('/history')) return 'Cases';
  if (pathname.startsWith('/batch')) return 'Batch scan';
  if (pathname.startsWith('/discovery')) return 'URL discovery';
  if (pathname.startsWith('/settings')) return 'Settings';
  if (/^\/case\/[^/]+\/evidence/.test(pathname)) return 'Evidence';
  if (/^\/case\/[^/]+\/intel/.test(pathname)) return 'Threat intel';
  if (/^\/case\/[^/]+\/ask/.test(pathname)) return 'Ask Sudarshan';
  if (pathname.startsWith('/case/')) return 'Summary';
  return 'Workspace';
}

export function isNavActive(pathname: string, item: NavItem): boolean {
  if (item.disabled) return false;
  if (item.exact || item.to === '/') return pathname === item.to;
  if (item.to === '#') return false;
  const prefix = item.matchPrefix || item.to;
  return pathname === item.to || pathname.startsWith(`${prefix}/`);
}
