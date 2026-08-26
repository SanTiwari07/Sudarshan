import type { LucideIcon } from 'lucide-react';
import {
  Database,
  UploadCloud,
  Layers,
} from 'lucide-react';

export type NavItem = {
  to: string;
  label: string;
  shortLabel: string;
  icon: LucideIcon;
  /** Highlight when pathname starts with this prefix */
  matchPrefix?: string;
  /** Nav-only: render as disabled control (no route yet) */
  disabled?: boolean;
};

/**
 * Workspace navigation.
 *
 * The four investigation views used to live here too, as an "Active case"
 * group: Executive, Technical, Intel, AI Assistant. They now live in the case
 * bar at `/case/:sha256`, named after the question each answers rather than
 * after the job title of whoever is expected to read it.
 *
 * Keeping both would have meant two menus to the same four destinations,
 * disagreeing about what to call them - which is the ambiguity this
 * reorganisation exists to remove.
 */
export const ENTERPRISE_NAV_END: NavItem[] = [
  { to: '/history', label: 'Cases', shortLabel: 'Cases', icon: Database, matchPrefix: '/history' },
  { to: '/batch', label: 'Batch Scan', shortLabel: 'Batch Scan', icon: Layers, matchPrefix: '/batch' },
  { to: '/', label: 'Upload APK', shortLabel: 'Upload', icon: UploadCloud, matchPrefix: '/' },
];

export const ENTERPRISE_NAV: NavItem[] = [...ENTERPRISE_NAV_END];

export function isNavActive(pathname: string, item: NavItem): boolean {
  if (item.disabled) return false;
  if (item.to === '/') {
    return pathname === '/';
  }
  if (item.to === '#') return false;
  const prefix = item.matchPrefix || item.to;
  return pathname === item.to || pathname.startsWith(`${prefix}/`);
}
