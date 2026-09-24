import type { LucideIcon } from 'lucide-react';
import {
  FolderGit2,
  Layers,
  Compass,
  Globe,
  History,
  Settings,
  UploadCloud,
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
 * Enterprise Workspace navigation.
 * Standardized across the SOC console:
 * - Cases
 * - Batch Scan
 * - Discovery
 * - Threat Intelligence
 * - History
 * [divider]
 * - Upload APK
 * - Settings
 */
export const ENTERPRISE_NAV_MAIN: NavItem[] = [
  { to: '/history', label: 'Cases', shortLabel: 'Cases', icon: FolderGit2, matchPrefix: '/history' },
  { to: '/batch', label: 'Batch Scan', shortLabel: 'Batch', icon: Layers, matchPrefix: '/batch' },
  { to: '/discovery', label: 'Discovery', shortLabel: 'Discovery', icon: Compass, matchPrefix: '/discovery' },
  { to: '/threat-intel', label: 'Threat Intelligence', shortLabel: 'Threat Intel', icon: Globe, matchPrefix: '/threat-intel' },
  { to: '/history', label: 'History', shortLabel: 'History', icon: History, matchPrefix: '/history' },
];

export const ENTERPRISE_NAV_BOTTOM: NavItem[] = [
  { to: '/', label: 'Upload APK', shortLabel: 'Upload', icon: UploadCloud, matchPrefix: '/' },
  { to: '/settings', label: 'Settings', shortLabel: 'Settings', icon: Settings, matchPrefix: '/settings' },
];

export const ENTERPRISE_NAV_END: NavItem[] = [...ENTERPRISE_NAV_MAIN, ...ENTERPRISE_NAV_BOTTOM];
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
