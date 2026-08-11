import type { LucideIcon } from 'lucide-react';
import {
  LayoutDashboard,
  Terminal,
  MessageSquare,
  Globe,
  Database,
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

/** Legacy drawer list - kept for any deep links; primary nav is AppHeader bar. */
export const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Upload & analyze', shortLabel: 'Upload', icon: UploadCloud, matchPrefix: '/' },
  { to: '/fraud-card', label: 'Fraud analyst intelligence', shortLabel: 'Fraud card', icon: LayoutDashboard },
  { to: '/technical', label: 'SOC / technical view', shortLabel: 'Technical', icon: Terminal },
  { to: '/chat', label: 'AI investigation assistant', shortLabel: 'AI assistant', icon: MessageSquare },
  { to: '/threat-intel', label: 'Threat intelligence', shortLabel: 'Threat intel', icon: Globe },
  { to: '/history', label: 'Case history registry', shortLabel: 'History', icon: Database, matchPrefix: '/history' },
];

export const ENTERPRISE_NAV_MAIN: NavItem[] = [
  { to: '/fraud-card', label: 'Executive Fraud Card', shortLabel: 'Executive', icon: LayoutDashboard },
  { to: '/technical', label: 'Technical SOC View', shortLabel: 'Technical', icon: Terminal },
  { to: '/threat-intel', label: 'Threat Intelligence', shortLabel: 'Intel', icon: Globe },
  { to: '/chat', label: 'AI Copilot', shortLabel: 'AI Copilot', icon: MessageSquare },
];

/** Right cluster: Cases, then Upload APK (adjacent to notifications). */
export const ENTERPRISE_NAV_END: NavItem[] = [
  { to: '/history', label: 'Cases', shortLabel: 'Cases', icon: Database, matchPrefix: '/history' },
  { to: '/', label: 'Upload APK', shortLabel: 'Upload', icon: UploadCloud, matchPrefix: '/' },
];

export const ENTERPRISE_NAV: NavItem[] = [...ENTERPRISE_NAV_MAIN, ...ENTERPRISE_NAV_END];

export function isNavActive(pathname: string, item: NavItem): boolean {
  if (item.disabled) return false;
  if (item.to === '/') {
    return pathname === '/';
  }
  if (item.to === '#') return false;
  const prefix = item.matchPrefix || item.to;
  return pathname === item.to || pathname.startsWith(`${prefix}/`);
}
