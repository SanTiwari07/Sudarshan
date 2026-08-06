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
};

export const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Upload & analyze', shortLabel: 'Upload', icon: UploadCloud, matchPrefix: '/' },
  { to: '/fraud-card', label: 'Fraud analyst intelligence', shortLabel: 'Fraud card', icon: LayoutDashboard },
  { to: '/technical', label: 'SOC / technical view', shortLabel: 'Technical', icon: Terminal },
  { to: '/chat', label: 'AI investigation assistant', shortLabel: 'AI assistant', icon: MessageSquare },
  { to: '/threat-intel', label: 'Threat intelligence', shortLabel: 'Threat intel', icon: Globe },
  { to: '/history', label: 'Case history registry', shortLabel: 'History', icon: Database, matchPrefix: '/history' },
];
