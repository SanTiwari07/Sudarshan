import { Link, useLocation } from 'react-router-dom';
import { FileText, Database, Globe, Sparkles, type LucideIcon } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { motion } from 'motion/react';
import {
  CASE_SECTIONS,
  SECTION_LABELS,
  activeCaseSection,
  caseSectionPath,
  type CaseSection,
} from '../../lib/caseRoutes';

const SECTION_ICONS: Record<CaseSection, LucideIcon> = {
  summary: FileText,
  evidence: Database,
  intel: Globe,
  ask: Sparkles,
};

function CaseTabs({ sha256 }: { sha256: string }) {
  const { pathname } = useLocation();
  const active = activeCaseSection(pathname) ?? 'summary';

  return (
    <nav
      aria-label="Case sections"
      className="flex min-w-0 items-center overflow-x-auto scrollbar-hidden rounded-xl bg-slate-100 p-1"
    >
      {CASE_SECTIONS.map((section) => {
        const Icon = SECTION_ICONS[section];
        const selected = section === active;
        return (
          <Link
            key={section}
            data-id={section}
            aria-current={selected ? 'page' : undefined}
            to={caseSectionPath(sha256, section)}
            title={SECTION_LABELS[section].hint}
            className={`relative flex items-center gap-2 whitespace-nowrap rounded-lg px-4 h-9 font-sans text-sm font-semibold tracking-[-0.01em] transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 z-10 ${
              selected ? 'text-slate-900' : 'text-slate-500 hover:text-slate-900'
            }`}
          >
            {selected && (
              <motion.div
                layoutId="active-investigation-tab"
                className="absolute inset-0 rounded-lg bg-white -z-10 shadow-sm"
                transition={{ type: 'spring', stiffness: 450, damping: 35 }}
              />
            )}
            <Icon className={`h-4 w-4 shrink-0 ${selected ? 'text-blue-600' : ''}`} aria-hidden />
            <span>{SECTION_LABELS[section].label}</span>
          </Link>
        );
      })}
    </nav>
  );
}

export function CaseBar({ data }: { data: FraudCardData }) {
  return (
    <div className="sticky -top-5 sm:-top-6 lg:-top-8 z-30 -mx-4 sm:-mx-6 lg:-mx-8 -mt-5 sm:-mt-6 lg:-mt-8 mb-6 border-b border-slate-200/70 bg-white px-4 sm:px-6 lg:px-8 py-2.5">
      <div className="flex items-center justify-center">
        <CaseTabs sha256={data.sha256} />
      </div>
    </div>
  );
}

export default CaseBar;

