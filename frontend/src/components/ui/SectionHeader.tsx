import React from 'react';

interface SectionHeaderProps {
  icon: React.ReactNode;
  title: string;
  subtitle?: React.ReactNode;
  badge?: React.ReactNode;
  action?: React.ReactNode; // alias for badge, used by collapsible panels
  className?: string;
}

export default function SectionHeader({ icon, title, subtitle, badge, action, className = '' }: SectionHeaderProps) {
  return (
    <div
      className={`flex items-start justify-between gap-3 px-3 py-2.5 border-b border-slate-200/60 bg-slate-50/50 ${className}`}
    >
      <div className="flex items-start gap-2.5 min-w-0">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-white text-slate-700 border border-slate-200 shadow-xs">
          {icon}
        </span>
        <div className="min-w-0 pt-0.5">
          <h2 className="text-xs font-bold text-slate-900 tracking-wider uppercase">{title}</h2>
          {subtitle && (
            <p className="text-[11px] text-slate-500 mt-0.5 leading-relaxed">{subtitle}</p>
          )}
        </div>
      </div>
      {(badge ?? action) && <div className="shrink-0 pt-0.5">{badge ?? action}</div>}
    </div>
  );
}
