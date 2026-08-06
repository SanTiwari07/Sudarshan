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
      className={`flex items-start justify-between gap-3 px-4 py-3 border-b border-slate-100 bg-white ${className}`}
    >
      <div className="flex items-start gap-3 min-w-0">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-50 text-blue-700 border border-slate-100">
          {icon}
        </span>
        <div className="min-w-0 pt-0.5">
          <h2 className="text-sm font-semibold text-slate-900 tracking-tight leading-snug">{title}</h2>
          {subtitle && (
            <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{subtitle}</p>
          )}
        </div>
      </div>
      {(badge ?? action) && <div className="shrink-0 pt-1">{badge ?? action}</div>}
    </div>
  );
}
