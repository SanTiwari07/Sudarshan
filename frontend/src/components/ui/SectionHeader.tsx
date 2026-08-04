import React from 'react';

interface SectionHeaderProps {
  icon: React.ReactNode;
  title: string;
  subtitle?: string;
  badge?: React.ReactNode;
  action?: React.ReactNode; // alias for badge, used by collapsible panels
  className?: string;
}

export default function SectionHeader({ icon, title, subtitle, badge, action, className = '' }: SectionHeaderProps) {
  return (
    <div className={`flex items-center justify-between px-5 py-3 bg-slate-50 border-b border-slate-200 ${className}`}>
      <div className="flex items-center gap-2">
        <span className="text-blue-700">{icon}</span>
        <div>
          <h2 className="text-sm font-semibold text-slate-800 tracking-tight">{title}</h2>
          {subtitle && <p className="text-xs text-slate-500">{subtitle}</p>}
        </div>
      </div>
      {badge ?? action}
    </div>
  );
}
