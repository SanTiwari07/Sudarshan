import React from 'react';

interface SocCardProps {
  children: React.ReactNode;
  className?: string;
}

export function SocCard({ children, className = '' }: SocCardProps) {
  return (
    <div className={`bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden ${className}`}>
      {children}
    </div>
  );
}

export default SocCard;
