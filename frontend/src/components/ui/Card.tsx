import React from 'react';

interface SocCardProps {
  children: React.ReactNode;
  className?: string;
  id?: string;
}

export function SocCard({ children, className = '', id }: SocCardProps) {
  return (
    <div
      id={id}
      className={`bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden ${className}`}
    >
      {children}
    </div>
  );
}

export default SocCard;
