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
      className={`bg-white border border-slate-200/80 rounded-md shadow-[0_1px_2px_rgba(0,0,0,0.02)] overflow-hidden ${className}`}
    >
      {children}
    </div>
  );
}

export default SocCard;
