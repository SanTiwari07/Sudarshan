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
      className={`bg-white border border-slate-200/80 rounded-xl shadow-sm overflow-hidden transition-shadow duration-200 hover:shadow-md ${className}`}
    >
      {children}
    </div>
  );
}

export default SocCard;
