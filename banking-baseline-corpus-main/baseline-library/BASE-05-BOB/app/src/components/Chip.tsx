import React from 'react';
import './Chip.css';

interface ChipProps {
  label: string;
  variant?: 'default' | 'success' | 'warning' | 'error';
  selected?: boolean;
  onClick?: () => void;
}

export const Chip: React.FC<ChipProps> = ({ label, variant = 'default', selected, onClick }) => {
  return (
    <span 
      className={`chip chip-${variant} ${selected ? 'bg-[var(--color-primary)] text-white' : ''} cursor-pointer`}
      onClick={onClick}
    >
      {label}
    </span>
  );
};
