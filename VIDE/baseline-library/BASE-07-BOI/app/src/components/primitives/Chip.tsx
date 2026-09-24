import React from 'react';
import './Chip.css';

interface ChipProps {
  label: string;
  variant?: 'default' | 'success' | 'warning' | 'error';
}

export const Chip: React.FC<ChipProps> = ({ label, variant = 'default' }) => {
  return (
    <span className={`chip chip-${variant}`}>
      {label}
    </span>
  );
};
