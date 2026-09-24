import React from 'react';
import './PINPad.css';

interface PINPadProps {
  onKeyPress: (key: string) => void;
  onDelete: () => void;
}

export const PINPad: React.FC<PINPadProps> = ({ onKeyPress, onDelete }) => {
  const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '', '0', 'del'];

  return (
    <div className="pinpad">
      {keys.map((key, i) => (
        <button
          key={i}
          className={`pinpad-btn ${key === '' ? 'pinpad-empty' : ''}`}
          onClick={() => {
            if (key === 'del') onDelete();
            else if (key !== '') onKeyPress(key);
          }}
          disabled={key === ''}
        >
          {key === 'del' ? '⌫' : key}
        </button>
      ))}
    </div>
  );
};
