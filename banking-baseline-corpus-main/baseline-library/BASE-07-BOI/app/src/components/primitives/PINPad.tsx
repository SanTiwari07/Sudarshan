import React, { useState } from 'react';
import './PINPad.css';

interface PINPadProps {
  length?: number;
  onComplete: (pin: string) => void;
}

export const PINPad: React.FC<PINPadProps> = ({ length = 6, onComplete }) => {
  const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '', '0', 'del'];
  const [pin, setPin] = useState('');

  const handleKeyPress = (key: string) => {
    if (key === 'del') {
      setPin(prev => prev.slice(0, -1));
    } else if (key !== '' && pin.length < length) {
      const newPin = pin + key;
      setPin(newPin);
      if (newPin.length === length) {
        onComplete(newPin);
      }
    }
  };

  return (
    <div className="pinpad-wrapper">
      <div className="pin-display">
        {Array.from({ length }).map((_, i) => (
          <div key={i} className={`pin-dot ${i < pin.length ? 'filled' : ''}`} />
        ))}
      </div>
      <div className="pinpad">
        {keys.map((key, i) => (
          <button
            key={i}
            className={`pinpad-btn ${key === '' ? 'pinpad-empty' : ''}`}
            onClick={() => handleKeyPress(key)}
            disabled={key === ''}
          >
            {key === 'del' ? '⌫' : key}
          </button>
        ))}
      </div>
    </div>
  );
};
