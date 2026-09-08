import React from 'react';
import './PINPad.css';

interface PINPadProps {
  onKeyPress?: (key: string) => void;
  onDelete?: () => void;
  length?: number;
  onComplete?: (pin: string) => void;
}

export const PINPad: React.FC<PINPadProps> = ({ onKeyPress, onDelete, length, onComplete }) => {
  const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '', '0', 'del'];
  const [pin, setPin] = React.useState('');

  const handleKeyPress = (key: string) => {
    if (key === 'del') {
      const newPin = pin.slice(0, -1);
      setPin(newPin);
      if (onDelete) onDelete();
    } else if (key !== '') {
      if (length && pin.length >= length) return;
      const newPin = pin + key;
      setPin(newPin);
      if (onKeyPress) onKeyPress(key);
      if (length && newPin.length === length && onComplete) {
        onComplete(newPin);
      }
    }
  };

  return (
    <div className="flex flex-col items-center">
      {length && (
        <div className="flex space-x-4 mb-8">
          {Array.from({ length }).map((_, i) => (
            <div 
              key={i} 
              className={`w-4 h-4 rounded-full ${i < pin.length ? 'bg-[var(--color-primary)]' : 'bg-gray-200'}`}
            />
          ))}
        </div>
      )}
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
