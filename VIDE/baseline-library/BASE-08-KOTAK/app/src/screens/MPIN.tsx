import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const MPIN: React.FC = () => {
  const navigate = useNavigate();
  const [pin, setPin] = useState('');

  const handleKeyPress = (num: string) => {
    if (pin.length < 6) {
      const newPin = pin + num;
      setPin(newPin);
      if (newPin.length === 6) {
        setTimeout(() => {
          navigate('/home');
        }, 300);
      }
    }
  };

  const handleDelete = () => {
    setPin(pin.slice(0, -1));
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 p-6 items-center">
      <div className="mt-12 text-center w-full">
        <h1 className="text-2xl font-bold mb-2" style={{ color: 'var(--color-text-primary)' }}>Enter MPIN</h1>
        <p style={{ color: 'var(--color-text-secondary)' }}>Enter 6-digit MPIN for your account</p>
      </div>

      <div className="flex justify-center gap-4 my-12">
        {[...Array(6)].map((_, i) => (
          <div
            key={i}
            className={`w-4 h-4 rounded-full ${i < pin.length ? 'bg-primary' : 'bg-gray-300'}`}
            style={{ backgroundColor: i < pin.length ? 'var(--color-primary)' : 'var(--color-divider)' }}
          />
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6 w-full max-w-xs mx-auto mt-auto mb-12">
        {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((num) => (
          <button
            key={num}
            onClick={() => handleKeyPress(num.toString())}
            className="w-16 h-16 rounded-full flex items-center justify-center text-2xl font-medium mx-auto shadow-sm"
            style={{ backgroundColor: 'var(--color-surface)', color: 'var(--color-secondary)' }}
          >
            {num}
          </button>
        ))}
        <div />
        <button
          onClick={() => handleKeyPress('0')}
          className="w-16 h-16 rounded-full flex items-center justify-center text-2xl font-medium mx-auto shadow-sm"
          style={{ backgroundColor: 'var(--color-surface)', color: 'var(--color-secondary)' }}
        >
          0
        </button>
        <button
          onClick={handleDelete}
          className="w-16 h-16 rounded-full flex items-center justify-center text-xl mx-auto shadow-sm"
          style={{ backgroundColor: 'var(--color-surface)', color: 'var(--color-text-secondary)' }}
        >
          ⌫
        </button>
      </div>
    </div>
  );
};

export default MPIN;
