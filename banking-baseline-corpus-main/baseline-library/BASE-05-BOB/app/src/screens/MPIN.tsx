import React from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/PINPad';

export const MPIN: React.FC = () => {
  const navigate = useNavigate();

  const handleComplete = (pin: string) => {
    // 6 digits expected
    if (pin.length === 6) {
      navigate('/home');
    }
  };

  return (
    <div className="flex flex-col h-full bg-white">
      <div className="flex-1 flex flex-col items-center justify-center p-6">
        <div className="w-16 h-16 rounded-full mb-6 flex items-center justify-center text-white text-xl font-bold" style={{ backgroundColor: 'var(--color-primary)' }}>
          AV
        </div>
        <h2 className="text-xl font-bold mb-2">Enter Login PIN</h2>
        <p className="text-sm text-[var(--color-text-secondary)] mb-8">Please enter your 4-digit or 6-digit MPIN</p>
        
        <PINPad 
          length={6} 
          onComplete={handleComplete} 
        />
        
        <button type="button" className="mt-8 text-sm font-medium text-[var(--color-primary)]">
          Forgot PIN?
        </button>
      </div>
    </div>
  );
};
