import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';

export const MPIN: React.FC = () => {
  const navigate = useNavigate();
  const [pin, setPin] = useState('');

  const handlePinChange = (newPin: string) => {
    setPin(newPin);
    if (newPin.length === 6) { // PNB often uses 4 or 6, spec says 6 digits -> HOME
      setTimeout(() => {
        navigate('/home');
      }, 300);
    }
  };

  return (
    <div style={{ 
      padding: 'var(--spacing-3)', 
      minHeight: '100vh', 
      display: 'flex', 
      flexDirection: 'column',
      justifyContent: 'center',
      alignItems: 'center'
    }}>
      <div style={{ textAlign: 'center', marginBottom: 'var(--spacing-4)' }}>
        <h2 style={{ marginBottom: 'var(--spacing-1)' }}>Enter MPIN</h2>
        <p style={{ color: 'var(--color-text-secondary)' }}>Please enter your 6-digit MPIN to continue</p>
      </div>

      <div style={{ 
        display: 'flex', 
        gap: 'var(--spacing-2)', 
        marginBottom: 'var(--spacing-4)' 
      }}>
        {Array.from({ length: 6 }).map((_, i) => (
          <div 
            key={i}
            style={{
              width: '16px',
              height: '16px',
              borderRadius: '50%',
              backgroundColor: i < pin.length ? 'var(--color-primary)' : 'var(--color-divider)',
              transition: 'background-color 0.2s'
            }}
          />
        ))}
      </div>

      <div style={{ width: '100%', maxWidth: '320px' }}>
        <PINPad 
          onKeyPress={(key) => handlePinChange(pin.length < 6 ? pin + key : pin)}
          onDelete={() => handlePinChange(pin.slice(0, -1))}
        />
      </div>
      
      <button 
        type="button" 
        style={{ 
          background: 'none', 
          border: 'none', 
          color: 'var(--color-primary)', 
          fontWeight: 500,
          cursor: 'pointer',
          padding: 'var(--spacing-3)',
          marginTop: 'var(--spacing-2)'
        }}
      >
        Forgot MPIN?
      </button>
    </div>
  );
};
