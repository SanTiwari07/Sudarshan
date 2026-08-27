import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';

export const MPIN: React.FC = () => {
  const navigate = useNavigate();
  const [pin, setPin] = useState('');

  const handlePinChange = (newPin: string) => {
    setPin(newPin);
    if (newPin.length === 6) {
      setTimeout(() => {
        navigate('/home');
      }, 300);
    }
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      backgroundColor: 'var(--color-surface)',
    }}>
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        padding: 'var(--spacing-3)',
      }}>
        <h2 style={{ color: 'var(--color-primary)', marginBottom: 'var(--spacing-1)' }}>Enter 6-digit MPIN</h2>
        <p style={{ color: 'var(--color-text-secondary)', marginBottom: 'var(--spacing-4)' }}>
          Enter MPIN to login
        </p>
        
        <div style={{ display: 'flex', gap: 'var(--spacing-2)', marginBottom: '40px' }}>
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              style={{
                width: '16px',
                height: '16px',
                borderRadius: '50%',
                backgroundColor: i < pin.length ? 'var(--color-primary)' : 'var(--color-divider)',
              }}
            />
          ))}
        </div>
      </div>

      <div style={{ paddingBottom: 'var(--spacing-4)' }}>
        <PINPad 
          onKeyPress={(key) => handlePinChange(pin.length < 6 ? pin + key : pin)} 
          onDelete={() => handlePinChange(pin.slice(0, -1))} 
        />
      </div>
    </div>
  );
};
