import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';

const MPIN: React.FC = () => {
  const navigate = useNavigate();
  const [pin, setPin] = useState('');

  const handleKeyPress = (key: string) => {
    if (pin.length < 6) {
      const newPin = pin + key;
      setPin(newPin);
      if (newPin.length === 6) {
        // Simulate validation delay
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
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      padding: 'var(--space-24)',
      height: '100vh',
      backgroundColor: 'var(--color-background)'
    }}>
      <div style={{ marginTop: 'var(--space-48)', marginBottom: 'var(--space-48)', textAlign: 'center' }}>
        <h2 style={{ color: 'var(--color-text-primary)', marginBottom: 'var(--space-8)' }}>Enter 6-digit MPIN</h2>
        <p style={{ color: 'var(--color-text-secondary)', marginBottom: 'var(--space-24)' }}>To access your account</p>
        
        {/* PIN Indicators */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: 'var(--space-12)' }}>
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              style={{
                width: '16px',
                height: '16px',
                borderRadius: '50%',
                backgroundColor: i < pin.length ? 'var(--color-primary)' : 'var(--color-divider)'
              }}
            />
          ))}
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', paddingBottom: 'var(--space-32)' }}>
        <PINPad onKeyPress={handleKeyPress} onDelete={handleDelete} />
      </div>
    </div>
  );
};

export default MPIN;
