import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';

export const MPIN: React.FC = () => {
  const navigate = useNavigate();
  const [pin, setPin] = useState<string[]>([]);

  const handleKeyPress = (key: string) => {
    if (pin.length < 6) {
      setPin(prev => [...prev, key]);
    }
  };

  const handleDelete = () => {
    setPin(prev => prev.slice(0, -1));
  };

  useEffect(() => {
    if (pin.length === 6) {
      navigate('/home');
    }
  }, [pin, navigate]);

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <h2 style={{ textAlign: 'center', marginBottom: '32px' }}>Enter MPIN</h2>
      <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', marginBottom: '32px' }}>
        {[0, 1, 2, 3, 4, 5].map(i => (
          <div key={i} style={{ width: '16px', height: '16px', borderRadius: '8px', backgroundColor: i < pin.length ? 'var(--color-primary)' : 'var(--color-divider)' }} />
        ))}
      </div>
      <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <PINPad onKeyPress={handleKeyPress} onDelete={handleDelete} />
      </div>
    </div>
  );
};
