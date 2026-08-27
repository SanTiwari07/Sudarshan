import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { PINPad } from '../components/primitives/PINPad';

export const Confirm: React.FC = () => {
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
      navigate('/transfer/receipt');
    }
  }, [pin, navigate]);

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <Header title="Enter MPIN to Confirm" showBack />
      <div className="page-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
        <p style={{ marginBottom: '24px' }}>Please enter your 6-digit MPIN</p>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', marginBottom: '32px' }}>
          {[0, 1, 2, 3, 4, 5].map(i => (
            <div key={i} style={{ width: '16px', height: '16px', borderRadius: '8px', backgroundColor: i < pin.length ? 'var(--color-primary)' : 'var(--color-divider)' }} />
          ))}
        </div>
        <PINPad onKeyPress={handleKeyPress} onDelete={handleDelete} />
      </div>
    </div>
  );
};
