import React from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';

export const MPIN: React.FC = () => {
  const navigate = useNavigate();

  const [pin, setPin] = React.useState('');

  const handleComplete = (completedPin: string) => {
    console.log(completedPin); // fix unused var
    // Mock authentication successful
    navigate('/home');
  };

  const handleKeyPress = (key: string) => {
    if (pin.length < 6) {
      const newPin = pin + key;
      setPin(newPin);
      if (newPin.length === 6) {
        handleComplete(newPin);
      }
    }
  };

  const handleDelete = () => {
    if (pin.length > 0) {
      setPin(pin.slice(0, -1));
    }
  };

  return (
    <div style={{ 
      padding: 'var(--space-24)', 
      display: 'flex', 
      flexDirection: 'column', 
      height: '100%', 
      backgroundColor: 'var(--color-surface)',
      alignItems: 'center',
      justifyContent: 'center'
    }}>
      <div style={{ textAlign: 'center', marginBottom: 'var(--space-32)' }}>
        <h2 style={{ margin: 0, color: 'var(--color-text-primary)' }}>Enter MPIN</h2>
        <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--space-8)' }}>
          Please enter your 6-digit MPIN to login
        </p>
      </div>

      <div style={{ display: 'flex', gap: '8px', justifyContent: 'center', marginBottom: '32px' }}>
        {[...Array(6)].map((_, i) => (
          <div key={i} style={{
            width: '16px', height: '16px', borderRadius: '50%',
            backgroundColor: i < pin.length ? 'var(--color-primary)' : 'var(--color-divider)'
          }} />
        ))}
      </div>

      <PINPad
        onKeyPress={handleKeyPress}
        onDelete={handleDelete}
      />
    </div>
  );
};
