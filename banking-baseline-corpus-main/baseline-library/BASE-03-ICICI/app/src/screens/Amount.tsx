import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, IndianRupee } from 'lucide-react';
import { Button } from '../components/primitives/Button';

export const Amount: React.FC = () => {
  const navigate = useNavigate();
  const [amount, setAmount] = useState('');

  const handleContinue = () => {
    if (amount) navigate('/transfer/review');
  };

  return (
    <div style={{ backgroundColor: 'var(--color-surface)', minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header style={{
        backgroundColor: 'var(--color-primary)',
        padding: 'var(--spacing-3) var(--spacing-2)',
        color: 'var(--color-surface)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
      }}>
        <ArrowLeft size={24} onClick={() => navigate(-1)} style={{ cursor: 'pointer' }} />
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Enter Amount</h2>
      </header>

      <div style={{ padding: 'var(--spacing-3)', flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ textAlign: 'center', marginBottom: 'var(--spacing-4)' }}>
          <p style={{ color: 'var(--color-text-secondary)', marginBottom: '8px' }}>Paying</p>
          <h3 style={{ margin: 0, fontSize: '1.5rem', color: 'var(--color-text-primary)' }}>Rahul Sharma</h3>
          <p style={{ margin: '4px 0 0', color: 'var(--color-text-secondary)' }}>ICICI Bank • XXXX-1234</p>
        </div>

        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', marginBottom: 'var(--spacing-4)' }}>
          <IndianRupee size={32} color="var(--color-text-secondary)" />
          <input
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0"
            style={{
              fontSize: '3rem',
              fontWeight: 'bold',
              border: 'none',
              outline: 'none',
              width: '100%',
              textAlign: 'center',
              color: 'var(--color-text-primary)',
              background: 'transparent'
            }}
            autoFocus
          />
        </div>

        <div style={{ marginTop: 'auto', marginBottom: 'var(--spacing-4)' }}>
          <Button variant="primary" onClick={handleContinue} disabled={!amount} style={{ width: '100%', backgroundColor: 'var(--color-secondary)' }}>
            Continue
          </Button>
        </div>
      </div>
    </div>
  );
};
