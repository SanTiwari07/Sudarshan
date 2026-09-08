import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { InputField } from '../components/primitives/InputField';
import { Button } from '../components/primitives/Button';

export const Amount: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [amount, setAmount] = useState('');
  const payee = location.state?.payee || { name: 'Unknown Payee', account: 'XXXX' };

  const handleContinue = () => {
    navigate('/transfer/review', { state: { payee, amount } });
  };

  return (
    <div style={{ backgroundColor: 'var(--color-surface)', minHeight: '100%', display: 'flex', flexDirection: 'column' }}>
      <Header title="Enter Amount" showBack />
      
      <div style={{ padding: 'var(--space-24)', flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{ color: 'var(--color-text-secondary)', marginBottom: '8px' }}>Paying</div>
          <div style={{ fontSize: '20px', fontWeight: 600, color: 'var(--color-text-primary)' }}>{payee.name}</div>
          <div style={{ fontSize: '14px', color: 'var(--color-text-secondary)' }}>{payee.account}</div>
        </div>

        <div style={{ marginBottom: '32px' }}>
          <InputField
            label="Amount (₹)"
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0.00"
          />
        </div>

        <div style={{ marginTop: 'auto' }}>
          <Button 
            variant="primary" 
            fullWidth 
            onClick={handleContinue}
            disabled={!amount || parseFloat(amount) <= 0}
          >
            Continue
          </Button>
        </div>
      </div>
    </div>
  );
};
