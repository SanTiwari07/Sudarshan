import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

export const Transfer: React.FC = () => {
  const navigate = useNavigate();
  const [payeeName, setPayeeName] = useState('');
  const [accountNumber, setAccountNumber] = useState('');

  const handleContinue = () => {
    if (payeeName && accountNumber) {
      navigate('/transfer/amount', { 
        state: { payeeName, accountNumber } 
      });
    }
  };

  return (
    <div style={{ minHeight: '100vh', backgroundColor: 'var(--color-background)' }}>
      {/* Header */}
      <div style={{ 
        backgroundColor: 'var(--color-primary)', 
        color: 'white',
        padding: 'var(--spacing-3)',
        paddingTop: 'var(--spacing-4)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)'
      }}>
        <button onClick={() => navigate(-1)} style={{ background: 'none', border: 'none', color: 'white', cursor: 'pointer', padding: 0 }}>
          <ArrowLeft size={24} />
        </button>
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Fund Transfer</h2>
      </div>

      <div style={{ padding: 'var(--spacing-3)' }}>
        <h3 style={{ marginBottom: 'var(--spacing-3)', fontSize: '1rem', color: 'var(--color-text-secondary)' }}>Enter Payee Details</h3>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-3)', marginBottom: 'var(--spacing-4)' }}>
          <InputField
            label="Payee Name"
            value={payeeName}
            onChange={(e) => setPayeeName(e.target.value)}
            placeholder="Enter name"
            required
          />
          <InputField
            label="Account Number"
            value={accountNumber}
            onChange={(e) => setAccountNumber(e.target.value)}
            placeholder="Enter account number"
            type="number"
            required
          />
        </div>

        <Button 
          variant="primary" 
          fullWidth 
          disabled={!payeeName || !accountNumber}
          onClick={handleContinue}
        >
          Continue
        </Button>
      </div>
    </div>
  );
};
