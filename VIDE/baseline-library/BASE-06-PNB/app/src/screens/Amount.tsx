import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import { MOCK_ACCOUNTS } from '../data/mockData';

export const Amount: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const payee = location.state || { payeeName: 'Unknown', accountNumber: 'XXXX' };
  
  const [amount, setAmount] = useState('');
  const [remarks, setRemarks] = useState('');
  const account = MOCK_ACCOUNTS[0];

  const handleContinue = () => {
    if (amount && Number(amount) > 0) {
      navigate('/transfer/review', { 
        state: { ...payee, amount: Number(amount), remarks, fromAccount: account.accountNumber } 
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
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Enter Amount</h2>
      </div>

      <div style={{ padding: 'var(--spacing-3)' }}>
        <div style={{ 
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-3)',
          marginBottom: 'var(--spacing-3)',
          boxShadow: '0 2px 8px rgba(0,0,0,0.05)'
        }}>
          <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>Paying to</div>
          <div style={{ fontSize: '1.125rem', fontWeight: 500, margin: '4px 0' }}>{payee.payeeName}</div>
          <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>Acc: {payee.accountNumber}</div>
        </div>

        <div style={{ textAlign: 'center', margin: 'var(--spacing-4) 0' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--color-primary)', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
            <span style={{ fontSize: '1.5rem', marginRight: '8px' }}>₹</span>
            <input 
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="0"
              style={{
                border: 'none',
                background: 'transparent',
                fontSize: '2.5rem',
                fontWeight: 700,
                color: 'var(--color-primary)',
                width: '150px',
                textAlign: 'left',
                outline: 'none'
              }}
              autoFocus
            />
          </div>
          <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '8px' }}>
            Available Balance: ₹{account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
          </div>
        </div>

        <div style={{ marginBottom: 'var(--spacing-4)' }}>
          <input 
            type="text"
            value={remarks}
            onChange={(e) => setRemarks(e.target.value)}
            placeholder="Add Remarks (Optional)"
            style={{
              width: '100%',
              padding: '12px',
              border: '1px solid var(--color-divider)',
              borderRadius: 'var(--radius-md)',
              fontSize: '1rem',
              outline: 'none'
            }}
          />
        </div>

        <Button 
          variant="primary" 
          fullWidth 
          disabled={!amount || Number(amount) <= 0 || Number(amount) > account.balance}
          onClick={handleContinue}
        >
          Proceed to Pay
        </Button>
      </div>
    </div>
  );
};
