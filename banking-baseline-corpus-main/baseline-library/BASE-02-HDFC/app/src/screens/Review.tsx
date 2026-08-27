import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { mockUser } from '../data/mockData';

export const Review: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { payee, amount } = location.state || { payee: { name: 'Unknown' }, amount: '0' };
  const fromAccount = mockUser.accounts[0]; // Assuming first account is default

  const handleConfirm = () => {
    // Navigate to receipt
    navigate('/transfer/receipt', { state: { payee, amount, success: true } });
  };

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%', display: 'flex', flexDirection: 'column' }}>
      <Header title="Review Transfer" showBack />
      
      <div style={{ padding: 'var(--space-16)', flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{
          backgroundColor: 'var(--color-surface)',
          padding: '24px',
          borderRadius: 'var(--radius-card)',
          boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
          marginBottom: '24px'
        }}>
          <div style={{ textAlign: 'center', marginBottom: '24px' }}>
            <div style={{ fontSize: '32px', fontWeight: 700, color: 'var(--color-primary)', marginBottom: '8px' }}>
              ₹{parseFloat(amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', marginBottom: '4px' }}>From Account</div>
              <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{fromAccount.type}</div>
              <div style={{ fontSize: '14px', color: 'var(--color-text-secondary)' }}>{fromAccount.number}</div>
            </div>
            
            <div style={{ height: '1px', backgroundColor: 'var(--color-divider)' }} />
            
            <div>
              <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', marginBottom: '4px' }}>To Payee</div>
              <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{payee.name}</div>
              <div style={{ fontSize: '14px', color: 'var(--color-text-secondary)' }}>{payee.account}</div>
            </div>
          </div>
        </div>

        <div style={{ marginTop: 'auto' }}>
          <Button variant="primary" fullWidth onClick={handleConfirm}>
            Confirm Transfer
          </Button>
        </div>
      </div>
    </div>
  );
};
