import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { CheckCircle } from 'lucide-react';

export const Receipt: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { payee, amount } = location.state || { payee: { name: 'Unknown' }, amount: '0' };
  
  const handleDone = () => {
    navigate('/home');
  };

  return (
    <div style={{ backgroundColor: 'var(--color-surface)', minHeight: '100%', display: 'flex', flexDirection: 'column' }}>
      <Header title="Receipt" />
      
      <div style={{ padding: 'var(--space-24)', flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{
          width: '64px',
          height: '64px',
          borderRadius: '32px',
          backgroundColor: 'rgba(23, 140, 78, 0.1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--color-success)',
          marginBottom: '24px'
        }}>
          <CheckCircle size={40} />
        </div>
        
        <h2 style={{ margin: '0 0 8px 0', color: 'var(--color-text-primary)', fontSize: '24px' }}>Transfer Successful</h2>
        <p style={{ color: 'var(--color-text-secondary)', textAlign: 'center', marginBottom: '32px' }}>
          Your payment of <strong>₹{parseFloat(amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</strong> to <strong>{payee.name}</strong> was successful.
        </p>

        <div style={{
          width: '100%',
          backgroundColor: 'var(--color-bg)',
          padding: '16px',
          borderRadius: 'var(--radius-card)',
          marginBottom: '48px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ color: 'var(--color-text-secondary)', fontSize: '14px' }}>Transaction ID</span>
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)', fontSize: '14px' }}>TXN{Math.floor(Math.random() * 1000000000)}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--color-text-secondary)', fontSize: '14px' }}>Date & Time</span>
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)', fontSize: '14px' }}>{new Date().toLocaleString()}</span>
          </div>
        </div>

        <div style={{ width: '100%', marginTop: 'auto' }}>
          <Button variant="primary" fullWidth onClick={handleDone}>
            Done
          </Button>
        </div>
      </div>
    </div>
  );
};
