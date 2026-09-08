import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';

export const Review: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)', display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <Header title="Review Transfer" showBack />
      <div className="page-content" style={{ padding: '16px', flex: 1 }}>
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '16px' }}>
          <h2 style={{ textAlign: 'center', marginBottom: '24px', fontSize: '32px' }}>₹ 500.00</h2>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--color-divider)' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>To</span>
            <strong style={{ textAlign: 'right' }}>Amit Kumar<br/>XXXX1122</strong>
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--color-divider)' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>From</span>
            <strong style={{ textAlign: 'right' }}>Savings Account<br/>XXXX 1234</strong>
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>Note</span>
            <strong>Gift</strong>
          </div>
        </div>
      </div>
      <div style={{ padding: '16px', backgroundColor: 'white' }}>
        <Button fullWidth onClick={() => navigate('/transfer/confirm')}>Confirm</Button>
      </div>
    </div>
  );
};
