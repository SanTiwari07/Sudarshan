import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';

export const Receipt: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', height: '100vh', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Receipt" />
      <div className="page-content" style={{ padding: '24px', flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ width: '64px', height: '64px', borderRadius: '32px', backgroundColor: 'var(--color-success)', color: 'white', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '32px', marginBottom: '24px' }}>
          ✓
        </div>
        <h2 style={{ marginBottom: '8px' }}>Payment successful</h2>
        <p style={{ color: 'var(--color-text-secondary)', marginBottom: '32px' }}>Transaction ID: TXN987654321</p>
        
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '16px', width: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0' }}>
            <span>To</span>
            <strong>Amit Kumar</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0' }}>
            <span>Amount</span>
            <strong>₹ 500.00</strong>
          </div>
        </div>
      </div>
      <div style={{ padding: '16px', backgroundColor: 'white' }}>
        <Button fullWidth onClick={() => navigate('/home')}>Done</Button>
      </div>
    </div>
  );
};
