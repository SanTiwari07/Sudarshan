import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { Button } from '../components/primitives/Button';

export const Review: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ backgroundColor: 'var(--color-background)', minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header style={{
        backgroundColor: 'var(--color-primary)',
        padding: 'var(--spacing-3) var(--spacing-2)',
        color: 'var(--color-surface)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
      }}>
        <ArrowLeft size={24} onClick={() => navigate(-1)} style={{ cursor: 'pointer' }} />
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Review Transfer</h2>
      </header>

      <div style={{ padding: 'var(--spacing-2)', flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ backgroundColor: 'var(--color-surface)', borderRadius: 'var(--radius-card)', padding: 'var(--spacing-3)', marginBottom: 'var(--spacing-3)' }}>
          <div style={{ textAlign: 'center', marginBottom: 'var(--spacing-4)' }}>
            <p style={{ color: 'var(--color-text-secondary)', margin: '0 0 8px' }}>Amount to Transfer</p>
            <h1 style={{ margin: 0, fontSize: '2rem', color: 'var(--color-primary)' }}>₹5,000.00</h1>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--color-divider)', paddingBottom: 'var(--spacing-2)' }}>
              <span style={{ color: 'var(--color-text-secondary)' }}>To</span>
              <div style={{ textAlign: 'right' }}>
                <p style={{ margin: 0, fontWeight: 500, color: 'var(--color-text-primary)' }}>Rahul Sharma</p>
                <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>ICICI Bank • XXXX-1234</p>
              </div>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--color-divider)', paddingBottom: 'var(--spacing-2)' }}>
              <span style={{ color: 'var(--color-text-secondary)' }}>From</span>
              <div style={{ textAlign: 'right' }}>
                <p style={{ margin: 0, fontWeight: 500, color: 'var(--color-text-primary)' }}>Savings Account</p>
                <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>XXXX-4321</p>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--color-text-secondary)' }}>Remarks</span>
              <span style={{ color: 'var(--color-text-primary)', fontWeight: 500 }}>Payment</span>
            </div>
          </div>
        </div>

        <div style={{ marginTop: 'auto', marginBottom: 'var(--spacing-4)' }}>
          <Button variant="primary" onClick={() => navigate('/transfer/receipt')} style={{ width: '100%', backgroundColor: 'var(--color-secondary)' }}>
            Confirm & Pay
          </Button>
        </div>
      </div>
    </div>
  );
};
