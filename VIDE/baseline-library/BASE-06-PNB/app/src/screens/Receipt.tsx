import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Check, Share2, Home } from 'lucide-react';
import { Button } from '../components/primitives/Button';

export const Receipt: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const txDetails = location.state || { payeeName: 'Unknown', accountNumber: 'XXXX', amount: 0, fromAccount: 'XXXX', remarks: '' };

  const refNumber = `PNB${Math.floor(Math.random() * 1000000000)}`;
  const date = new Date().toLocaleString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: true
  });

  return (
    <div style={{ minHeight: '100vh', backgroundColor: 'var(--color-primary)', display: 'flex', flexDirection: 'column' }}>
      <div style={{ flex: 1, padding: 'var(--spacing-3)', paddingTop: '20vh', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        
        <div style={{ 
          width: '64px', height: '64px', 
          backgroundColor: 'var(--color-success)', 
          borderRadius: '50%',
          display: 'flex', justifyContent: 'center', alignItems: 'center',
          color: 'white',
          marginBottom: 'var(--spacing-3)'
        }}>
          <Check size={32} />
        </div>

        <h2 style={{ color: 'white', margin: '0 0 8px 0' }}>Transfer Successful!</h2>
        <p style={{ color: 'rgba(255,255,255,0.8)', margin: '0 0 var(--spacing-4) 0' }}>{date}</p>

        <div style={{ 
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          width: '100%',
          padding: 'var(--spacing-4)',
          boxShadow: '0 4px 16px rgba(0,0,0,0.1)'
        }}>
          <div style={{ textAlign: 'center', marginBottom: 'var(--spacing-3)' }}>
            <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>Amount Sent</div>
            <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--color-primary)', margin: '8px 0' }}>
              ₹{txDetails.amount.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
            </div>
            <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>To {txDetails.payeeName}</div>
          </div>

          <div style={{ height: '1px', borderTop: '1px dashed var(--color-divider)', margin: 'var(--spacing-3) 0' }} />

          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>Ref No.</span>
              <span style={{ fontWeight: 500, fontSize: '0.875rem' }}>{refNumber}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>From Account</span>
              <span style={{ fontWeight: 500, fontSize: '0.875rem' }}>{txDetails.fromAccount}</span>
            </div>
          </div>
        </div>
      </div>

      <div style={{ padding: 'var(--spacing-3)', backgroundColor: 'var(--color-surface)', borderTopLeftRadius: '24px', borderTopRightRadius: '24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--spacing-2)' }}>
          <Button variant="secondary" onClick={() => {}} style={{ display: 'flex', justifyContent: 'center', gap: '8px' }}>
            <Share2 size={18} /> Share
          </Button>
          <Button variant="primary" onClick={() => navigate('/home')} style={{ display: 'flex', justifyContent: 'center', gap: '8px' }}>
            <Home size={18} /> Home
          </Button>
        </div>
      </div>
    </div>
  );
};
