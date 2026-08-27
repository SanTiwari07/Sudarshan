import React from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckCircle, Home } from 'lucide-react';
import { Button } from '../components/primitives/Button';

export const Receipt: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ backgroundColor: 'var(--color-surface)', minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: 'var(--spacing-4) var(--spacing-3)',
      }}>
        <div style={{ marginTop: '40px', marginBottom: 'var(--spacing-3)' }}>
          <CheckCircle size={80} color="var(--color-success)" />
        </div>
        
        <h1 style={{ color: 'var(--color-success)', margin: '0 0 var(--spacing-1)', textAlign: 'center' }}>Payment Successful</h1>
        <p style={{ color: 'var(--color-text-secondary)', marginBottom: 'var(--spacing-4)', textAlign: 'center' }}>
          Reference ID: 123456789012
        </p>

        <div style={{
          width: '100%',
          backgroundColor: 'var(--color-background)',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-3)',
          display: 'flex',
          flexDirection: 'column',
          gap: 'var(--spacing-3)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>Amount</span>
            <span style={{ fontWeight: 'bold', color: 'var(--color-text-primary)' }}>₹5,000.00</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>To</span>
            <span style={{ fontWeight: 500, color: 'var(--color-text-primary)', textAlign: 'right' }}>Rahul Sharma<br/>XXXX-1234</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>Date & Time</span>
            <span style={{ fontWeight: 500, color: 'var(--color-text-primary)' }}>12 Aug 2026, 14:30</span>
          </div>
        </div>

        <div style={{ marginTop: 'auto', width: '100%', display: 'flex', gap: 'var(--spacing-2)' }}>
          <Button variant="outline" onClick={() => {}} style={{ flex: 1, color: 'var(--color-primary)', borderColor: 'var(--color-primary)' }}>
            Share
          </Button>
          <Button variant="primary" onClick={() => navigate('/home')} style={{ flex: 1, backgroundColor: 'var(--color-primary)', display: 'flex', gap: '8px', alignItems: 'center', justifyContent: 'center' }}>
            <Home size={20} /> Back to Home
          </Button>
        </div>
      </div>
    </div>
  );
};
