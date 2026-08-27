import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';

export const Transfer: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%' }}>
      <Header title="Fund Transfer" showBack onBack={() => navigate('/home')} />
      
      <div style={{ padding: 'var(--space-16)' }}>
        <h3 style={{ margin: '0 0 16px 0', fontSize: '16px', color: 'var(--color-text-primary)' }}>Select Payee</h3>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {mockUser.payees.map(payee => (
            <div 
              key={payee.id}
              onClick={() => navigate('/transfer/amount', { state: { payee } })}
              style={{
                backgroundColor: 'var(--color-surface)',
                padding: '16px',
                borderRadius: 'var(--radius-card)',
                boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
                display: 'flex',
                alignItems: 'center',
                cursor: 'pointer',
                border: '1px solid var(--color-divider)'
              }}
            >
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '20px',
                backgroundColor: 'var(--color-primary)',
                color: 'white',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 600,
                marginRight: '16px'
              }}>
                {payee.name.charAt(0)}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                  {payee.name}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                  {payee.bank} • {payee.account}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
