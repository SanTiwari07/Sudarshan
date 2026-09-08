import React from 'react';
import { Send, Wallet, Receipt, CreditCard } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const Home: React.FC = () => {
  const navigate = useNavigate();

  const quickActions = [
    { icon: Send, label: 'Send Money', color: 'var(--color-primary)', path: '/transfer' },
    { icon: Wallet, label: 'Pay Bills', color: 'var(--color-secondary)' },
    { icon: Receipt, label: 'Recharge', color: 'var(--color-accent)' },
    { icon: CreditCard, label: 'Cards', color: 'var(--color-text-primary)' },
  ];

  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-24)' }}>
      {/* Account Card */}
      <div 
        onClick={() => navigate('/accounts')}
        style={{
          backgroundColor: 'var(--color-surface)',
          padding: 'var(--space-24)',
          borderRadius: 'var(--radius-card)',
          boxShadow: 'var(--elevation-1)',
          cursor: 'pointer'
        }}
      >
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem', marginBottom: 'var(--space-8)' }}>Savings Account</p>
        <h2 style={{ fontSize: '1.5rem', marginBottom: 'var(--space-4)' }}>₹ 45,678.90</h2>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>A/C No: XXXXXX4321</p>
      </div>

      {/* Quick Actions Grid */}
      <div>
        <h3 style={{ marginBottom: 'var(--space-16)', fontSize: '1.125rem' }}>Quick Actions</h3>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 'var(--space-12)'
        }}>
          {quickActions.map((action, index) => (
            <div key={index} 
                 onClick={() => action.path ? navigate(action.path) : null}
                 style={{
                   display: 'flex',
                   flexDirection: 'column',
                   alignItems: 'center',
                   gap: 'var(--space-8)',
                   cursor: action.path ? 'pointer' : 'default'
                 }}>
              <div style={{
                backgroundColor: 'var(--color-surface)',
                padding: 'var(--space-12)',
                borderRadius: 'var(--radius-card)',
                boxShadow: 'var(--elevation-1)',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center'
              }}>
                <action.icon size={24} color={action.color} />
              </div>
              <span style={{ fontSize: '0.75rem', textAlign: 'center', color: 'var(--color-text-secondary)' }}>
                {action.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Home;
