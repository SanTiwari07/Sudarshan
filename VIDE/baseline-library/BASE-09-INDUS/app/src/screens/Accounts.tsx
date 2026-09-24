import React from 'react';
import { useNavigate } from 'react-router-dom';
import { MOCK_ACCOUNTS } from './mockData';

const Accounts: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <h2 style={{ color: 'var(--color-primary)' }}>My Accounts</h2>
      {MOCK_ACCOUNTS.map(acc => (
        <div key={acc.id} 
             onClick={() => navigate('/accounts/' + acc.id)}
             style={{
               backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)',
               borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)',
               cursor: 'pointer'
             }}>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>{acc.type}</p>
          <h3 style={{ margin: 'var(--space-4) 0' }}>{acc.balance}</h3>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>A/C: {acc.number}</p>
        </div>
      ))}
    </div>
  );
};
export default Accounts;