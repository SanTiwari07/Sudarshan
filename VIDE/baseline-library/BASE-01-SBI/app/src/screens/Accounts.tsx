import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';

export const Accounts: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Accounts" showBack />
      <div className="page-content" style={{ padding: '16px' }}>
        {mockUser.accounts.map(acc => (
          <div 
            key={acc.id}
            onClick={() => navigate(`/accounts/${acc.id}`)}
            style={{ 
              backgroundColor: 'white', 
              padding: '20px', 
              borderRadius: '16px',
              marginBottom: '16px',
              cursor: 'pointer'
            }}
          >
            <p style={{ color: 'var(--color-text-secondary)' }}>{acc.type}</p>
            <h3 style={{ fontSize: '20px', margin: '8px 0' }}>{acc.currency} {acc.balance.toFixed(2)}</h3>
            <p>{acc.number}</p>
          </div>
        ))}
      </div>
    </div>
  );
};
