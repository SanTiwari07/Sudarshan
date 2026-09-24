import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';
import { AccountCard } from '../components/blocks/AccountCard';

export const Accounts: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%' }}>
      <Header title="My Accounts" showBack onBack={() => navigate('/home')} />
      <div style={{ padding: 'var(--space-16)' }}>
        {mockUser.accounts.map(account => (
          <AccountCard 
            key={account.id} 
            {...account} 
            onClick={() => navigate(`/accounts/${account.id}`)} 
          />
        ))}
      </div>
    </div>
  );
};
