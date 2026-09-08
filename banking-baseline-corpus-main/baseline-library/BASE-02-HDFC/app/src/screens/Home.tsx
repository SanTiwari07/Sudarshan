import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';
import { AccountCard } from '../components/blocks/AccountCard';
import { TransactionRow } from '../components/blocks/TransactionRow';
import { Send, CreditCard, Receipt, FileText } from 'lucide-react';

export const Home: React.FC = () => {
  const navigate = useNavigate();
  const mainAccount = mockUser.accounts[0];
  const recentTxns = mockUser.transactions.slice(0, 3);

  const quickActions = [
    { icon: Send, label: 'Transfer', path: '/transfer' },
    { icon: Receipt, label: 'Pay Bills', path: '/services' },
    { icon: CreditCard, label: 'Cards', path: '/cards' },
    { icon: FileText, label: 'Deposits', path: '/services' },
  ];

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%' }}>
      <Header title={`Hi, ${mockUser.name.split(' ')[0]}`} showNotifications />
      
      <div style={{ padding: 'var(--space-16)' }}>
        <AccountCard 
          {...mainAccount} 
          onClick={() => navigate(`/accounts/${mainAccount.id}`)} 
        />

        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(4, 1fr)', 
          gap: '8px', 
          marginBottom: '24px',
          backgroundColor: 'var(--color-surface)',
          padding: '16px',
          borderRadius: 'var(--radius-card)',
          boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
        }}>
          {quickActions.map((action, idx) => (
            <div 
              key={idx} 
              onClick={() => navigate(action.path)}
              style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', cursor: 'pointer' }}
            >
              <div style={{ 
                width: '48px', height: '48px', 
                backgroundColor: 'var(--color-bg)', 
                borderRadius: '24px', 
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--color-primary)',
                marginBottom: '8px'
              }}>
                <action.icon size={24} />
              </div>
              <span style={{ fontSize: '12px', textAlign: 'center', color: 'var(--color-text-primary)' }}>
                {action.label}
              </span>
            </div>
          ))}
        </div>

        <div style={{
          backgroundColor: 'var(--color-surface)',
          padding: '16px',
          borderRadius: 'var(--radius-card)',
          boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ margin: 0, fontSize: '16px', color: 'var(--color-text-primary)' }}>Recent Activity</h3>
            <span 
              onClick={() => navigate(`/accounts/${mainAccount.id}/transactions`)}
              style={{ color: 'var(--color-primary)', fontSize: '14px', fontWeight: 600, cursor: 'pointer' }}
            >
              View All
            </span>
          </div>
          <div>
            {recentTxns.map(txn => (
              <TransactionRow key={txn.id} {...txn} type={txn.type as "debit" | "credit"} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
