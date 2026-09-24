import React from 'react';
import { useParams } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';
import { TransactionRow } from '../components/blocks/TransactionRow';

export const TxnHistory: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const account = mockUser.accounts.find(a => a.id === id) || mockUser.accounts[0];

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%' }}>
      <Header title="Transaction History" showBack />
      
      <div style={{ padding: 'var(--space-16)' }}>
        <div style={{ marginBottom: '16px', color: 'var(--color-text-secondary)', fontSize: '14px' }}>
          Showing transactions for {account.number}
        </div>
        
        <div style={{
          backgroundColor: 'var(--color-surface)',
          padding: '16px',
          borderRadius: 'var(--radius-card)',
          boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
        }}>
          {mockUser.transactions.map(txn => (
            <TransactionRow key={txn.id} {...txn} type={txn.type as "debit" | "credit"} />
          ))}
        </div>
      </div>
    </div>
  );
};
