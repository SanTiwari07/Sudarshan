import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';
import { TransactionRow } from '../components/blocks/TransactionRow';
import { Button } from '../components/primitives/Button';

export const AccountDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const account = mockUser.accounts.find(a => a.id === id) || mockUser.accounts[0];
  const recentTxns = mockUser.transactions.slice(0, 5);

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%' }}>
      <Header title="Account Details" showBack />
      
      <div style={{ padding: 'var(--space-16)' }}>
        <div style={{ 
          backgroundColor: 'var(--color-primary)', 
          color: 'white',
          padding: '24px',
          borderRadius: 'var(--radius-card)',
          marginBottom: '16px'
        }}>
          <div style={{ fontSize: '14px', opacity: 0.9, marginBottom: '8px' }}>Available Balance</div>
          <div style={{ fontSize: '28px', fontWeight: 700, marginBottom: '16px' }}>
            ₹{account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '14px', opacity: 0.9 }}>
            <span>{account.type}</span>
            <span>{account.number}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', opacity: 0.8, marginTop: '8px' }}>
            <span>IFSC: {account.ifsc}</span>
          </div>
        </div>

        <div style={{
          backgroundColor: 'var(--color-surface)',
          padding: '16px',
          borderRadius: 'var(--radius-card)',
          boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
        }}>
          <h3 style={{ margin: '0 0 16px 0', fontSize: '16px', color: 'var(--color-text-primary)' }}>Recent Transactions</h3>
          <div>
            {recentTxns.map(txn => (
              <TransactionRow key={txn.id} {...txn} type={txn.type as "debit" | "credit"} />
            ))}
          </div>
          <div style={{ marginTop: '16px' }}>
            <Button variant="secondary" fullWidth onClick={() => navigate(`/accounts/${account.id}/transactions`)}>
              View All Transactions
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
