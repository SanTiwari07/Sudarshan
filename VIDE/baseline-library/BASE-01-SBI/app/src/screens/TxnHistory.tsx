import React from 'react';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';

export const TxnHistory: React.FC = () => {

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)', height: '100vh', overflowY: 'auto' }}>
      <Header title="Transaction History" showBack />
      <div className="page-content" style={{ padding: '16px' }}>
        <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '16px' }}>
          {mockUser.transactions.map(txn => (
            <div key={txn.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '16px 0', borderBottom: '1px solid var(--color-divider)' }}>
              <div>
                <p style={{ fontWeight: 500 }}>{txn.description}</p>
                <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>{txn.date}</p>
              </div>
              <div style={{ color: txn.amount > 0 ? 'var(--color-success)' : 'var(--color-text-primary)' }}>
                {txn.amount > 0 ? '+' : ''}{txn.amount.toFixed(2)}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
