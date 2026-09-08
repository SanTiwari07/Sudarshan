import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { mockUser } from '../data/mockData';

export const AccountDetails: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams();
  const account = mockUser.accounts.find(a => a.id === id) || mockUser.accounts[0];

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Account Details" showBack />
      <div className="page-content" style={{ padding: '16px' }}>
        <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '16px' }}>
          <p style={{ textAlign: 'center', color: 'var(--color-text-secondary)' }}>Available Balance</p>
          <h2 style={{ textAlign: 'center', fontSize: '28px', margin: '16px 0', color: 'var(--color-primary)' }}>
            {account.currency} {account.balance.toFixed(2)}
          </h2>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderTop: '1px solid var(--color-divider)' }}>
            <span>Account Number</span>
            <strong>{account.number}</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderTop: '1px solid var(--color-divider)' }}>
            <span>Account Type</span>
            <strong>{account.type}</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderTop: '1px solid var(--color-divider)' }}>
            <span>IFSC</span>
            <strong>SBIN0001234</strong>
          </div>
        </div>

        <div style={{ marginTop: '24px' }}>
          <Button fullWidth onClick={() => navigate(`/accounts/${account.id}/transactions`)}>View all transactions</Button>
        </div>
      </div>
    </div>
  );
};
