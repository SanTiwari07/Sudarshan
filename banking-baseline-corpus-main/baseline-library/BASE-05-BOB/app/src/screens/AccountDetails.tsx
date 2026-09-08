import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { mockAccounts } from '../data/mockData';
import { Button } from '../components/Button';

export const AccountDetails: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const account = mockAccounts.find(a => a.id === id) || mockAccounts[0];

  return (
    <div className="flex flex-col h-full bg-[var(--color-bg)]">
      {/* Header */}
      <div className="flex items-center p-4 text-white" style={{ backgroundColor: 'var(--color-primary)' }}>
        <button onClick={() => navigate(-1)} className="mr-4 text-xl">
          ←
        </button>
        <h1 className="text-lg font-bold">Account Details</h1>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="bg-white p-6 shadow-sm mb-4">
          <p className="text-sm text-[var(--color-text-secondary)] mb-1">Available Balance</p>
          <h2 className="text-3xl font-bold mb-4 text-[var(--color-primary)]">
            {account.currency} {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
          </h2>
          
          <div className="grid grid-cols-2 gap-4 mt-6">
            <div>
              <p className="text-xs text-[var(--color-text-secondary)] mb-1">Account Number</p>
              <p className="font-medium">{account.accountNumber}</p>
            </div>
            <div>
              <p className="text-xs text-[var(--color-text-secondary)] mb-1">Account Type</p>
              <p className="font-medium">{account.type}</p>
            </div>
            <div>
              <p className="text-xs text-[var(--color-text-secondary)] mb-1">Status</p>
              <p className="font-medium text-green-600">{account.status}</p>
            </div>
            <div>
              <p className="text-xs text-[var(--color-text-secondary)] mb-1">IFSC Code</p>
              <p className="font-medium">BARB0MOCKIN</p>
            </div>
          </div>
        </div>

        <div className="p-4 space-y-4">
          <Button variant="primary" fullWidth onClick={() => navigate(`/accounts/${account.id}/transactions`)}>
            View Statement
          </Button>
          <Button variant="outline" fullWidth onClick={() => navigate('/transfer')}>
            Fund Transfer
          </Button>
        </div>
      </div>
    </div>
  );
};
