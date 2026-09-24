import React from 'react';
import { useNavigate } from 'react-router-dom';
import { mockAccounts } from '../data/mockData';

export const Accounts: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col h-full bg-[var(--color-bg)]">
      {/* Header */}
      <div className="flex items-center p-4 text-white" style={{ backgroundColor: 'var(--color-primary)' }}>
        <button onClick={() => navigate(-1)} className="mr-4 text-xl">
          ←
        </button>
        <h1 className="text-lg font-bold">My Accounts</h1>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {mockAccounts.map(account => (
          <div 
            key={account.id} 
            className="bg-white rounded-[var(--radius-card)] p-4 shadow-sm cursor-pointer border-l-4"
            style={{ borderLeftColor: 'var(--color-primary)' }}
            onClick={() => navigate(`/accounts/${account.id}`)}
          >
            <div className="flex justify-between items-start mb-2">
              <div>
                <h3 className="font-bold">{account.type}</h3>
                <p className="text-sm text-[var(--color-text-secondary)]">{account.accountNumber}</p>
              </div>
              <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded">
                {account.status}
              </span>
            </div>
            <div className="mt-4">
              <p className="text-xs text-[var(--color-text-secondary)] mb-1">Available Balance</p>
              <p className="text-xl font-bold">{account.currency} {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
