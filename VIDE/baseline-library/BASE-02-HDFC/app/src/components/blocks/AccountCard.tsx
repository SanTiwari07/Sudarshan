import React from 'react';

interface AccountCardProps {
  id: string;
  type: string;
  number: string;
  balance: number;
  currency?: string;
  onClick?: () => void;
}

export const AccountCard: React.FC<AccountCardProps> = ({ type, number, balance, currency = 'INR', onClick }) => {
  return (
    <div 
      onClick={onClick}
      style={{
        backgroundColor: 'var(--color-surface)',
        borderRadius: 'var(--radius-card)',
        padding: 'var(--space-16)',
        marginBottom: 'var(--space-16)',
        boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
        cursor: onClick ? 'pointer' : 'default',
        border: '1px solid var(--color-divider)'
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
        <span style={{ color: 'var(--color-text-secondary)', fontSize: '14px' }}>{type}</span>
      </div>
      <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '16px' }}>
        {number}
      </div>
      <div>
        <div style={{ color: 'var(--color-text-secondary)', fontSize: '12px' }}>Available Balance</div>
        <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--color-primary)' }}>
          {currency === 'INR' ? '₹' : currency} {balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
        </div>
      </div>
    </div>
  );
};
