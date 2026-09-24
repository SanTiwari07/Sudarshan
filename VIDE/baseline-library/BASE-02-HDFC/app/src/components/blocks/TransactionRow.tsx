import React from 'react';

interface TransactionRowProps {
  date: string;
  description: string;
  amount: number;
  type: 'credit' | 'debit';
}

export const TransactionRow: React.FC<TransactionRowProps> = ({ date, description, amount, type }) => {
  const isCredit = type === 'credit';
  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: 'var(--space-16) 0',
      borderBottom: '1px solid var(--color-divider)'
    }}>
      <div>
        <div style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
          {description}
        </div>
        <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>
          {date}
        </div>
      </div>
      <div style={{
        fontWeight: 700,
        color: isCredit ? 'var(--color-success)' : 'var(--color-text-primary)'
      }}>
        {isCredit ? '+' : '-'} ₹{Math.abs(amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}
      </div>
    </div>
  );
};
