import React from 'react';
import { useNavigate } from 'react-router-dom';
import { MOCK_ACCOUNTS } from '../data/mockData';
import { ChevronRight, ArrowLeft } from 'lucide-react';

export const Accounts: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ paddingBottom: '80px', minHeight: '100vh', backgroundColor: 'var(--color-background)' }}>
      {/* Header */}
      <div style={{ 
        backgroundColor: 'var(--color-primary)', 
        color: 'white',
        padding: 'var(--spacing-3)',
        paddingTop: 'var(--spacing-4)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)'
      }}>
        <button onClick={() => navigate(-1)} style={{ background: 'none', border: 'none', color: 'white', cursor: 'pointer', padding: 0 }}>
          <ArrowLeft size={24} />
        </button>
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>My Accounts</h2>
      </div>

      <div style={{ padding: 'var(--spacing-3)' }}>
        {MOCK_ACCOUNTS.map((account) => (
          <div 
            key={account.id}
            onClick={() => navigate('/accounts/details')}
            style={{ 
              backgroundColor: 'var(--color-surface)',
              borderRadius: 'var(--radius-card)',
              padding: 'var(--spacing-3)',
              marginBottom: 'var(--spacing-2)',
              boxShadow: '0 2px 8px rgba(0,0,0,0.05)',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-2)' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--color-text-primary)' }}>{account.type}</h3>
                <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>{account.accountNumber}</span>
              </div>
              <ChevronRight color="var(--color-text-secondary)" />
            </div>
            
            <div style={{ height: '1px', backgroundColor: 'var(--color-divider)', margin: 'var(--spacing-2) 0' }} />
            
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>Available Balance</span>
              <span style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--color-primary)' }}>
                {account.currency} {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
