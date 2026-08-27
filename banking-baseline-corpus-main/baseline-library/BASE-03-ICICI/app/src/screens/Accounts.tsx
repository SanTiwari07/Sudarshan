import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, ChevronRight, IndianRupee } from 'lucide-react';

export const Accounts: React.FC = () => {
  const navigate = useNavigate();

  const accounts = [
    { id: '1', type: 'Savings Account', number: 'XXXX-4321', balance: '1,45,230.50' },
    { id: '2', type: 'Current Account', number: 'XXXX-8765', balance: '5,30,000.00' },
    { id: '3', type: 'Fixed Deposit', number: 'XXXX-1122', balance: '10,00,000.00' }
  ];

  return (
    <div style={{ backgroundColor: 'var(--color-background)', minHeight: '100vh', paddingBottom: '80px' }}>
      <header style={{
        backgroundColor: 'var(--color-primary)',
        padding: 'var(--spacing-3) var(--spacing-2)',
        color: 'var(--color-surface)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
      }}>
        <ArrowLeft size={24} onClick={() => navigate(-1)} style={{ cursor: 'pointer' }} />
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>My Accounts</h2>
      </header>

      <div style={{ padding: 'var(--spacing-2)' }}>
        <h3 style={{ color: 'var(--color-text-secondary)', marginBottom: 'var(--spacing-2)', fontSize: '1rem' }}>
          Accounts Summary
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-2)' }}>
          {accounts.map(acc => (
            <div key={acc.id} onClick={() => navigate(`/accounts/${acc.id}`)} style={{
              backgroundColor: 'var(--color-surface)',
              borderRadius: 'var(--radius-card)',
              padding: 'var(--spacing-3)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
              cursor: 'pointer'
            }}>
              <div>
                <p style={{ margin: '0 0 4px', fontWeight: 500, color: 'var(--color-text-primary)' }}>{acc.type}</p>
                <p style={{ margin: '0 0 8px', fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>{acc.number}</p>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--color-text-primary)' }}>
                  <IndianRupee size={16} />
                  <span style={{ fontSize: '1.25rem', fontWeight: 'bold' }}>{acc.balance}</span>
                </div>
              </div>
              <ChevronRight size={24} color="var(--color-text-secondary)" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
