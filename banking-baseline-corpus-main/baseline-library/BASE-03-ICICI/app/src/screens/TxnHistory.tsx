import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Search, Filter } from 'lucide-react';
import { InputField } from '../components/primitives/InputField';

export const TxnHistory: React.FC = () => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');

  const mockTxns = [
    { id: 1, name: 'Amazon', date: '12 Aug 2026', amount: '-₹1,299.00', color: 'var(--color-error)' },
    { id: 2, name: 'Salary', date: '01 Aug 2026', amount: '+₹85,000.00', color: 'var(--color-success)' },
    { id: 3, name: 'Zomato', date: '30 Jul 2026', amount: '-₹450.00', color: 'var(--color-error)' },
    { id: 4, name: 'Uber', date: '28 Jul 2026', amount: '-₹320.00', color: 'var(--color-error)' },
    { id: 5, name: 'Fund Transfer', date: '25 Jul 2026', amount: '+₹5,000.00', color: 'var(--color-success)' },
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
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Transaction History</h2>
      </header>

      <div style={{ padding: 'var(--spacing-2)' }}>
        <div style={{ display: 'flex', gap: 'var(--spacing-2)', marginBottom: 'var(--spacing-3)' }}>
          <div style={{ flex: 1 }}>
            <InputField 
              placeholder="Search transactions" 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              icon={<Search size={20} />} 
            />
          </div>
          <div style={{
            backgroundColor: 'var(--color-surface)',
            borderRadius: 'var(--radius-md)',
            padding: '0 var(--spacing-2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer'
          }}>
            <Filter size={20} color="var(--color-primary)" />
          </div>
        </div>

        <div style={{ backgroundColor: 'var(--color-surface)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
          {mockTxns.map((txn, idx) => (
            <div key={txn.id} style={{
              display: 'flex',
              justifyContent: 'space-between',
              padding: 'var(--spacing-3)',
              borderBottom: idx < mockTxns.length - 1 ? '1px solid var(--color-divider)' : 'none'
            }}>
              <div>
                <h4 style={{ margin: '0 0 4px', color: 'var(--color-text-primary)' }}>{txn.name}</h4>
                <p style={{ margin: '0 0 2px', fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>{txn.date}</p>
                <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>Ref: {100000 + txn.id}</p>
              </div>
              <span style={{ fontWeight: 'bold', color: txn.color, fontSize: '1.125rem' }}>{txn.amount}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
