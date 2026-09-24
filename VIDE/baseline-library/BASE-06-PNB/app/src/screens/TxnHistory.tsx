import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { MOCK_TRANSACTIONS } from '../data/mockData';
import { ArrowLeft, Filter } from 'lucide-react';
import { InputField } from '../components/primitives/InputField';

export const TxnHistory: React.FC = () => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');

  const filteredTxns = MOCK_TRANSACTIONS.filter(txn => 
    txn.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

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
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>m-Passbook</h2>
      </div>

      <div style={{ padding: 'var(--spacing-3)' }}>
        <div style={{ display: 'flex', gap: 'var(--spacing-2)', marginBottom: 'var(--spacing-3)' }}>
          <div style={{ flex: 1 }}>
            <InputField 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search transactions..."
            />
          </div>
          <button style={{ 
            width: '48px', 
            height: '48px', 
            backgroundColor: 'var(--color-surface)',
            border: '1px solid var(--color-divider)',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            color: 'var(--color-primary)',
            cursor: 'pointer'
          }}>
            <Filter size={20} />
          </button>
        </div>

        <div style={{ backgroundColor: 'var(--color-surface)', borderRadius: 'var(--radius-card)', padding: 'var(--spacing-2)' }}>
          {filteredTxns.length > 0 ? filteredTxns.map((txn, idx) => (
            <div key={txn.id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--spacing-2) 0' }}>
                <div>
                  <div style={{ fontWeight: 500, marginBottom: '4px' }}>{txn.description}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                    {txn.date} • {txn.id}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ 
                    fontWeight: 600, 
                    color: txn.amount < 0 ? 'var(--color-text-primary)' : 'var(--color-success)' 
                  }}>
                    {txn.amount < 0 ? '-' : '+'}₹{Math.abs(txn.amount).toFixed(2)}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', marginTop: '4px' }}>
                    {txn.type}
                  </div>
                </div>
              </div>
              {idx < filteredTxns.length - 1 && <div style={{ height: '1px', backgroundColor: 'var(--color-divider)' }} />}
            </div>
          )) : (
            <div style={{ padding: 'var(--spacing-4)', textAlign: 'center', color: 'var(--color-text-secondary)' }}>
              No transactions found.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
