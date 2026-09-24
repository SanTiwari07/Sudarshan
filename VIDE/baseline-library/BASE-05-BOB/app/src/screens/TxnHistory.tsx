import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { mockTransactions } from '../data/mockData';
import { Chip } from '../components/Chip';

export const TxnHistory: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  
  const [filter, setFilter] = useState('All');
  
  const transactions = mockTransactions.filter(t => t.accountId === id || !id);
  const filtered = filter === 'All' ? transactions : transactions.filter(t => t.type === filter.toLowerCase());

  return (
    <div className="flex flex-col h-full bg-[var(--color-bg)]">
      {/* Header */}
      <div className="flex items-center p-4 text-white shadow-md z-10" style={{ backgroundColor: 'var(--color-primary)' }}>
        <button onClick={() => navigate(-1)} className="mr-4 text-xl">
          ←
        </button>
        <h1 className="text-lg font-bold">Statement</h1>
      </div>

      <div className="bg-white p-3 border-b border-[var(--color-divider)] flex space-x-2 overflow-x-auto">
        <Chip label="All" selected={filter === 'All'} onClick={() => setFilter('All')} />
        <Chip label="Credit" selected={filter === 'Credit'} onClick={() => setFilter('Credit')} />
        <Chip label="Debit" selected={filter === 'Debit'} onClick={() => setFilter('Debit')} />
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {filtered.map(txn => (
          <div key={txn.id} className="bg-white rounded-lg p-4 shadow-sm flex justify-between items-center border-l-4" style={{ borderLeftColor: txn.type === 'credit' ? 'var(--color-success)' : 'var(--color-error)' }}>
            <div>
              <p className="font-bold text-sm">{txn.description}</p>
              <p className="text-xs text-[var(--color-text-secondary)] mt-1">{txn.date}</p>
            </div>
            <div className={`font-bold ${txn.type === 'credit' ? 'text-[var(--color-success)]' : ''}`}>
              {txn.type === 'credit' ? '+' : ''}{txn.amount.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
            </div>
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="text-center py-10 text-[var(--color-text-secondary)]">
            No transactions found.
          </div>
        )}
      </div>
    </div>
  );
};
