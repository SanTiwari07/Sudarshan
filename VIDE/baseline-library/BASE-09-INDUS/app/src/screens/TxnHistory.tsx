import React from 'react';
import { useNavigate } from 'react-router-dom';
import { MOCK_TXNS } from './mockData';

const TxnHistory: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <button onClick={() => navigate(-1)} style={{alignSelf: 'flex-start', background:'none', border:'none', color:'var(--color-primary)', cursor:'pointer'}}>← Back</button>
      <h2 style={{ color: 'var(--color-primary)' }}>Transaction History</h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-12)' }}>
        {MOCK_TXNS.map(txn => (
          <div key={txn.id} style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)',
            borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)'
          }}>
            <div>
              <p style={{ fontWeight: 600 }}>{txn.desc}</p>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.75rem' }}>{txn.date}</p>
            </div>
            <p style={{ color: txn.type === 'credit' ? 'var(--color-success)' : 'var(--color-text-primary)', fontWeight: 600 }}>
              {txn.amount}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};
export default TxnHistory;