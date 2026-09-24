import React from 'react';
import { useNavigate } from 'react-router-dom';

const Transfer: React.FC = () => {
  const navigate = useNavigate();
  const payees = [{ id: 'p1', name: 'John Doe', acc: 'XXXXXX1111' }, { id: 'p2', name: 'Jane Smith', acc: 'XXXXXX2222' }];
  
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <h2 style={{ color: 'var(--color-primary)' }}>Transfer Money</h2>
      <h3>Select Payee</h3>
      {payees.map(p => (
        <div key={p.id} onClick={() => navigate('/transfer/amount')} style={{
          backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)',
          borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)', cursor: 'pointer'
        }}>
          <p style={{ fontWeight: 600 }}>{p.name}</p>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>{p.acc}</p>
        </div>
      ))}
    </div>
  );
};
export default Transfer;