import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { MOCK_ACCOUNTS } from './mockData';
import { Button } from '../components/primitives/Button';

const AccountDetails: React.FC = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const acc = MOCK_ACCOUNTS.find(a => a.id === id) || MOCK_ACCOUNTS[0];

  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <button onClick={() => navigate(-1)} style={{alignSelf: 'flex-start', background:'none', border:'none', color:'var(--color-primary)', cursor:'pointer'}}>← Back</button>
      <h2 style={{ color: 'var(--color-primary)' }}>Account Details</h2>
      <div style={{
        backgroundColor: 'var(--color-primary)', color: 'var(--color-surface)', padding: 'var(--space-24)',
        borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)'
      }}>
        <p style={{ fontSize: '0.875rem', opacity: 0.9 }}>{acc.type}</p>
        <h3 style={{ margin: 'var(--space-8) 0', fontSize: '1.5rem' }}>{acc.balance}</h3>
        <p style={{ fontSize: '0.875rem', opacity: 0.9 }}>A/C: {acc.number}</p>
      </div>
      <Button variant="secondary" onClick={() => navigate('/accounts/' + acc.id + '/transactions')} fullWidth>
        View Transactions
      </Button>
    </div>
  );
};
export default AccountDetails;