import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';

const Review: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)', height: '100%' }}>
      <button onClick={() => navigate(-1)} style={{alignSelf: 'flex-start', background:'none', border:'none', color:'var(--color-primary)', cursor:'pointer'}}>← Back</button>
      <h2 style={{ color: 'var(--color-primary)' }}>Review Transfer</h2>
      <div style={{ flex: 1, backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)', borderRadius: 'var(--radius-card)' }}>
        <p style={{ color: 'var(--color-text-secondary)' }}>To: John Doe</p>
        <p style={{ color: 'var(--color-text-secondary)' }}>Amount:</p>
        <h3 style={{ fontSize: '1.5rem', margin: 'var(--space-8) 0' }}>₹ 500.00</h3>
      </div>
      <Button variant="primary" fullWidth onClick={() => navigate('/transfer/receipt')}>Confirm Transfer</Button>
    </div>
  );
};
export default Review;