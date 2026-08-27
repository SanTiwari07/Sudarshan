import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';

const Receipt: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)', height: '100%', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ width: 64, height: 64, borderRadius: '50%', backgroundColor: 'var(--color-success)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontSize: '32px', marginBottom: 'var(--space-16)' }}>✓</div>
      <h2 style={{ color: 'var(--color-success)' }}>Transfer Successful</h2>
      <p style={{ color: 'var(--color-text-secondary)' }}>₹ 500.00 sent to John Doe</p>
      <div style={{ marginTop: 'auto', width: '100%' }}>
        <Button variant="primary" fullWidth onClick={() => navigate('/home')}>Back to Home</Button>
      </div>
    </div>
  );
};
export default Receipt;