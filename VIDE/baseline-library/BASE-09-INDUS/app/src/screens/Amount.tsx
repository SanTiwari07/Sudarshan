import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

const Amount: React.FC = () => {
  const navigate = useNavigate();
  const [amount, setAmount] = useState('');
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)', height: '100%' }}>
      <button onClick={() => navigate(-1)} style={{alignSelf: 'flex-start', background:'none', border:'none', color:'var(--color-primary)', cursor:'pointer'}}>← Back</button>
      <h2 style={{ color: 'var(--color-primary)' }}>Enter Amount</h2>
      <div style={{ flex: 1 }}>
        <InputField label="Amount (₹)" type="number" value={amount} onChange={e => setAmount(e.target.value)} placeholder="0.00" />
      </div>
      <Button variant="primary" fullWidth onClick={() => navigate('/transfer/review')} disabled={!amount}>Continue</Button>
    </div>
  );
};
export default Amount;