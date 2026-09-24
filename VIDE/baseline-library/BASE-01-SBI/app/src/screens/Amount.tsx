import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

export const Amount: React.FC = () => {
  const navigate = useNavigate();
  const [amount, setAmount] = useState('');

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)', display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <Header title="Enter Amount" showBack />
      <div className="page-content" style={{ padding: '16px', flex: 1 }}>
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '16px', textAlign: 'center', marginBottom: '24px' }}>
          <p style={{ color: 'var(--color-text-secondary)' }}>Paying Amit Kumar</p>
          <p style={{ fontSize: '12px' }}>HDFC Bank - XXXX1122</p>
        </div>
        
        <InputField 
          label="Amount" 
          placeholder="₹ 0.00" 
          type="number"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
        <InputField 
          label="Add a note (Optional)" 
          placeholder="e.g. Rent" 
        />
      </div>
      <div style={{ padding: '16px', backgroundColor: 'white' }}>
        <Button fullWidth onClick={() => navigate('/transfer/review')}>Continue</Button>
      </div>
    </div>
  );
};
