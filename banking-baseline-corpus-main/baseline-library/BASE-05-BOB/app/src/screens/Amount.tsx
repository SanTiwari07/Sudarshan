import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/Button';
import { InputField } from '../components/InputField';
import { mockAccounts } from '../data/mockData';

export const Amount: React.FC = () => {
  const navigate = useNavigate();
  const [amount, setAmount] = useState('');
  const [remarks, setRemarks] = useState('');
  
  const account = mockAccounts[0];

  const handleContinue = () => {
    if (amount && parseFloat(amount) > 0) {
      navigate('/transfer/review');
    }
  };

  return (
    <div className="flex flex-col h-full bg-[var(--color-bg)]">
      <div className="flex items-center p-4 text-white shadow-md" style={{ backgroundColor: 'var(--color-primary)' }}>
        <button onClick={() => navigate(-1)} className="mr-4 text-xl">
          ←
        </button>
        <h1 className="text-lg font-bold">Enter Amount</h1>
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        <div className="bg-white rounded-[var(--radius-card)] p-4 shadow-sm mb-6">
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">From Account</p>
          <p className="font-bold">{account.accountNumber}</p>
          <p className="text-xs text-[var(--color-text-secondary)] mt-1">Avail Bal: {account.currency} {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</p>
        </div>
        
        <div className="bg-white rounded-[var(--radius-card)] p-4 shadow-sm mb-6">
          <p className="text-xs text-[var(--color-text-secondary)] mb-1">To Payee</p>
          <p className="font-bold">Rahul Sharma</p>
          <p className="text-xs text-[var(--color-text-secondary)] mt-1">HDFC Bank • **** 9876</p>
        </div>

        <div className="bg-white rounded-[var(--radius-card)] p-6 shadow-sm mb-6 flex flex-col items-center">
          <p className="text-sm text-[var(--color-text-secondary)] mb-2">Amount</p>
          <div className="flex items-center text-4xl font-bold text-[var(--color-primary)]">
            <span>₹</span>
            <input 
              type="number" 
              className="w-full bg-transparent border-none text-center outline-none"
              placeholder="0.00"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              autoFocus
            />
          </div>
        </div>
        
        <InputField 
          label="Remarks (Optional)" 
          placeholder="e.g. Rent" 
          value={remarks}
          onChange={(e) => setRemarks(e.target.value)}
        />
      </div>

      <div className="p-4 bg-white border-t border-[var(--color-divider)]">
        <Button variant="primary" fullWidth onClick={handleContinue}>
          PROCEED
        </Button>
      </div>
    </div>
  );
};
