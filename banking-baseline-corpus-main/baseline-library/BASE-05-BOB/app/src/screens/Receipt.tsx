import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/Button';

export const Receipt: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col h-full bg-white">
      <div className="flex-1 flex flex-col items-center justify-center p-6">
        <div className="w-20 h-20 rounded-full flex items-center justify-center text-4xl mb-6 text-white" style={{ backgroundColor: 'var(--color-success)' }}>
          ✓
        </div>
        
        <h2 className="text-2xl font-bold mb-2">Transfer Successful</h2>
        <p className="text-[var(--color-text-secondary)] text-center mb-8">
          Your transaction was processed successfully.
        </p>

        <div className="w-full bg-[var(--color-bg)] rounded-[var(--radius-card)] p-6 space-y-4 mb-8">
          <div className="flex justify-between">
            <span className="text-[var(--color-text-secondary)] text-sm">Amount</span>
            <span className="font-bold">₹ 5,000.00</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[var(--color-text-secondary)] text-sm">To</span>
            <span className="font-bold">Rahul Sharma</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[var(--color-text-secondary)] text-sm">From</span>
            <span className="font-bold">**** 1234</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[var(--color-text-secondary)] text-sm">Ref No.</span>
            <span className="font-bold">IMPS2608109876</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[var(--color-text-secondary)] text-sm">Date</span>
            <span className="font-bold">13 Aug 2026</span>
          </div>
        </div>
      </div>

      <div className="p-4 space-y-4">
        <Button variant="outline" fullWidth onClick={() => {}}>
          Share Receipt
        </Button>
        <Button variant="primary" fullWidth onClick={() => navigate('/home')}>
          BACK TO HOME
        </Button>
      </div>
    </div>
  );
};
