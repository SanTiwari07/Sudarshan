import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/Button';
import { Modal } from '../components/Modal';
import { PINPad } from '../components/PINPad';

export const Review: React.FC = () => {
  const navigate = useNavigate();
  const [showPin, setShowPin] = useState(false);

  const handleConfirm = () => {
    setShowPin(true);
  };

  const handlePinComplete = (pin: string) => {
    if (pin.length === 4 || pin.length === 6) {
      setShowPin(false);
      navigate('/transfer/receipt');
    }
  };

  return (
    <div className="flex flex-col h-full bg-[var(--color-bg)]">
      <div className="flex items-center p-4 text-white shadow-md" style={{ backgroundColor: 'var(--color-primary)' }}>
        <button onClick={() => navigate(-1)} className="mr-4 text-xl">
          ←
        </button>
        <h1 className="text-lg font-bold">Review Transfer</h1>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div className="bg-white rounded-[var(--radius-card)] p-6 shadow-sm flex flex-col items-center">
          <p className="text-sm text-[var(--color-text-secondary)] mb-2">Amount to be Transferred</p>
          <h2 className="text-3xl font-bold text-[var(--color-primary)]">₹ 5,000.00</h2>
        </div>
        
        <div className="bg-white rounded-[var(--radius-card)] p-4 shadow-sm space-y-4">
          <div>
            <p className="text-xs text-[var(--color-text-secondary)] mb-1">From Account</p>
            <p className="font-bold">**** **** 1234</p>
          </div>
          <div className="w-full h-px bg-[var(--color-divider)]"></div>
          <div>
            <p className="text-xs text-[var(--color-text-secondary)] mb-1">To Payee</p>
            <p className="font-bold">Rahul Sharma</p>
            <p className="text-sm text-[var(--color-text-secondary)]">HDFC Bank • **** 9876</p>
          </div>
          <div className="w-full h-px bg-[var(--color-divider)]"></div>
          <div>
            <p className="text-xs text-[var(--color-text-secondary)] mb-1">Transfer Type</p>
            <p className="font-bold">IMPS</p>
          </div>
          <div className="w-full h-px bg-[var(--color-divider)]"></div>
          <div>
            <p className="text-xs text-[var(--color-text-secondary)] mb-1">Remarks</p>
            <p className="font-bold">Rent</p>
          </div>
        </div>
      </div>

      <div className="p-4 bg-white border-t border-[var(--color-divider)]">
        <Button variant="primary" fullWidth onClick={handleConfirm}>
          CONFIRM TRANSFER
        </Button>
      </div>

      <Modal isOpen={showPin} onClose={() => setShowPin(false)} title="Enter Transaction PIN">
        <div className="py-4 flex flex-col items-center">
          <p className="text-sm text-center text-[var(--color-text-secondary)] mb-6">
            Enter your T-PIN to confirm transfer of ₹ 5,000.00 to Rahul Sharma
          </p>
          <PINPad length={4} onComplete={handlePinComplete} />
        </div>
      </Modal>
    </div>
  );
};
