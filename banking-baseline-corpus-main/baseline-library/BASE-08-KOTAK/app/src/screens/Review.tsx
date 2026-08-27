import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { PAYEES, ACCOUNTS } from '../data/mockData';

const Review: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { payeeId, amount, remark } = location.state || { payeeId: 'p1', amount: '0', remark: '' };
  
  const payee = PAYEES.find(p => p.id === payeeId) || PAYEES[0];
  const account = ACCOUNTS[0];

  const handleConfirm = () => {
    navigate('/transfer/receipt', {
      state: { payeeId, amount, remark }
    });
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 pb-20">
      <div className="p-4 bg-white shadow-sm flex items-center gap-4">
        <button onClick={() => navigate(-1)} className="p-2 -ml-2">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <h1 className="text-lg font-bold">Review Payment</h1>
      </div>

      <div className="flex-1 p-4">
        <div className="bg-white rounded-xl shadow-sm p-6 mb-4">
          <h2 className="text-3xl font-bold text-center mb-6">₹ {parseFloat(amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</h2>
          
          <div className="space-y-4">
            <div className="flex justify-between items-start border-b border-gray-100 pb-4">
              <span className="text-sm text-gray-500">To</span>
              <div className="text-right">
                <p className="font-bold">{payee.name}</p>
                <p className="text-xs text-gray-500">{payee.vpa}</p>
              </div>
            </div>
            <div className="flex justify-between items-start border-b border-gray-100 pb-4">
              <span className="text-sm text-gray-500">From</span>
              <div className="text-right">
                <p className="font-bold">{account.type}</p>
                <p className="text-xs text-gray-500">{account.number}</p>
              </div>
            </div>
            {remark && (
              <div className="flex justify-between items-center pb-2">
                <span className="text-sm text-gray-500">Remarks</span>
                <span className="text-sm font-medium">{remark}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="p-4 fixed bottom-0 left-0 right-0 bg-white shadow-[0_-4px_6px_-1px_rgba(0,0,0,0.05)]">
        <button
          onClick={handleConfirm}
          className="w-full py-4 rounded-xl font-bold text-white shadow-md"
          style={{ backgroundColor: 'var(--color-primary)' }}
        >
          Confirm & Pay
        </button>
      </div>
    </div>
  );
};

export default Review;
