import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { PAYEES, ACCOUNTS } from '../data/mockData';

const Amount: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const payeeId = location.state?.payeeId || 'p1';
  const payee = PAYEES.find(p => p.id === payeeId) || PAYEES[0];
  const account = ACCOUNTS[0];

  const [amount, setAmount] = useState('');
  const [remark, setRemark] = useState('');

  const handleContinue = () => {
    if (amount && parseFloat(amount) > 0) {
      navigate('/transfer/review', {
        state: { payeeId, amount, remark }
      });
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 pb-24">
      <div className="p-4 bg-white shadow-sm flex items-center gap-4">
        <button onClick={() => navigate(-1)} className="p-2 -ml-2">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <h1 className="text-lg font-bold">Enter Amount</h1>
      </div>

      <div className="flex-1 p-4">
        <div className="bg-white rounded-xl shadow-sm p-6 flex flex-col items-center mb-6">
          <div className="w-16 h-16 rounded-full flex items-center justify-center text-2xl font-bold mb-3 shadow-sm" style={{ backgroundColor: 'var(--color-secondary)', color: 'white' }}>
            {payee.name.charAt(0)}
          </div>
          <h2 className="text-lg font-bold">{payee.name}</h2>
          <p className="text-sm text-gray-500 mb-6">{payee.vpa}</p>
          
          <div className="flex items-center text-4xl font-bold mb-4">
            <span className="text-gray-400 mr-1">₹</span>
            <input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              className="w-full max-w-[200px] bg-transparent border-none outline-none text-center"
              placeholder="0"
              autoFocus
            />
          </div>

          <input
            type="text"
            value={remark}
            onChange={(e) => setRemark(e.target.value)}
            placeholder="Add a remark (optional)"
            className="w-full text-center text-sm p-3 bg-gray-50 rounded-lg border-none"
          />
        </div>

        <div className="bg-white rounded-xl shadow-sm p-4 flex justify-between items-center mb-6 border border-gray-100">
          <div>
            <p className="text-xs text-gray-500 mb-1">Paying from</p>
            <p className="font-bold">{account.type}</p>
            <p className="text-xs text-gray-500">{account.number}</p>
          </div>
          <div className="text-right">
            <p className="text-xs text-gray-500 mb-1">Available</p>
            <p className="font-bold">₹ {account.balance.toLocaleString('en-IN')}</p>
          </div>
        </div>
      </div>

      <div className="p-4 fixed bottom-0 left-0 right-0 bg-white shadow-[0_-4px_6px_-1px_rgba(0,0,0,0.05)]">
        <button
          onClick={handleContinue}
          disabled={!amount || parseFloat(amount) <= 0}
          className="w-full py-4 rounded-xl font-bold text-white transition-opacity"
          style={{ 
            backgroundColor: amount && parseFloat(amount) > 0 ? 'var(--color-primary)' : 'var(--color-text-secondary)',
            opacity: amount && parseFloat(amount) > 0 ? 1 : 0.5 
          }}
        >
          Proceed to Pay
        </button>
      </div>
    </div>
  );
};

export default Amount;
