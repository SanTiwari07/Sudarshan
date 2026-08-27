import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { PAYEES } from '../data/mockData';

const Receipt: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { payeeId, amount } = location.state || { payeeId: 'p1', amount: '0' };
  
  const payee = PAYEES.find(p => p.id === payeeId) || PAYEES[0];
  const date = new Date().toLocaleString('en-IN', {
    day: 'numeric', month: 'short', year: 'numeric',
    hour: 'numeric', minute: '2-digit', hour12: true
  });
  const refNum = `KOTAK${Math.floor(Math.random() * 1000000000).toString().padStart(9, '0')}`;

  return (
    <div className="flex flex-col min-h-screen bg-gray-50">
      <div className="flex-1 flex flex-col items-center justify-center p-6">
        <div className="w-20 h-20 rounded-full flex items-center justify-center mb-6 shadow-sm" style={{ backgroundColor: 'var(--color-success)', color: 'white' }}>
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
        </div>
        
        <h1 className="text-2xl font-bold mb-2">Payment Successful</h1>
        <p className="text-gray-500 text-center mb-8">
          Your payment to {payee.name} has been processed successfully.
        </p>

        <div className="bg-white rounded-xl shadow-sm p-6 w-full max-w-sm mb-8">
          <h2 className="text-3xl font-bold text-center mb-6" style={{ color: 'var(--color-secondary)' }}>
            ₹ {parseFloat(amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}
          </h2>
          
          <div className="space-y-4">
            <div className="flex justify-between items-center border-b border-gray-100 pb-3">
              <span className="text-sm text-gray-500">To</span>
              <span className="text-sm font-bold">{payee.name}</span>
            </div>
            <div className="flex justify-between items-center border-b border-gray-100 pb-3">
              <span className="text-sm text-gray-500">Date</span>
              <span className="text-sm font-medium">{date}</span>
            </div>
            <div className="flex justify-between items-center pb-1">
              <span className="text-sm text-gray-500">Ref. No</span>
              <span className="text-sm font-medium">{refNum}</span>
            </div>
          </div>
        </div>

        <button
          onClick={() => navigate('/home')}
          className="w-full max-w-sm py-4 rounded-xl font-bold text-white shadow-md"
          style={{ backgroundColor: 'var(--color-primary)' }}
        >
          Back to Home
        </button>
      </div>
    </div>
  );
};

export default Receipt;
