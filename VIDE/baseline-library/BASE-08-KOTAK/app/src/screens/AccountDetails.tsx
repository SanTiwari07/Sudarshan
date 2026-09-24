import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ACCOUNTS } from '../data/mockData';

const AccountDetails: React.FC = () => {
  const navigate = useNavigate();
  const account = ACCOUNTS[0];

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 pb-20">
      <div className="p-4 shadow-sm flex items-center gap-4" style={{ backgroundColor: 'var(--color-secondary)', color: 'var(--color-surface)' }}>
        <button onClick={() => navigate(-1)} className="p-2 -ml-2">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <h1 className="text-lg font-bold">Account Details</h1>
      </div>

      <div className="p-6 text-center shadow-sm" style={{ backgroundColor: 'var(--color-secondary)', color: 'var(--color-surface)' }}>
        <p className="text-sm opacity-80 mb-2">{account.type}</p>
        <h2 className="text-3xl font-bold mb-1">₹ {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</h2>
        <p className="text-xs opacity-80 mb-4">{account.number}</p>
        
        <div className="flex justify-center gap-4 mt-6">
          <button onClick={() => navigate('/transactions')} className="flex flex-col items-center gap-2">
            <div className="w-12 h-12 rounded-full bg-white/20 flex items-center justify-center">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            </div>
            <span className="text-xs">Statement</span>
          </button>
          <button onClick={() => navigate('/transfer')} className="flex flex-col items-center gap-2">
            <div className="w-12 h-12 rounded-full bg-white/20 flex items-center justify-center">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </div>
            <span className="text-xs">Transfer</span>
          </button>
        </div>
      </div>

      <div className="p-4 mt-2">
        <h3 className="font-bold text-gray-900 mb-4">Account Info</h3>
        <div className="bg-white rounded-xl shadow-sm p-4 space-y-4">
          <div className="flex justify-between border-b border-gray-100 pb-3">
            <span className="text-sm text-gray-500">Account Type</span>
            <span className="text-sm font-medium">{account.type}</span>
          </div>
          <div className="flex justify-between border-b border-gray-100 pb-3">
            <span className="text-sm text-gray-500">Branch</span>
            <span className="text-sm font-medium">Mumbai Main</span>
          </div>
          <div className="flex justify-between border-b border-gray-100 pb-3">
            <span className="text-sm text-gray-500">IFSC Code</span>
            <span className="text-sm font-medium">KKBK0000958</span>
          </div>
          <div className="flex justify-between">
            <span className="text-sm text-gray-500">Status</span>
            <span className="text-sm font-medium text-green-600">{account.status}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AccountDetails;
