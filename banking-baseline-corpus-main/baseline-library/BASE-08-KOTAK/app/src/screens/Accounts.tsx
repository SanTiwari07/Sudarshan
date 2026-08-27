import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ACCOUNTS } from '../data/mockData';

const Accounts: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 pb-20">
      <div className="p-4 bg-white shadow-sm flex items-center gap-4">
        <button onClick={() => navigate(-1)} className="p-2 -ml-2">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <h1 className="text-lg font-bold" style={{ color: 'var(--color-text-primary)' }}>My Accounts</h1>
      </div>

      <div className="p-4 space-y-4">
        {ACCOUNTS.map((acc) => (
          <div key={acc.id} onClick={() => navigate('/accounts/details')} className="bg-white rounded-xl shadow-sm p-4 cursor-pointer active:bg-gray-50">
            <div className="flex justify-between items-start gap-4 mb-4">
              <div>
                <h3 className="font-bold text-gray-900">{acc.type}</h3>
                <p className="text-xs text-gray-500 mt-1">{acc.number}</p>
              </div>
              <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded">
                {acc.status}
              </span>
            </div>
            
            <div className="pt-4 border-t border-gray-100">
              <p className="text-xs text-gray-500 mb-2">Available Balance</p>
              <h2 className="text-xl font-bold" style={{ color: 'var(--color-secondary)' }}>
                ₹ {acc.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
              </h2>
            </div>
            {acc.maturityDate && (
              <div className="mt-2 text-xs text-gray-500">
                Maturity Date: {acc.maturityDate}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Accounts;
