import React from 'react';
import { useNavigate } from 'react-router-dom';
import { TRANSACTIONS } from '../data/mockData';

const TxnHistory: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 pb-20">
      <div className="p-4 bg-white shadow-sm flex items-center gap-4">
        <button onClick={() => navigate(-1)} className="p-2 -ml-2">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <h1 className="text-lg font-bold" style={{ color: 'var(--color-text-primary)' }}>Passbook</h1>
      </div>

      <div className="p-4">
        <div className="bg-white rounded-xl shadow-sm overflow-hidden">
          {TRANSACTIONS.map((tx, idx) => (
            <div key={tx.id} className={`p-4 flex justify-between items-center ${idx !== TRANSACTIONS.length - 1 ? 'border-b border-gray-100' : ''}`}>
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-full flex items-center justify-center bg-gray-50" style={{ color: 'var(--color-secondary)' }}>
                  <span className="font-bold text-sm">{tx.description.charAt(0)}</span>
                </div>
                <div>
                  <p className="font-medium text-gray-900">{tx.description}</p>
                  <p className="text-xs text-gray-500 mt-1">{tx.date} • {tx.category}</p>
                </div>
              </div>
              <div className="text-right">
                <p className={`font-bold ${tx.type === 'credit' ? 'text-green-600' : 'text-gray-900'}`}>
                  {tx.type === 'credit' ? '+' : '-'}₹ {Math.abs(tx.amount).toFixed(2)}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default TxnHistory;
