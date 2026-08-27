import React from 'react';
import { useNavigate } from 'react-router-dom';
import { mockPayees } from '../data/mockData';

export const Transfer: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col h-full bg-[var(--color-bg)]">
      {/* Header */}
      <div className="flex items-center p-4 text-white shadow-md" style={{ backgroundColor: 'var(--color-primary)' }}>
        <button onClick={() => navigate('/home')} className="mr-4 text-xl">
          ←
        </button>
        <h1 className="text-lg font-bold">Fund Transfer</h1>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        <div>
          <h3 className="text-sm font-bold text-[var(--color-text-secondary)] mb-3">TRANSFER OPTIONS</h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-white rounded-[var(--radius-card)] p-4 shadow-sm flex flex-col items-center justify-center cursor-pointer h-24" onClick={() => navigate('/transfer/amount')}>
              <span className="text-2xl mb-2 text-[var(--color-primary)]">🔄</span>
              <span className="text-xs font-bold text-center">Self Linked Accounts</span>
            </div>
            <div className="bg-white rounded-[var(--radius-card)] p-4 shadow-sm flex flex-col items-center justify-center cursor-pointer h-24" onClick={() => navigate('/transfer/amount')}>
              <span className="text-2xl mb-2 text-[var(--color-primary)]">🏦</span>
              <span className="text-xs font-bold text-center">Third Party within BoB</span>
            </div>
            <div className="bg-white rounded-[var(--radius-card)] p-4 shadow-sm flex flex-col items-center justify-center cursor-pointer h-24" onClick={() => navigate('/transfer/amount')}>
              <span className="text-2xl mb-2 text-[var(--color-primary)]">⚡</span>
              <span className="text-xs font-bold text-center">IMPS / NEFT / RTGS</span>
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-sm font-bold text-[var(--color-text-secondary)] mb-3">RECENT PAYEES</h3>
          <div className="space-y-3">
            {mockPayees.map(payee => (
              <div 
                key={payee.id} 
                className="bg-white rounded-lg p-4 shadow-sm flex items-center cursor-pointer"
                onClick={() => navigate('/transfer/amount')}
              >
                <div className="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-4 font-bold text-[var(--color-primary)]">
                  {payee.name.charAt(0)}
                </div>
                <div>
                  <p className="font-bold text-sm">{payee.name}</p>
                  <p className="text-xs text-[var(--color-text-secondary)]">{payee.bank} • {payee.accountNumber}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
